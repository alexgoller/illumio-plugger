#!/usr/bin/env python3
"""
ven-fleet-manager -- Fleet-level VEN management, enforcement progression
tracking, agent health monitoring, and batch enforcement operations.

Provides a dashboard with enforcement pipeline funnel, compatibility check
analysis, VEN version distribution, agent health, and batch progression API.
"""

import json
import logging
import os
import signal
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from illumio import PolicyComputeEngine

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
log = logging.getLogger("ven-fleet-manager")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
fleet_state = {
    "last_scan": None,
    "scan_count": 0,
    "scanning": False,
    "error": None,
    "scan_requested": False,
    "fleet": None,
}

label_cache = {}  # href -> {key, value}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCAN_INTERVAL = max(300, int(os.environ.get("SCAN_INTERVAL", "3600")))
OFFLINE_THRESHOLD_HOURS = int(os.environ.get("OFFLINE_THRESHOLD_HOURS", "24"))
STALE_HEARTBEAT_HOURS = int(os.environ.get("STALE_HEARTBEAT_HOURS", "48"))
TARGET_VEN_VERSION = os.environ.get("TARGET_VEN_VERSION", "")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

# ---------------------------------------------------------------------------
# PCE helpers
# ---------------------------------------------------------------------------

def get_pce():
    pce = PolicyComputeEngine(
        url=os.environ["PCE_HOST"],
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ["PCE_API_KEY"],
        password=os.environ["PCE_API_SECRET"],
    )
    verify = os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() != "true"
    pce.set_tls_settings(verify=verify)
    return pce


def fetch_labels(pce):
    global label_cache
    try:
        resp = pce.get("/labels")
        labels = resp.json() if resp.status_code == 200 else []
        cache = {}
        for lbl in labels:
            href = lbl.get("href", "")
            if href:
                cache[href] = {"key": lbl.get("key", ""), "value": lbl.get("value", "")}
        label_cache = cache
        log.info("Loaded %d labels", len(cache))
        return labels
    except Exception as e:
        log.error("Failed to fetch labels: %s", e)
        return []


def resolve_labels(workload):
    result = {}
    for lbl in workload.get("labels", []):
        if isinstance(lbl, dict):
            href = lbl.get("href", "")
            if href in label_cache:
                cached = label_cache[href]
                result[cached["key"]] = cached["value"]
    return result


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def collect_workloads(pce):
    try:
        resp = pce.get("/workloads", params={"max_results": 10000})
        if resp.status_code == 200:
            wl = resp.json()
            if isinstance(wl, list):
                return wl
    except Exception as e:
        log.error("Failed to fetch workloads: %s", e)
    return []


def collect_vens(pce):
    try:
        resp = pce.get("/vens", params={"max_results": 10000})
        if resp.status_code == 200:
            vens = resp.json()
            if isinstance(vens, list):
                return vens
    except Exception as e:
        log.warning("VEN endpoint not available: %s", e)
    return []


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def parse_iso(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def get_agent_version(wl):
    agent = wl.get("agent") or {}
    status = agent.get("status") or {}
    config = agent.get("config") or {}
    return status.get("agent_version") or config.get("agent_version") or ""


def get_agent_health(wl):
    agent = wl.get("agent") or {}
    status = agent.get("status") or {}
    return status.get("agent_health") or []


def get_last_heartbeat(wl):
    agent = wl.get("agent") or {}
    status = agent.get("status") or {}
    return parse_iso(status.get("last_heartbeat_on") or agent.get("last_heartbeat_on", ""))


def get_compat_status(health_items):
    """Analyze compatibility check status from agent_health array.

    Returns one of: "pass", "fail", "unknown"
    """
    compat_items = [h for h in health_items if isinstance(h, dict)
                    and "compat" in (h.get("type", "") or "").lower()]
    if not compat_items:
        return "unknown"
    for item in compat_items:
        sev = (item.get("severity") or "").lower()
        if sev in ("error", "err"):
            return "fail"
    for item in compat_items:
        sev = (item.get("severity") or "").lower()
        if sev == "warning":
            return "fail"
    return "pass"


def get_compat_issues(health_items):
    issues = []
    for h in health_items:
        if not isinstance(h, dict):
            continue
        if "compat" in (h.get("type", "") or "").lower():
            sev = (h.get("severity") or "").lower()
            if sev in ("error", "err", "warning"):
                issues.append({
                    "type": h.get("type", ""),
                    "severity": sev,
                    "audit_event": h.get("audit_event", ""),
                })
    return issues


def analyze_fleet(workloads, vens_data):
    now = datetime.now(timezone.utc)
    offline_threshold = now - timedelta(hours=OFFLINE_THRESHOLD_HOURS)
    stale_threshold = now - timedelta(hours=STALE_HEARTBEAT_HOURS)

    # Determine target version
    all_versions = []
    for wl in workloads:
        v = get_agent_version(wl)
        if v:
            all_versions.append(v)
    version_counts = Counter(all_versions)
    target_version = TARGET_VEN_VERSION
    if not target_version and version_counts:
        target_version = max(version_counts.keys())

    # Core counters
    total = len(workloads)
    managed = 0
    unmanaged = 0
    online_count = 0
    offline_count = 0
    stale_heartbeat_count = 0
    fresh_heartbeat_count = 0

    # Enforcement
    enforcement_dist = Counter()

    # Progression pipeline
    idle_total = 0
    idle_compat_pass = []
    idle_compat_fail = []
    idle_compat_unknown = []
    visibility_total = 0
    visibility_ready = []
    visibility_not_ready = []
    selective_total = 0
    full_total = 0

    # Agent health
    agent_errors = []
    agent_warnings = []
    offline_workloads = []
    stale_workloads = []

    # Version tracking
    version_detail = defaultdict(lambda: {"count": 0, "os_breakdown": Counter()})

    # OS distribution
    os_dist = Counter()

    # Coverage by labels
    by_app = defaultdict(lambda: Counter())
    by_env = defaultdict(lambda: Counter())
    unlabeled_count = 0

    # Per-workload details for progression table
    workload_details = []

    for wl in workloads:
        hostname = wl.get("hostname") or wl.get("name") or "(unnamed)"
        href = wl.get("href", "")
        is_online = wl.get("online", False)
        is_managed = wl.get("managed", False)
        mode = wl.get("enforcement_mode", "idle")
        os_id = wl.get("os_id") or ""
        os_detail = wl.get("os_detail") or os_id
        agent = wl.get("agent") or {}
        health_items = get_agent_health(wl)
        version = get_agent_version(wl)
        last_hb = get_last_heartbeat(wl)
        labels = resolve_labels(wl)
        created_at = parse_iso(wl.get("created_at", ""))
        updated_at = parse_iso(wl.get("updated_at", ""))
        ven_info = wl.get("ven") or {}
        ven_status = ven_info.get("status", "")

        # Agent status fields
        status_obj = agent.get("status") or {}
        policy_received = parse_iso(status_obj.get("security_policy_received_at", ""))
        policy_applied = parse_iso(status_obj.get("security_policy_applied_at", ""))

        if is_managed:
            managed += 1
        else:
            unmanaged += 1

        if is_online:
            online_count += 1
        else:
            offline_count += 1

        enforcement_dist[mode] += 1

        # OS
        if os_detail:
            os_dist[os_detail] += 1

        # Version detail
        if version:
            version_detail[version]["count"] += 1
            if os_detail:
                version_detail[version]["os_breakdown"][os_detail] += 1

        # Labels
        app_label = labels.get("app", "")
        env_label = labels.get("env", "")
        if not labels:
            unlabeled_count += 1
        if app_label:
            by_app[app_label][mode] += 1
        if env_label:
            by_env[env_label][mode] += 1

        # Heartbeat freshness
        hb_stale = False
        if last_hb:
            if last_hb < stale_threshold:
                stale_heartbeat_count += 1
                hb_stale = True
            else:
                fresh_heartbeat_count += 1

        # Compatibility
        compat_status = get_compat_status(health_items)
        compat_issues = get_compat_issues(health_items)

        # Compute time in current mode (using updated_at as proxy)
        time_in_mode_hours = 0
        if updated_at:
            time_in_mode_hours = (now - updated_at).total_seconds() / 3600

        # Build workload detail entry
        interfaces = wl.get("interfaces") or []
        ip = interfaces[0].get("address", "") if interfaces else ""

        detail = {
            "hostname": hostname,
            "href": href,
            "ip": ip,
            "mode": mode,
            "online": is_online,
            "managed": is_managed,
            "version": version,
            "os": os_detail,
            "labels": labels,
            "compat_status": compat_status,
            "compat_issues": compat_issues,
            "last_heartbeat": last_hb.isoformat() if last_hb else None,
            "heartbeat_stale": hb_stale,
            "time_in_mode_hours": round(time_in_mode_hours, 1),
            "policy_received": policy_received.isoformat() if policy_received else None,
            "policy_applied": policy_applied.isoformat() if policy_applied else None,
            "created_at": created_at.isoformat() if created_at else None,
            "updated_at": updated_at.isoformat() if updated_at else None,
            "ven_status": ven_status,
        }
        workload_details.append(detail)

        # Progression pipeline
        if mode == "idle":
            idle_total += 1
            if compat_status == "pass":
                idle_compat_pass.append(detail)
            elif compat_status == "fail":
                idle_compat_fail.append(detail)
            else:
                idle_compat_unknown.append(detail)
        elif mode == "visibility_only":
            visibility_total += 1
            if policy_received:
                visibility_ready.append(detail)
            else:
                visibility_not_ready.append(detail)
        elif mode == "selective":
            selective_total += 1
        elif mode == "full":
            full_total += 1

        # Agent health items
        for h in health_items:
            if not isinstance(h, dict):
                continue
            sev = (h.get("severity") or "").lower()
            entry = {
                "hostname": hostname,
                "href": href,
                "type": h.get("type", ""),
                "severity": sev,
                "audit_event": h.get("audit_event", ""),
            }
            if sev in ("error", "err"):
                agent_errors.append(entry)
            elif sev == "warning":
                agent_warnings.append(entry)

        # Offline / stale lists
        if not is_online:
            offline_workloads.append({
                "hostname": hostname,
                "href": href,
                "ip": ip,
                "labels": labels,
                "last_heartbeat": last_hb.isoformat() if last_hb else None,
                "version": version,
            })
        if hb_stale:
            stale_workloads.append({
                "hostname": hostname,
                "href": href,
                "ip": ip,
                "labels": labels,
                "last_heartbeat": last_hb.isoformat() if last_hb else None,
                "hours_since_heartbeat": round((now - last_hb).total_seconds() / 3600, 1) if last_hb else None,
            })

    # Sort progression lists by time_in_mode descending (most stuck first)
    for lst in [idle_compat_pass, idle_compat_fail, idle_compat_unknown,
                visibility_ready, visibility_not_ready]:
        lst.sort(key=lambda x: x["time_in_mode_hours"], reverse=True)

    stale_workloads.sort(key=lambda x: x.get("hours_since_heartbeat") or 0, reverse=True)

    # Version distribution
    version_dist = {}
    for ver, info in sorted(version_detail.items()):
        version_dist[ver] = {
            "count": info["count"],
            "os_breakdown": dict(info["os_breakdown"]),
        }

    oldest_version = min(version_counts.keys()) if version_counts else ""
    newest_version = max(version_counts.keys()) if version_counts else ""

    # Upgrade readiness
    on_target = version_counts.get(target_version, 0) if target_version else 0
    needs_upgrade = total - on_target if target_version else 0

    # Fleet health score (0-100)
    online_pct = (online_count / total * 100) if total else 0
    enforcement_pct = ((total - idle_total) / total * 100) if total else 0
    version_pct = (on_target / total * 100) if total and target_version else 100
    heartbeat_total_checked = fresh_heartbeat_count + stale_heartbeat_count
    heartbeat_pct = (fresh_heartbeat_count / heartbeat_total_checked * 100) if heartbeat_total_checked else 100
    compat_checked = len(idle_compat_pass) + len(idle_compat_fail)
    compat_pct = (len(idle_compat_pass) / compat_checked * 100) if compat_checked else 100

    health_score = round(
        online_pct * 0.30 +
        enforcement_pct * 0.25 +
        version_pct * 0.20 +
        heartbeat_pct * 0.15 +
        compat_pct * 0.10
    )
    health_score = max(0, min(100, health_score))

    # Coverage by labels
    coverage_by_app = {}
    for app, modes in sorted(by_app.items()):
        coverage_by_app[app] = dict(modes)
    coverage_by_env = {}
    for env, modes in sorted(by_env.items()):
        coverage_by_env[env] = dict(modes)

    return {
        "timestamp": now.isoformat(),
        "summary": {
            "total": total,
            "managed": managed,
            "unmanaged": unmanaged,
            "online": online_count,
            "offline": offline_count,
            "health_score": health_score,
            "health_components": {
                "online_pct": round(online_pct, 1),
                "enforcement_pct": round(enforcement_pct, 1),
                "version_pct": round(version_pct, 1),
                "heartbeat_pct": round(heartbeat_pct, 1),
                "compat_pct": round(compat_pct, 1),
            },
        },
        "enforcement": {
            "distribution": dict(enforcement_dist),
            "idle": idle_total,
            "visibility_only": visibility_total,
            "selective": selective_total,
            "full": full_total,
        },
        "progression": {
            "idle_total": idle_total,
            "idle_compat_pass": idle_compat_pass,
            "idle_compat_fail": idle_compat_fail,
            "idle_compat_unknown": idle_compat_unknown,
            "visibility_total": visibility_total,
            "visibility_ready": visibility_ready,
            "visibility_not_ready": visibility_not_ready,
            "selective_total": selective_total,
            "full_total": full_total,
        },
        "health": {
            "online": online_count,
            "offline": offline_count,
            "stale_heartbeats": stale_heartbeat_count,
            "fresh_heartbeats": fresh_heartbeat_count,
            "agent_errors": agent_errors,
            "agent_warnings": agent_warnings,
            "offline_workloads": offline_workloads,
            "stale_workloads": stale_workloads,
        },
        "versions": {
            "distribution": version_dist,
            "target": target_version,
            "oldest": oldest_version,
            "newest": newest_version,
            "on_target": on_target,
            "needs_upgrade": needs_upgrade,
            "total_with_version": len(all_versions),
        },
        "os_distribution": dict(os_dist.most_common()),
        "coverage": {
            "by_app": coverage_by_app,
            "by_env": coverage_by_env,
            "unlabeled": unlabeled_count,
        },
        "workloads": workload_details,
    }


# ---------------------------------------------------------------------------
# Scan loop
# ---------------------------------------------------------------------------

pce_client = None


def run_scan(pce):
    with state_lock:
        if fleet_state["scanning"]:
            return
        fleet_state["scanning"] = True

    try:
        log.info("Starting fleet scan...")
        if not label_cache:
            fetch_labels(pce)

        workloads = collect_workloads(pce)
        vens = collect_vens(pce)
        log.info("Collected %d workloads, %d VENs", len(workloads), len(vens))

        fleet = analyze_fleet(workloads, vens)

        with state_lock:
            fleet_state["fleet"] = fleet
            fleet_state["last_scan"] = fleet["timestamp"]
            fleet_state["scan_count"] += 1
            fleet_state["error"] = None
            fleet_state["scanning"] = False

        score = fleet["summary"]["health_score"]
        total = fleet["summary"]["total"]
        log.info("Scan #%d complete: %d workloads, health score %d/100",
                 fleet_state["scan_count"], total, score)

    except Exception as e:
        log.exception("Fleet scan failed")
        with state_lock:
            fleet_state["error"] = str(e)
            fleet_state["scanning"] = False


def poller_loop(pce):
    while True:
        try:
            with state_lock:
                requested = fleet_state["scan_requested"]
                if requested:
                    fleet_state["scan_requested"] = False

            if requested:
                run_scan(pce)
            else:
                run_scan(pce)
        except Exception:
            log.exception("Scan loop error")

        time.sleep(SCAN_INTERVAL)


# ---------------------------------------------------------------------------
# Batch progression
# ---------------------------------------------------------------------------

VALID_PROGRESSIONS = {
    "idle": ["visibility_only", "selective", "full"],
    "visibility_only": ["selective", "full"],
    "selective": ["full"],
}

FILTER_MAP = {
    "idle_compat_pass": lambda fleet: fleet["progression"]["idle_compat_pass"],
    "idle_compat_fail": lambda fleet: fleet["progression"]["idle_compat_fail"],
    "idle_compat_unknown": lambda fleet: fleet["progression"]["idle_compat_unknown"],
    "idle_all": lambda fleet: (
        fleet["progression"]["idle_compat_pass"] +
        fleet["progression"]["idle_compat_fail"] +
        fleet["progression"]["idle_compat_unknown"]
    ),
    "visibility_ready": lambda fleet: fleet["progression"]["visibility_ready"],
    "visibility_all": lambda fleet: (
        fleet["progression"]["visibility_ready"] +
        fleet["progression"]["visibility_not_ready"]
    ),
}


def batch_progress(pce, fleet, body):
    to_mode = body.get("to_mode", "")
    if to_mode not in ("visibility_only", "selective", "full"):
        return {"error": f"Invalid to_mode: {to_mode}"}, 400

    dry_run = body.get("dry_run", False)
    max_batch = min(body.get("max_batch", 50), 200)

    # Resolve targets
    targets = body.get("targets", [])
    filter_name = body.get("filter", "")

    if filter_name and filter_name in FILTER_MAP:
        target_workloads = FILTER_MAP[filter_name](fleet)
    elif targets:
        href_set = set(targets)
        target_workloads = [w for w in fleet["workloads"] if w["href"] in href_set]
    else:
        return {"error": "Provide 'filter' or 'targets'"}, 400

    # Validate progression paths
    eligible = []
    skipped = []
    for wl in target_workloads:
        current = wl["mode"]
        allowed = VALID_PROGRESSIONS.get(current, [])
        if to_mode in allowed:
            eligible.append(wl)
        else:
            skipped.append({
                "hostname": wl["hostname"],
                "reason": f"Cannot progress from {current} to {to_mode}",
            })

    eligible = eligible[:max_batch]

    if dry_run:
        return {
            "dry_run": True,
            "would_progress": len(eligible),
            "would_skip": len(skipped),
            "eligible": [{"hostname": w["hostname"], "from": w["mode"], "to": to_mode} for w in eligible],
            "skipped": skipped,
        }, 200

    results = []
    success_count = 0
    fail_count = 0

    for wl in eligible:
        href = wl["href"]
        hostname = wl["hostname"]
        try:
            resp = pce.put(href, json={"enforcement_mode": to_mode})
            if resp.status_code in (200, 204):
                results.append({
                    "hostname": hostname,
                    "status": "success",
                    "from": wl["mode"],
                    "to": to_mode,
                })
                success_count += 1
                log.info("Progressed %s: %s -> %s", hostname, wl["mode"], to_mode)
            else:
                error_msg = f"HTTP {resp.status_code}"
                try:
                    error_msg += ": " + resp.text[:200]
                except Exception:
                    pass
                results.append({
                    "hostname": hostname,
                    "status": "error",
                    "error": error_msg,
                })
                fail_count += 1
        except Exception as e:
            results.append({
                "hostname": hostname,
                "status": "error",
                "error": str(e),
            })
            fail_count += 1

    # Trigger re-scan after batch operation
    with state_lock:
        fleet_state["scan_requested"] = True

    return {
        "progressed": success_count,
        "failed": fail_count,
        "skipped": len(skipped),
        "results": results,
    }, 200


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VEN Fleet Manager</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#11111b}
::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.score-gauge{transition:stroke-dashoffset 1.5s ease-in-out}
.tab-btn{cursor:pointer;padding:8px 16px;font-size:14px;font-weight:500;border-radius:8px 8px 0 0;border:1px solid transparent;color:#6c7086;transition:all .2s}
.tab-btn:hover{color:#cdd6f4;background:rgba(49,50,68,0.5)}
.tab-btn.active{color:#89b4fa;background:#1e1e2e;border-color:#313244;border-bottom-color:#1e1e2e}
.tab-panel{display:none}
.tab-panel.active{display:block}
.funnel-stage{position:relative;transition:all .2s}
.funnel-stage:hover{transform:translateY(-2px);box-shadow:0 4px 20px rgba(0,0,0,0.3)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.scanning-indicator{animation:pulse 2s infinite}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeIn .3s ease-out}
@media print{
  body{background:white!important;color:black!important;font-size:11px}
  .no-print{display:none!important}
  .bg-dark-800,.bg-dark-900{background:#f9f9f9!important;border:1px solid #ddd!important}
  *{color:black!important;border-color:#ddd!important}
}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-6">

<!-- Header -->
<div class="flex items-center justify-between mb-8 fade-in">
  <div>
    <h1 class="text-2xl font-bold text-white flex items-center gap-2">
      <svg class="w-7 h-7 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
      VEN Fleet Manager
    </h1>
    <div class="flex items-center gap-2 mt-1">
      <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
      <span id="status-text" class="text-sm text-gray-400">Loading...</span>
    </div>
  </div>
  <div class="flex items-center gap-3 no-print">
    <button onclick="triggerScan()" id="scan-btn" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Scan Now</button>
    <a id="export-link" href="/api/export/json" class="bg-dark-700 hover:bg-dark-800 text-gray-300 px-4 py-1.5 rounded text-sm border border-gray-600 inline-block no-underline">Export JSON</a>
  </div>
</div>

<!-- Score + Stats Row -->
<div class="grid grid-cols-1 lg:grid-cols-6 gap-4 mb-8">
  <!-- Health Score Gauge -->
  <div class="lg:col-span-2 bg-dark-800 rounded-xl border border-gray-700 p-6 flex flex-col items-center justify-center">
    <div class="relative" style="width:160px;height:160px">
      <svg viewBox="0 0 120 120" class="w-full h-full">
        <circle cx="60" cy="60" r="52" fill="none" stroke="#313244" stroke-width="8"/>
        <circle id="gauge-circle" cx="60" cy="60" r="52" fill="none" stroke="#89b4fa" stroke-width="8"
                stroke-linecap="round" stroke-dasharray="326.7" stroke-dashoffset="326.7"
                transform="rotate(-90 60 60)" class="score-gauge"/>
      </svg>
      <div class="absolute inset-0 flex flex-col items-center justify-center">
        <span id="gauge-score" class="text-4xl font-bold text-white">--</span>
        <span class="text-xs text-gray-500">Fleet Health</span>
      </div>
    </div>
    <div id="health-components" class="grid grid-cols-5 gap-1 mt-3 text-center w-full">
      <div><div class="text-xs text-gray-500">Online</div><div id="hc-online" class="text-sm font-semibold text-gray-300">--</div></div>
      <div><div class="text-xs text-gray-500">Enforced</div><div id="hc-enforced" class="text-sm font-semibold text-gray-300">--</div></div>
      <div><div class="text-xs text-gray-500">Version</div><div id="hc-version" class="text-sm font-semibold text-gray-300">--</div></div>
      <div><div class="text-xs text-gray-500">Heartbeat</div><div id="hc-heartbeat" class="text-sm font-semibold text-gray-300">--</div></div>
      <div><div class="text-xs text-gray-500">Compat</div><div id="hc-compat" class="text-sm font-semibold text-gray-300">--</div></div>
    </div>
  </div>

  <!-- Key Stats -->
  <div class="lg:col-span-4 grid grid-cols-2 lg:grid-cols-4 gap-4">
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-total" class="text-3xl font-bold text-blue-400">--</div>
      <div class="text-sm text-gray-500 mt-1">Total Workloads</div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-online" class="text-3xl font-bold text-green-400">--</div>
      <div class="text-sm text-gray-500 mt-1">Online</div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-enforced" class="text-3xl font-bold text-purple-400">--</div>
      <div class="text-sm text-gray-500 mt-1">Enforced (not idle)</div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-ready" class="text-3xl font-bold text-yellow-400">--</div>
      <div class="text-sm text-gray-500 mt-1">Ready to Progress</div>
    </div>
  </div>
</div>

<!-- Tabs -->
<div class="mb-0 flex border-b border-gray-700 no-print" id="tab-bar">
  <button class="tab-btn active" onclick="showTab('overview')">Overview</button>
  <button class="tab-btn" onclick="showTab('progression')">Enforcement Progression</button>
  <button class="tab-btn" onclick="showTab('health')">Agent Health</button>
  <button class="tab-btn" onclick="showTab('versions')">Versions</button>
  <button class="tab-btn" onclick="showTab('coverage')">Coverage</button>
</div>

<!-- Tab: Overview -->
<div id="tab-overview" class="tab-panel active bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <!-- Funnel -->
  <h2 class="text-lg font-semibold text-white mb-4">Enforcement Pipeline</h2>
  <div id="funnel-container" class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8"></div>

  <!-- Doughnut + Quick actions -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Enforcement Distribution</h3>
      <div style="height:280px"><canvas id="chart-enforcement"></canvas></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Quick Actions</h3>
      <div class="space-y-3" id="quick-actions">
        <button onclick="batchProgress('idle_compat_pass','visibility_only')" class="w-full text-left px-4 py-3 rounded-lg bg-dark-700 hover:bg-dark-800 border border-gray-600 transition">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-green-400">Progress idle (compat pass) to Visibility</div>
              <div class="text-xs text-gray-500 mt-0.5">Move workloads that passed compatibility checks</div>
            </div>
            <span id="qa-idle-pass-count" class="text-lg font-bold text-green-400">--</span>
          </div>
        </button>
        <button onclick="batchProgress('visibility_ready','selective')" class="w-full text-left px-4 py-3 rounded-lg bg-dark-700 hover:bg-dark-800 border border-gray-600 transition">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-blue-400">Progress visibility to Selective</div>
              <div class="text-xs text-gray-500 mt-0.5">Move workloads with policy received</div>
            </div>
            <span id="qa-vis-ready-count" class="text-lg font-bold text-blue-400">--</span>
          </div>
        </button>
        <button onclick="batchProgress('visibility_ready','full')" class="w-full text-left px-4 py-3 rounded-lg bg-dark-700 hover:bg-dark-800 border border-gray-600 transition">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-purple-400">Progress visibility to Full</div>
              <div class="text-xs text-gray-500 mt-0.5">Move workloads with policy directly to full enforcement</div>
            </div>
            <span id="qa-vis-full-count" class="text-lg font-bold text-purple-400">--</span>
          </div>
        </button>
      </div>
    </div>
  </div>
</div>

<!-- Tab: Enforcement Progression -->
<div id="tab-progression" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="flex items-center justify-between mb-4">
    <h2 class="text-lg font-semibold text-white">Enforcement Progression</h2>
    <div class="flex items-center gap-3">
      <select id="prog-filter" onchange="renderProgressionTable()" class="bg-dark-700 text-sm border border-gray-600 rounded px-3 py-1.5 text-gray-300">
        <option value="all">All Workloads</option>
        <option value="idle_pass">Idle - Ready to Progress</option>
        <option value="idle_fail">Idle - Compat Issues</option>
        <option value="idle_unknown">Idle - Waiting</option>
        <option value="vis_ready">Visibility - Ready for Enforcement</option>
        <option value="vis_not_ready">Visibility - Not Ready</option>
      </select>
      <select id="prog-sort" onchange="renderProgressionTable()" class="bg-dark-700 text-sm border border-gray-600 rounded px-3 py-1.5 text-gray-300">
        <option value="time_desc">Longest in mode first</option>
        <option value="time_asc">Shortest in mode first</option>
        <option value="hostname">Hostname A-Z</option>
      </select>
      <input type="text" id="prog-search" placeholder="Search..." oninput="renderProgressionTable()" class="bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-500 w-40">
    </div>
  </div>
  <div class="overflow-x-auto max-h-[600px] overflow-y-auto">
    <table class="w-full text-sm">
      <thead class="sticky top-0 bg-dark-800 z-10"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
        <th class="px-3 py-2">Hostname</th>
        <th class="px-3 py-2">Mode</th>
        <th class="px-3 py-2">Compat</th>
        <th class="px-3 py-2">Time in Mode</th>
        <th class="px-3 py-2">Labels</th>
        <th class="px-3 py-2">Online</th>
        <th class="px-3 py-2">Version</th>
        <th class="px-3 py-2 text-right">Action</th>
      </tr></thead>
      <tbody id="prog-table-body"></tbody>
    </table>
  </div>
  <div id="prog-table-footer" class="mt-3 text-xs text-gray-500"></div>
</div>

<!-- Tab: Agent Health -->
<div id="tab-health" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Online / Offline Split</h3>
      <div style="height:250px"><canvas id="chart-online"></canvas></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Version Distribution</h3>
      <div style="height:250px"><canvas id="chart-version-bar"></canvas></div>
    </div>
  </div>

  <!-- Offline workloads -->
  <div class="bg-dark-900 rounded-xl border border-gray-700 p-5 mb-6">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Offline Workloads</h3>
    <div class="overflow-x-auto max-h-[300px] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-dark-900"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
          <th class="px-3 py-2">Hostname</th><th class="px-3 py-2">IP</th><th class="px-3 py-2">Last Heartbeat</th><th class="px-3 py-2">Version</th>
        </tr></thead>
        <tbody id="offline-table-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Stale heartbeats -->
  <div class="bg-dark-900 rounded-xl border border-gray-700 p-5 mb-6">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Stale Heartbeats (&gt;""" + str(STALE_HEARTBEAT_HOURS) + r"""h)</h3>
    <div class="overflow-x-auto max-h-[300px] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-dark-900"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
          <th class="px-3 py-2">Hostname</th><th class="px-3 py-2">IP</th><th class="px-3 py-2">Last Heartbeat</th><th class="px-3 py-2">Hours Since</th>
        </tr></thead>
        <tbody id="stale-table-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Agent errors/warnings -->
  <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Agent Errors &amp; Warnings</h3>
    <div class="overflow-x-auto max-h-[300px] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-dark-900"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
          <th class="px-3 py-2">Hostname</th><th class="px-3 py-2">Type</th><th class="px-3 py-2">Severity</th><th class="px-3 py-2">Details</th>
        </tr></thead>
        <tbody id="errors-table-body"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Tab: Versions -->
<div id="tab-versions" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">VEN Version Distribution</h3>
      <div style="height:280px"><canvas id="chart-version-pie"></canvas></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Upgrade Readiness</h3>
      <div id="upgrade-summary" class="space-y-4"></div>
    </div>
  </div>

  <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Version Detail</h3>
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
          <th class="px-3 py-2">Version</th><th class="px-3 py-2">Count</th><th class="px-3 py-2">% of Fleet</th><th class="px-3 py-2">OS Breakdown</th><th class="px-3 py-2">Status</th>
        </tr></thead>
        <tbody id="version-table-body"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Tab: Coverage -->
<div id="tab-coverage" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Enforcement Mode by Application</h3>
      <div style="height:350px"><canvas id="chart-coverage-app"></canvas></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Enforcement Mode by Environment</h3>
      <div style="height:350px"><canvas id="chart-coverage-env"></canvas></div>
    </div>
  </div>
  <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
    <div id="unlabeled-info" class="text-sm text-gray-400"></div>
  </div>
</div>

<!-- Footer -->
<div class="text-center text-xs text-gray-600 py-4 no-print">
  VEN Fleet Manager &mdash; Powered by Illumio Plugger &mdash; Auto-refreshes every 15s
</div>

</div>

<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\/plugins\/[^/]+\/ui/);return m?m[0]:''})();
let fleetData=null;
let charts={};

function formatNum(n){
  if(n>=1e6)return(n/1e6).toFixed(1)+'M';
  if(n>=1e3)return(n/1e3).toFixed(1)+'K';
  return(n||0).toLocaleString();
}

function timeAgo(ts){
  if(!ts)return '--';
  const d=(Date.now()-new Date(ts).getTime())/1000;
  if(d<60)return 'just now';
  if(d<3600)return Math.floor(d/60)+'m ago';
  if(d<86400)return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}

function formatHours(h){
  if(!h&&h!==0)return '--';
  if(h<1)return Math.round(h*60)+'m';
  if(h<24)return Math.round(h)+'h';
  if(h<720)return Math.round(h/24)+'d';
  return Math.round(h/720)+'mo';
}

function scoreColor(score){
  if(score>=80)return '#a6e3a1';
  if(score>=60)return '#f9e2af';
  if(score>=40)return '#fab387';
  return '#f38ba8';
}

function modeColor(mode){
  return{idle:'#6c7086',visibility_only:'#89b4fa',selective:'#f9e2af',full:'#a6e3a1'}[mode]||'#6c7086';
}

function modeBadge(mode){
  const c=modeColor(mode);
  const label={idle:'Idle',visibility_only:'Visibility',selective:'Selective',full:'Full'}[mode]||mode;
  return '<span class="px-2 py-0.5 rounded text-xs font-medium" style="background:'+c+'22;color:'+c+';border:1px solid '+c+'44">'+label+'</span>';
}

function compatBadge(status){
  const map={pass:{color:'#a6e3a1',label:'Pass'},fail:{color:'#f38ba8',label:'Fail'},unknown:{color:'#6c7086',label:'Unknown'}};
  const s=map[status]||map.unknown;
  return '<span class="px-2 py-0.5 rounded text-xs font-medium" style="background:'+s.color+'22;color:'+s.color+';border:1px solid '+s.color+'44">'+s.label+'</span>';
}

function labelsStr(labels){
  if(!labels||!Object.keys(labels).length)return '<span class="text-gray-600">--</span>';
  return Object.entries(labels).map(([k,v])=>'<span class="text-xs px-1.5 py-0.5 rounded bg-dark-700 text-gray-400">'+k+':'+v+'</span>').join(' ');
}

// Tabs
function showTab(name){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  const btns=document.querySelectorAll('.tab-btn');
  const tabs=['overview','progression','health','versions','coverage'];
  const idx=tabs.indexOf(name);
  if(idx>=0&&btns[idx])btns[idx].classList.add('active');
}

// Charts initialization
function initCharts(){
  const doughnutOpts={responsive:true,maintainAspectRatio:false,cutout:'60%',plugins:{legend:{position:'bottom',labels:{color:'#a6adc8',usePointStyle:true,padding:8,font:{size:11}}}}};
  const barOpts={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280'}},y:{grid:{display:false},ticks:{color:'#a6adc8',font:{size:11}}}}};

  charts.enforcement=new Chart(document.getElementById('chart-enforcement'),{
    type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:[],borderWidth:0}]},options:doughnutOpts
  });
  charts.online=new Chart(document.getElementById('chart-online'),{
    type:'doughnut',data:{labels:['Online','Offline'],datasets:[{data:[0,0],backgroundColor:['#a6e3a1','#f38ba8'],borderWidth:0}]},options:doughnutOpts
  });
  charts.versionBar=new Chart(document.getElementById('chart-version-bar'),{
    type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#89b4fa44',borderColor:'#89b4fa',borderWidth:1,borderRadius:4}]},
    options:{...barOpts,indexAxis:'y'}
  });
  charts.versionPie=new Chart(document.getElementById('chart-version-pie'),{
    type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:[],borderWidth:0}]},options:doughnutOpts
  });
  charts.coverageApp=new Chart(document.getElementById('chart-coverage-app'),{
    type:'bar',data:{labels:[],datasets:[]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#a6adc8',usePointStyle:true,font:{size:11}}}},scales:{x:{stacked:true,grid:{display:false},ticks:{color:'#a6adc8',font:{size:10},maxRotation:45}},y:{stacked:true,grid:{color:'#31324422'},ticks:{color:'#6b7280'}}}}
  });
  charts.coverageEnv=new Chart(document.getElementById('chart-coverage-env'),{
    type:'bar',data:{labels:[],datasets:[]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#a6adc8',usePointStyle:true,font:{size:11}}}},scales:{x:{stacked:true,grid:{display:false},ticks:{color:'#a6adc8',font:{size:10},maxRotation:45}},y:{stacked:true,grid:{color:'#31324422'},ticks:{color:'#6b7280'}}}}
  });
}

// Main render
function renderAll(data){
  if(!data||!data.fleet){
    document.getElementById('status-text').textContent='No fleet data. Click Scan Now.';
    return;
  }
  fleetData=data;
  const f=data.fleet;
  const s=f.summary;

  // Status
  const dot=document.getElementById('status-dot');
  dot.className='w-2.5 h-2.5 rounded-full '+(data.scanning?'bg-yellow-500 scanning-indicator':'bg-green-500');
  document.getElementById('status-text').textContent=(data.scanning?'Scanning... ':'')+'Scan #'+(data.scan_count||0)+' · '+timeAgo(data.last_scan)+' · Score: '+s.health_score+'/100';

  // Gauge
  const circle=document.getElementById('gauge-circle');
  const pct=s.health_score/100;
  circle.style.strokeDashoffset=326.7*(1-pct);
  circle.style.stroke=scoreColor(s.health_score);
  document.getElementById('gauge-score').textContent=s.health_score;

  // Health components
  const hc=s.health_components;
  document.getElementById('hc-online').textContent=Math.round(hc.online_pct)+'%';
  document.getElementById('hc-enforced').textContent=Math.round(hc.enforcement_pct)+'%';
  document.getElementById('hc-version').textContent=Math.round(hc.version_pct)+'%';
  document.getElementById('hc-heartbeat').textContent=Math.round(hc.heartbeat_pct)+'%';
  document.getElementById('hc-compat').textContent=Math.round(hc.compat_pct)+'%';

  // Stats
  document.getElementById('stat-total').textContent=formatNum(s.total);
  document.getElementById('stat-online').textContent=formatNum(s.online);
  const enforced=s.total-(f.enforcement.idle||0);
  document.getElementById('stat-enforced').textContent=formatNum(enforced);
  const ready=(f.progression.idle_compat_pass||[]).length+(f.progression.visibility_ready||[]).length;
  document.getElementById('stat-ready').textContent=formatNum(ready);

  // Quick action counts
  document.getElementById('qa-idle-pass-count').textContent=(f.progression.idle_compat_pass||[]).length;
  document.getElementById('qa-vis-ready-count').textContent=(f.progression.visibility_ready||[]).length;
  document.getElementById('qa-vis-full-count').textContent=(f.progression.visibility_ready||[]).length;

  renderFunnel(f);
  renderEnforcementChart(f);
  renderProgressionTable();
  renderHealthTab(f);
  renderVersionsTab(f);
  renderCoverageTab(f);

  // Update export link
  document.getElementById('export-link').href=BASE+'/api/export/json';
}

function renderFunnel(f){
  const p=f.progression;
  const stages=[
    {label:'Idle',count:p.idle_total,color:'#6c7086',sub:[
      {label:'Compat Pass',count:(p.idle_compat_pass||[]).length,color:'#a6e3a1'},
      {label:'Compat Fail',count:(p.idle_compat_fail||[]).length,color:'#f38ba8'},
      {label:'Waiting',count:(p.idle_compat_unknown||[]).length,color:'#6c7086'},
    ]},
    {label:'Visibility',count:p.visibility_total,color:'#89b4fa',sub:[
      {label:'Ready',count:(p.visibility_ready||[]).length,color:'#a6e3a1'},
      {label:'Not Ready',count:(p.visibility_not_ready||[]).length,color:'#f9e2af'},
    ]},
    {label:'Selective',count:p.selective_total,color:'#f9e2af',sub:[]},
    {label:'Full',count:p.full_total,color:'#a6e3a1',sub:[]},
  ];
  const total=f.summary.total||1;
  const container=document.getElementById('funnel-container');
  container.innerHTML=stages.map((st,i)=>{
    const pct=Math.round(st.count/total*100);
    const subsHtml=st.sub.map(sub=>`<div class="flex items-center justify-between text-xs mt-1"><span style="color:${sub.color}">${sub.label}</span><span class="text-gray-400">${sub.count}</span></div>`).join('');
    const arrow=i<stages.length-1?`<div class="hidden md:flex absolute -right-4 top-1/2 -translate-y-1/2 z-10 text-gray-600"><svg width="16" height="24" viewBox="0 0 16 24"><path d="M2 2l12 10-12 10" fill="none" stroke="currentColor" stroke-width="2"/></svg></div>`:'';
    return `<div class="funnel-stage bg-dark-900 rounded-xl border border-gray-700 p-5 relative">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs uppercase tracking-wider" style="color:${st.color}">${st.label}</span>
        <span class="text-xs text-gray-500">${pct}%</span>
      </div>
      <div class="text-3xl font-bold text-white">${st.count}</div>
      <div class="w-full bg-dark-700 rounded-full h-1.5 mt-2 mb-2"><div class="h-1.5 rounded-full" style="width:${pct}%;background:${st.color}"></div></div>
      ${subsHtml}
      ${arrow}
    </div>`;
  }).join('');
}

function renderEnforcementChart(f){
  const dist=f.enforcement.distribution||{};
  const modes=['idle','visibility_only','selective','full'];
  const colors=['#6c7086','#89b4fa','#f9e2af','#a6e3a1'];
  const labels=['Idle','Visibility','Selective','Full'];
  const data=modes.map(m=>dist[m]||0);
  charts.enforcement.data.labels=labels;
  charts.enforcement.data.datasets[0].data=data;
  charts.enforcement.data.datasets[0].backgroundColor=colors;
  charts.enforcement.update('none');
}

function renderProgressionTable(){
  if(!fleetData||!fleetData.fleet)return;
  const f=fleetData.fleet;
  const filter=document.getElementById('prog-filter').value;
  const sort=document.getElementById('prog-sort').value;
  const search=(document.getElementById('prog-search').value||'').toLowerCase();

  let workloads=[];
  if(filter==='idle_pass')workloads=f.progression.idle_compat_pass||[];
  else if(filter==='idle_fail')workloads=f.progression.idle_compat_fail||[];
  else if(filter==='idle_unknown')workloads=f.progression.idle_compat_unknown||[];
  else if(filter==='vis_ready')workloads=f.progression.visibility_ready||[];
  else if(filter==='vis_not_ready')workloads=f.progression.visibility_not_ready||[];
  else workloads=f.workloads||[];

  if(search){
    workloads=workloads.filter(w=>{
      const lstr=Object.entries(w.labels||{}).map(([k,v])=>k+':'+v).join(' ').toLowerCase();
      return w.hostname.toLowerCase().includes(search)||lstr.includes(search)||(w.ip||'').includes(search);
    });
  }

  if(sort==='time_desc')workloads=[...workloads].sort((a,b)=>(b.time_in_mode_hours||0)-(a.time_in_mode_hours||0));
  else if(sort==='time_asc')workloads=[...workloads].sort((a,b)=>(a.time_in_mode_hours||0)-(b.time_in_mode_hours||0));
  else if(sort==='hostname')workloads=[...workloads].sort((a,b)=>a.hostname.localeCompare(b.hostname));

  const shown=workloads.slice(0,500);
  document.getElementById('prog-table-body').innerHTML=shown.map(w=>{
    const canProgress=w.mode==='idle'&&w.compat_status==='pass';
    const canEnforce=w.mode==='visibility_only'&&w.policy_received;
    let actionHtml='<span class="text-gray-600 text-xs">--</span>';
    if(canProgress)actionHtml=`<button onclick="progressOne('${w.href}','visibility_only','${w.hostname}')" class="px-2 py-0.5 text-xs rounded bg-green-900/50 hover:bg-green-800/50 text-green-400 border border-green-800/30">→ Visibility</button>`;
    else if(canEnforce)actionHtml=`<button onclick="progressOne('${w.href}','selective','${w.hostname}')" class="px-2 py-0.5 text-xs rounded bg-blue-900/50 hover:bg-blue-800/50 text-blue-400 border border-blue-800/30">→ Selective</button>`;
    return `<tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
      <td class="px-3 py-2"><code class="text-xs">${w.hostname}</code></td>
      <td class="px-3 py-2">${modeBadge(w.mode)}</td>
      <td class="px-3 py-2">${compatBadge(w.compat_status)}</td>
      <td class="px-3 py-2 text-xs text-gray-400">${formatHours(w.time_in_mode_hours)}</td>
      <td class="px-3 py-2">${labelsStr(w.labels)}</td>
      <td class="px-3 py-2">${w.online?'<span class="text-green-400 text-xs">Online</span>':'<span class="text-red-400 text-xs">Offline</span>'}</td>
      <td class="px-3 py-2 text-xs text-gray-500 font-mono">${w.version||'--'}</td>
      <td class="px-3 py-2 text-right">${actionHtml}</td>
    </tr>`;
  }).join('');
  document.getElementById('prog-table-footer').textContent='Showing '+shown.length+' of '+workloads.length+' workloads';
}

function renderHealthTab(f){
  const h=f.health;

  // Online/Offline chart
  charts.online.data.datasets[0].data=[h.online,h.offline];
  charts.online.update('none');

  // Version bar chart
  const vd=f.versions.distribution||{};
  const versions=Object.entries(vd).sort((a,b)=>b[1].count-a[1].count).slice(0,15);
  charts.versionBar.data.labels=versions.map(v=>v[0]);
  charts.versionBar.data.datasets[0].data=versions.map(v=>v[1].count);
  charts.versionBar.update('none');

  // Offline table
  document.getElementById('offline-table-body').innerHTML=(h.offline_workloads||[]).slice(0,200).map(w=>`
    <tr class="border-b border-gray-700/30">
      <td class="px-3 py-2"><code class="text-xs">${w.hostname}</code></td>
      <td class="px-3 py-2 text-xs text-gray-500 font-mono">${w.ip||'--'}</td>
      <td class="px-3 py-2 text-xs text-gray-500">${w.last_heartbeat?timeAgo(w.last_heartbeat):'--'}</td>
      <td class="px-3 py-2 text-xs text-gray-500 font-mono">${w.version||'--'}</td>
    </tr>
  `).join('')||'<tr><td colspan="4" class="px-3 py-4 text-center text-gray-600">No offline workloads</td></tr>';

  // Stale heartbeats table
  document.getElementById('stale-table-body').innerHTML=(h.stale_workloads||[]).slice(0,200).map(w=>`
    <tr class="border-b border-gray-700/30">
      <td class="px-3 py-2"><code class="text-xs">${w.hostname}</code></td>
      <td class="px-3 py-2 text-xs text-gray-500 font-mono">${w.ip||'--'}</td>
      <td class="px-3 py-2 text-xs text-gray-500">${w.last_heartbeat?timeAgo(w.last_heartbeat):'--'}</td>
      <td class="px-3 py-2 text-xs text-gray-500">${w.hours_since_heartbeat?Math.round(w.hours_since_heartbeat)+'h':'--'}</td>
    </tr>
  `).join('')||'<tr><td colspan="4" class="px-3 py-4 text-center text-gray-600">No stale heartbeats</td></tr>';

  // Errors/warnings table
  const allIssues=[...(h.agent_errors||[]),...(h.agent_warnings||[])];
  document.getElementById('errors-table-body').innerHTML=allIssues.slice(0,200).map(e=>{
    const sc=e.severity==='error'||e.severity==='err'?'text-red-400':'text-yellow-400';
    return `<tr class="border-b border-gray-700/30">
      <td class="px-3 py-2"><code class="text-xs">${e.hostname}</code></td>
      <td class="px-3 py-2 text-xs text-gray-400">${e.type}</td>
      <td class="px-3 py-2"><span class="${sc} text-xs font-medium">${e.severity}</span></td>
      <td class="px-3 py-2 text-xs text-gray-500">${e.audit_event||'--'}</td>
    </tr>`;
  }).join('')||'<tr><td colspan="4" class="px-3 py-4 text-center text-gray-600">No agent issues</td></tr>';
}

function renderVersionsTab(f){
  const v=f.versions;
  const dist=v.distribution||{};
  const total=v.total_with_version||1;

  // Pie chart
  const palette=['#89b4fa','#a6e3a1','#f9e2af','#fab387','#f38ba8','#cba6f7','#94e2d5','#f5c2e7','#74c7ec','#b4befe'];
  const entries=Object.entries(dist).sort((a,b)=>b[1].count-a[1].count);
  charts.versionPie.data.labels=entries.map(e=>e[0]);
  charts.versionPie.data.datasets[0].data=entries.map(e=>e[1].count);
  charts.versionPie.data.datasets[0].backgroundColor=entries.map((_,i)=>palette[i%palette.length]);
  charts.versionPie.update('none');

  // Upgrade summary
  document.getElementById('upgrade-summary').innerHTML=`
    <div class="flex items-center justify-between p-3 rounded-lg bg-dark-700 border border-gray-600">
      <span class="text-sm text-gray-400">Target Version</span>
      <span class="text-sm font-mono font-semibold text-blue-400">${v.target||'auto-detect'}</span>
    </div>
    <div class="flex items-center justify-between p-3 rounded-lg bg-dark-700 border border-gray-600">
      <span class="text-sm text-gray-400">On Target</span>
      <span class="text-sm font-semibold text-green-400">${v.on_target} / ${total} (${Math.round(v.on_target/total*100)}%)</span>
    </div>
    <div class="flex items-center justify-between p-3 rounded-lg bg-dark-700 border border-gray-600">
      <span class="text-sm text-gray-400">Needs Upgrade</span>
      <span class="text-sm font-semibold text-yellow-400">${v.needs_upgrade}</span>
    </div>
    <div class="flex items-center justify-between p-3 rounded-lg bg-dark-700 border border-gray-600">
      <span class="text-sm text-gray-400">Oldest Version</span>
      <span class="text-sm font-mono text-red-400">${v.oldest||'--'}</span>
    </div>
    <div class="flex items-center justify-between p-3 rounded-lg bg-dark-700 border border-gray-600">
      <span class="text-sm text-gray-400">Newest Version</span>
      <span class="text-sm font-mono text-green-400">${v.newest||'--'}</span>
    </div>
  `;

  // Version table
  document.getElementById('version-table-body').innerHTML=entries.map(([ver,info])=>{
    const pct=Math.round(info.count/total*100);
    const isTarget=ver===v.target;
    const statusBadge=isTarget?'<span class="text-xs px-2 py-0.5 rounded bg-green-900/50 text-green-400 border border-green-800/30">Target</span>'
      :ver===v.oldest?'<span class="text-xs px-2 py-0.5 rounded bg-red-900/50 text-red-400 border border-red-800/30">Oldest</span>'
      :'<span class="text-xs px-2 py-0.5 rounded bg-yellow-900/50 text-yellow-400 border border-yellow-800/30">Upgrade</span>';
    const osBreakdown=Object.entries(info.os_breakdown||{}).slice(0,3).map(([os,cnt])=>os+' ('+cnt+')').join(', ');
    return `<tr class="border-b border-gray-700/30 ${isTarget?'bg-green-900/10':''}">
      <td class="px-3 py-2 font-mono text-sm">${ver}</td>
      <td class="px-3 py-2 text-sm text-gray-300">${info.count}</td>
      <td class="px-3 py-2 text-sm text-gray-400">${pct}%</td>
      <td class="px-3 py-2 text-xs text-gray-500">${osBreakdown||'--'}</td>
      <td class="px-3 py-2">${statusBadge}</td>
    </tr>`;
  }).join('')||'<tr><td colspan="5" class="px-3 py-4 text-center text-gray-600">No version data</td></tr>';
}

function renderCoverageTab(f){
  const cov=f.coverage;
  const modes=['idle','visibility_only','selective','full'];
  const modeLabels=['Idle','Visibility','Selective','Full'];
  const modeColors=['#6c708666','#89b4fa66','#f9e2af66','#a6e3a166'];
  const modeBorders=['#6c7086','#89b4fa','#f9e2af','#a6e3a1'];

  // By app
  const apps=Object.entries(cov.by_app||{}).sort((a,b)=>{
    const ta=Object.values(a[1]).reduce((s,v)=>s+v,0);
    const tb=Object.values(b[1]).reduce((s,v)=>s+v,0);
    return tb-ta;
  }).slice(0,20);
  charts.coverageApp.data.labels=apps.map(a=>a[0]);
  charts.coverageApp.data.datasets=modes.map((m,i)=>({
    label:modeLabels[i],data:apps.map(a=>(a[1][m]||0)),backgroundColor:modeColors[i],borderColor:modeBorders[i],borderWidth:1
  }));
  charts.coverageApp.update('none');

  // By env
  const envs=Object.entries(cov.by_env||{}).sort((a,b)=>{
    const ta=Object.values(a[1]).reduce((s,v)=>s+v,0);
    const tb=Object.values(b[1]).reduce((s,v)=>s+v,0);
    return tb-ta;
  }).slice(0,20);
  charts.coverageEnv.data.labels=envs.map(e=>e[0]);
  charts.coverageEnv.data.datasets=modes.map((m,i)=>({
    label:modeLabels[i],data:envs.map(e=>(e[1][m]||0)),backgroundColor:modeColors[i],borderColor:modeBorders[i],borderWidth:1
  }));
  charts.coverageEnv.update('none');

  // Unlabeled
  document.getElementById('unlabeled-info').innerHTML=`<span class="text-gray-500">Unlabeled workloads:</span> <span class="font-semibold text-white">${cov.unlabeled||0}</span>`;
}

// Batch progress
async function batchProgress(filter,toMode){
  const count=filter==='idle_compat_pass'?(fleetData.fleet.progression.idle_compat_pass||[]).length
    :(fleetData.fleet.progression.visibility_ready||[]).length;
  if(!count){alert('No workloads match this filter.');return;}
  const label={visibility_only:'Visibility Only',selective:'Selective',full:'Full'}[toMode]||toMode;
  if(!confirm('Progress '+count+' workload(s) to '+label+'?\n\nThis will modify enforcement mode on your PCE.'))return;
  try{
    const resp=await fetch(BASE+'/api/progress',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({filter:filter,to_mode:toMode,dry_run:false,max_batch:50})
    });
    const result=await resp.json();
    if(result.error){alert('Error: '+result.error);return;}
    alert('Progressed: '+result.progressed+'\nFailed: '+result.failed+'\nSkipped: '+result.skipped);
    fetchData();
  }catch(e){alert('Request failed: '+e);}
}

async function progressOne(href,toMode,hostname){
  const label={visibility_only:'Visibility Only',selective:'Selective',full:'Full'}[toMode]||toMode;
  if(!confirm('Progress "'+hostname+'" to '+label+'?'))return;
  try{
    const resp=await fetch(BASE+'/api/progress',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({targets:[href],to_mode:toMode,dry_run:false,max_batch:1})
    });
    const result=await resp.json();
    if(result.error){alert('Error: '+result.error);return;}
    if(result.progressed)alert('Success: '+hostname+' → '+label);
    else alert('Failed: '+(result.results||[]).map(r=>r.error).join(', '));
    fetchData();
  }catch(e){alert('Request failed: '+e);}
}

async function triggerScan(){
  try{
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning-indicator';
    document.getElementById('status-text').textContent='Scan triggered...';
    await fetch(BASE+'/api/scan',{method:'POST'});
  }catch(e){console.error(e);}
}

async function fetchData(){
  try{
    const resp=await fetch(BASE+'/api/state');
    const data=await resp.json();
    renderAll(data);
  }catch(e){console.error('Fetch failed:',e);}
}

// Init
initCharts();
fetchData();
setInterval(fetchData,15000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class FleetHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, "")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/" or path == "":
            self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")

        elif path == "/healthz":
            self._send(200, json.dumps({"status": "healthy"}))

        elif path == "/api/state":
            with state_lock:
                data = {
                    "scanning": fleet_state["scanning"],
                    "error": fleet_state["error"],
                    "last_scan": fleet_state["last_scan"],
                    "scan_count": fleet_state["scan_count"],
                    "fleet": fleet_state["fleet"],
                }
            self._send(200, json.dumps(data, default=str))

        elif path == "/api/fleet":
            with state_lock:
                fleet = fleet_state["fleet"]
            if fleet:
                summary = {
                    "timestamp": fleet["timestamp"],
                    "summary": fleet["summary"],
                    "enforcement": fleet["enforcement"],
                }
                self._send(200, json.dumps(summary, default=str))
            else:
                self._send(200, json.dumps({"error": "No scan data yet"}))

        elif path == "/api/progression":
            with state_lock:
                fleet = fleet_state["fleet"]
            if fleet:
                self._send(200, json.dumps(fleet["progression"], default=str))
            else:
                self._send(200, json.dumps({"error": "No scan data yet"}))

        elif path == "/api/health":
            with state_lock:
                fleet = fleet_state["fleet"]
            if fleet:
                self._send(200, json.dumps(fleet["health"], default=str))
            else:
                self._send(200, json.dumps({"error": "No scan data yet"}))

        elif path == "/api/versions":
            with state_lock:
                fleet = fleet_state["fleet"]
            if fleet:
                self._send(200, json.dumps(fleet["versions"], default=str))
            else:
                self._send(200, json.dumps({"error": "No scan data yet"}))

        elif path == "/api/export/json":
            with state_lock:
                fleet = fleet_state["fleet"]
            if fleet:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition", "attachment; filename=ven-fleet-export.json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(fleet, default=str, indent=2).encode())
            else:
                self._send(200, json.dumps({"error": "No scan data yet"}))

        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""

        if path == "/api/scan":
            with state_lock:
                if fleet_state["scanning"]:
                    self._send(409, json.dumps({"error": "Scan already in progress"}))
                    return
                fleet_state["scan_requested"] = True
            self._send(200, json.dumps({"status": "scan_requested"}))

        elif path == "/api/progress":
            try:
                body = json.loads(raw_body) if raw_body else {}
            except json.JSONDecodeError:
                self._send(400, json.dumps({"error": "Invalid JSON"}))
                return

            with state_lock:
                fleet = fleet_state["fleet"]

            if not fleet:
                self._send(400, json.dumps({"error": "No fleet data available. Run a scan first."}))
                return

            result, code = batch_progress(pce_client, fleet, body)
            self._send(code, json.dumps(result, default=str))

        else:
            self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global pce_client

    log.info("VEN Fleet Manager starting...")
    log.info("Config: scan_interval=%ds, offline_threshold=%dh, stale_heartbeat=%dh, target_version=%s",
             SCAN_INTERVAL, OFFLINE_THRESHOLD_HOURS, STALE_HEARTBEAT_HOURS, TARGET_VEN_VERSION or "(auto)")

    pce_client = get_pce()
    log.info("Connected to PCE: %s", pce_client.base_url)

    # Initial scan
    run_scan(pce_client)

    # Background poller
    poller = threading.Thread(target=poller_loop, args=(pce_client,), daemon=True)
    poller.start()

    # HTTP server
    server = HTTPServer(("0.0.0.0", HTTP_PORT), FleetHandler)
    log.info("Dashboard listening on http://0.0.0.0:%d", HTTP_PORT)

    def shutdown(sig, frame):
        log.info("Shutting down...")
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server.serve_forever()
    log.info("Stopped.")


if __name__ == "__main__":
    main()
