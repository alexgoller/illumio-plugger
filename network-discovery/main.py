#!/usr/bin/env python3
"""
network-discovery — Scan traffic flows for bare IPs, reverse-DNS resolve
them, and create unmanaged workloads in the PCE.

Plugger injects PCE connection details as environment variables:
  PCE_HOST, PCE_PORT, PCE_ORG_ID, PCE_API_KEY, PCE_API_SECRET
"""

import ipaddress
import json
import logging
import os
import re
import signal
import socket
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import dns.reversename
from illumio import PolicyComputeEngine
from illumio.explorer import TrafficQuery

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("network-discovery")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
POLL_INTERVAL = max(300, int(os.environ.get("POLL_INTERVAL", "3600")))
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "24"))
MAX_RESULTS = int(os.environ.get("MAX_RESULTS", "10000"))
INTERNAL_SUBNETS_STR = os.environ.get("INTERNAL_SUBNETS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
DNS_SERVER = os.environ.get("DNS_SERVER", "").strip()
DNS_TIMEOUT = int(os.environ.get("DNS_TIMEOUT", "5"))
MODE = os.environ.get("MODE", "dry-run").strip().lower()
HOSTNAME_LABEL_RULES_STR = os.environ.get("HOSTNAME_LABEL_RULES", "").strip()
STATE_FILE = os.environ.get("STATE_FILE", "/data/state.json")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

# Parse subnets
SUBNETS = []
for s in INTERNAL_SUBNETS_STR.split(","):
    s = s.strip()
    if s:
        try:
            SUBNETS.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            log.warning("Invalid subnet: %s", s)

# Parse hostname label rules
LABEL_RULES = []
if HOSTNAME_LABEL_RULES_STR:
    try:
        raw = json.loads(HOSTNAME_LABEL_RULES_STR)
        for rule in raw:
            pattern = rule.get("pattern", "")
            labels = rule.get("labels", {})
            if pattern and labels:
                LABEL_RULES.append({"regex": re.compile(pattern, re.IGNORECASE), "labels": labels})
        log.info("Loaded %d hostname label rules", len(LABEL_RULES))
    except Exception as e:
        log.warning("Failed to parse HOSTNAME_LABEL_RULES: %s", e)

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
discovery_state = {
    "last_scan": None,
    "last_scan_duration": 0,
    "scan_count": 0,
    "scanning": False,
    "error": None,
    "mode": MODE,
    "funnel": {
        "total_endpoints": 0,
        "bare_ips": 0,
        "unique_bare_ips": 0,
        "internal": 0,
        "external": 0,
        "resolved": 0,
        "unresolved": 0,
        "already_exists": 0,
        "created": 0,
        "labeled": 0,
    },
    "dns_stats": {
        "total_queries": 0,
        "successful": 0,
        "failed": 0,
        "timeout": 0,
        "avg_latency_ms": 0,
        "cache_hits": 0,
    },
    "subnet_breakdown": [],
    "discovered": [],
    "activity": [],
    "cumulative": {
        "total_ips_discovered": 0,
        "total_workloads_created": 0,
        "total_dns_queries": 0,
        "scan_history": [],
    },
}

label_cache = {}
label_href_map = {}
dns_cache = {}
existing_workload_ips = set()
created_workload_ips = set()
pce_client = None

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
    global label_cache, label_href_map
    try:
        resp = pce.get("/labels")
        if resp.status_code == 200:
            for lbl in resp.json():
                href = lbl.get("href", "")
                key = lbl.get("key", "")
                value = lbl.get("value", "")
                if href:
                    label_cache[href] = {"key": key, "value": value}
                    label_href_map[(key, value)] = href
            log.info("Loaded %d labels", len(label_cache))
    except Exception as e:
        log.warning("Failed to fetch labels: %s", e)


def ensure_label(pce, key, value):
    existing = label_href_map.get((key, value))
    if existing:
        return existing
    try:
        resp = pce.post("/labels", json={"key": key, "value": value})
        if resp.status_code in (200, 201):
            href = resp.json().get("href", "")
            if href:
                label_href_map[(key, value)] = href
                label_cache[href] = {"key": key, "value": value}
            return href
    except Exception as e:
        log.warning("Failed to create label %s:%s — %s", key, value, e)
    return ""


def fetch_existing_workloads(pce):
    global existing_workload_ips
    try:
        resp = pce.get("/workloads")
        if resp.status_code == 200:
            ips = set()
            for wl in resp.json():
                for iface in wl.get("interfaces", []):
                    addr = iface.get("address", "")
                    if addr and ":" not in addr:
                        ips.add(addr)
            existing_workload_ips = ips
            log.info("Loaded %d existing workload IPs", len(ips))
    except Exception as e:
        log.warning("Failed to fetch workloads: %s", e)


def pce_console_url(href):
    pce_host = os.environ.get("PCE_HOST", "localhost")
    m = re.match(r'.*/orgs/\d+/(.*)', href)
    path = m.group(1) if m else href.lstrip('/')
    path = path.replace('sec_policy/draft/', '').replace('sec_policy/active/', '')
    return f"https://{pce_host}/#/{path}"

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def is_internal(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in SUBNETS)
    except ValueError:
        return False


def get_subnet(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in SUBNETS:
            if addr in net:
                return str(net)
    except ValueError:
        pass
    return None


def is_bare_ip(endpoint):
    if not isinstance(endpoint, dict):
        return False
    ip = endpoint.get("ip", "")
    if not ip or ":" in ip:
        return False
    hostname = (endpoint.get("workload") or {}).get("hostname", "")
    return not hostname

# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

DNS_CACHE_TTL = 3600
DNS_NEG_CACHE_TTL = 600

def resolve_dns(ip_str):
    now = time.time()
    if ip_str in dns_cache:
        hostname, ts = dns_cache[ip_str]
        ttl = DNS_CACHE_TTL if hostname else DNS_NEG_CACHE_TTL
        if now - ts < ttl:
            return hostname, 0, None, True

    start = time.time()
    hostname = None
    error = None

    # System DNS first
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        result = socket.gethostbyaddr(ip_str)
        hostname = result[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        pass

    # Fallback to custom DNS server
    if not hostname and DNS_SERVER:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [DNS_SERVER]
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT
            rev = dns.reversename.from_address(ip_str)
            answer = resolver.resolve(rev, "PTR")
            hostname = str(answer[0]).rstrip(".")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            error = "nxdomain"
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            error = "timeout"
        except Exception as e:
            error = str(e)

    if not hostname and not error:
        error = "unresolved"

    latency_ms = (time.time() - start) * 1000
    dns_cache[ip_str] = (hostname, now)
    return hostname, latency_ms, error, False

# ---------------------------------------------------------------------------
# Label inference
# ---------------------------------------------------------------------------

def infer_labels(hostname):
    for rule in LABEL_RULES:
        if rule["regex"].search(hostname):
            return dict(rule["labels"])
    return {}

# ---------------------------------------------------------------------------
# Core discovery
# ---------------------------------------------------------------------------

def scan_traffic(pce):
    with state_lock:
        if discovery_state["scanning"]:
            return
        discovery_state["scanning"] = True

    scan_start = time.time()
    log.info("Starting traffic scan (lookback=%dh, max=%d)...", LOOKBACK_HOURS, MAX_RESULTS)

    try:
        fetch_labels(pce)
        fetch_existing_workloads(pce)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

        query = TrafficQuery.build(
            start_date=start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_date=end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            policy_decisions=["allowed", "blocked", "potentially_blocked", "unknown"],
            max_results=MAX_RESULTS,
        )

        raw_flows = pce.get_traffic_flows_async(
            query_name="plugger-network-discovery",
            traffic_query=query,
        )

        flows = []
        for f in raw_flows:
            if hasattr(f, 'to_json'):
                flow = f.to_json()
                if isinstance(flow, str):
                    flow = json.loads(flow)
            elif hasattr(f, '__dict__'):
                flow = f.__dict__
            elif isinstance(f, dict):
                flow = f
            else:
                continue
            flows.append(flow)

        log.info("Got %d traffic flows", len(flows))

        # Extract bare IPs
        bare_ips = {}
        total_endpoints = 0
        bare_count = 0
        for flow in flows:
            for direction in ("src", "dst"):
                ep = flow.get(direction, {})
                total_endpoints += 1
                if is_bare_ip(ep):
                    bare_count += 1
                    ip = ep["ip"]
                    if ip not in bare_ips:
                        bare_ips[ip] = {"directions": set(), "flow_count": 0, "services": set()}
                    bare_ips[ip]["directions"].add(direction)
                    bare_ips[ip]["flow_count"] += flow.get("num_connections", 1)
                    svc = flow.get("service", {})
                    if isinstance(svc, dict):
                        port = svc.get("port", "?")
                        proto = svc.get("proto", "?")
                        bare_ips[ip]["services"].add(f"{port}/{proto}")

        log.info("Found %d bare IPs from %d endpoints", len(bare_ips), total_endpoints)

        # Classify internal vs external
        internal = {}
        external_count = 0
        subnet_counts = Counter()
        for ip, meta in bare_ips.items():
            if is_internal(ip):
                meta["subnet"] = get_subnet(ip)
                internal[ip] = meta
                if meta["subnet"]:
                    subnet_counts[meta["subnet"]] += 1
            else:
                external_count += 1

        # Dedup against known workloads
        new_ips = {}
        already_exists = 0
        for ip, meta in internal.items():
            if ip in existing_workload_ips or ip in created_workload_ips:
                already_exists += 1
            else:
                new_ips[ip] = meta

        log.info("Internal: %d, external: %d, new: %d, already exists: %d",
                 len(internal), external_count, len(new_ips), already_exists)

        # DNS resolution
        dns_results = {}
        dns_total = 0
        dns_ok = 0
        dns_fail = 0
        dns_timeout = 0
        dns_cached = 0
        latencies = []

        for ip in new_ips:
            hostname, latency_ms, error, was_cached = resolve_dns(ip)
            dns_total += 1
            if was_cached:
                dns_cached += 1
            if hostname:
                dns_ok += 1
                dns_results[ip] = hostname
            else:
                dns_fail += 1
                if error == "timeout":
                    dns_timeout += 1
            if not was_cached:
                latencies.append(latency_ms)

        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        log.info("DNS: %d resolved, %d failed, %d timeouts, %d cache hits",
                 dns_ok, dns_fail, dns_timeout, dns_cached)

        # Group by hostname (multi-homed hosts)
        hostname_groups = defaultdict(list)
        for ip, hostname in dns_results.items():
            hostname_groups[hostname].append(ip)

        # Create workloads
        created = 0
        labeled = 0
        activity = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for hostname, ips in hostname_groups.items():
            labels_dict = infer_labels(hostname)

            if MODE == "auto-create":
                label_hrefs = []
                for key, value in labels_dict.items():
                    href = ensure_label(pce, key, value)
                    if href:
                        label_hrefs.append({"href": href})

                interfaces = [{"address": ip, "friendly_name": f"eth{i}"} for i, ip in enumerate(ips)]
                body = {
                    "name": hostname,
                    "hostname": hostname,
                    "interfaces": interfaces,
                    "service_provider": "plugger-network-discovery",
                    "description": f"Discovered from traffic flows by plugger network-discovery",
                }
                if label_hrefs:
                    body["labels"] = label_hrefs

                try:
                    resp = pce.post("/workloads", json=body)
                    if resp.status_code in (200, 201):
                        created += 1
                        if labels_dict:
                            labeled += 1
                        for ip in ips:
                            created_workload_ips.add(ip)
                        wl_href = resp.json().get("href", "")
                        activity.append({
                            "timestamp": now_iso,
                            "action": "created",
                            "ip": ", ".join(ips),
                            "hostname": hostname,
                            "detail": f"Created with {len(ips)} interface(s)" + (f", labels: {labels_dict}" if labels_dict else ""),
                            "href": wl_href,
                        })
                        log.info("Created workload: %s (%s)", hostname, ", ".join(ips))
                    else:
                        activity.append({
                            "timestamp": now_iso,
                            "action": "failed",
                            "ip": ", ".join(ips),
                            "hostname": hostname,
                            "detail": f"HTTP {resp.status_code}: {resp.text[:200]}",
                        })
                        log.warning("Failed to create %s: HTTP %d", hostname, resp.status_code)
                except Exception as e:
                    activity.append({
                        "timestamp": now_iso,
                        "action": "failed",
                        "ip": ", ".join(ips),
                        "hostname": hostname,
                        "detail": str(e),
                    })
            else:
                activity.append({
                    "timestamp": now_iso,
                    "action": "pending",
                    "ip": ", ".join(ips),
                    "hostname": hostname,
                    "detail": f"Would create with {len(ips)} interface(s)" + (f", labels: {labels_dict}" if labels_dict else "") + " (dry-run)",
                })
                if labels_dict:
                    labeled += 1

        # Build discovered IPs list
        discovered = []
        for ip, meta in internal.items():
            hostname = dns_results.get(ip)
            status = "exists"
            if ip in created_workload_ips:
                status = "created"
            elif hostname and MODE == "auto-create":
                status = "created"
            elif hostname:
                status = "pending"
            elif ip in new_ips:
                status = "unresolved"
            labels_dict = infer_labels(hostname) if hostname else {}
            discovered.append({
                "ip": ip,
                "hostname": hostname or "",
                "subnet": meta.get("subnet", ""),
                "status": status,
                "labels": labels_dict,
                "directions": sorted(meta["directions"]),
                "flow_count": meta["flow_count"],
                "services": sorted(list(meta.get("services", set()))[:5]),
            })

        discovered.sort(key=lambda x: x["ip"])

        # Subnet breakdown
        subnet_breakdown = []
        for subnet_str, count in sorted(subnet_counts.items()):
            resolved_in_subnet = sum(1 for ip, meta in internal.items()
                                     if meta.get("subnet") == subnet_str and ip in dns_results)
            created_in_subnet = sum(1 for ip, meta in internal.items()
                                    if meta.get("subnet") == subnet_str and ip in created_workload_ips)
            subnet_breakdown.append({
                "subnet": subnet_str,
                "ips": count,
                "resolved": resolved_in_subnet,
                "created": created_in_subnet,
            })

        duration = time.time() - scan_start

        with state_lock:
            discovery_state["last_scan"] = now_iso
            discovery_state["last_scan_duration"] = round(duration, 1)
            discovery_state["scan_count"] += 1
            discovery_state["scanning"] = False
            discovery_state["error"] = None
            discovery_state["funnel"] = {
                "total_endpoints": total_endpoints,
                "bare_ips": bare_count,
                "unique_bare_ips": len(bare_ips),
                "internal": len(internal),
                "external": external_count,
                "resolved": dns_ok,
                "unresolved": dns_fail,
                "already_exists": already_exists,
                "created": created,
                "labeled": labeled,
            }
            discovery_state["dns_stats"] = {
                "total_queries": dns_total,
                "successful": dns_ok,
                "failed": dns_fail,
                "timeout": dns_timeout,
                "avg_latency_ms": round(avg_latency, 1),
                "cache_hits": dns_cached,
            }
            discovery_state["subnet_breakdown"] = subnet_breakdown
            discovery_state["discovered"] = discovered
            old_activity = discovery_state["activity"]
            discovery_state["activity"] = (activity + old_activity)[:200]

            cum = discovery_state["cumulative"]
            cum["total_ips_discovered"] += len(new_ips)
            cum["total_workloads_created"] += created
            cum["total_dns_queries"] += dns_total
            cum["scan_history"].append({
                "timestamp": now_iso,
                "bare_ips": len(bare_ips),
                "internal": len(internal),
                "resolved": dns_ok,
                "created": created,
            })
            cum["scan_history"] = cum["scan_history"][-50:]

        log.info("Scan #%d complete: %d bare IPs, %d internal, %d resolved, %d created (%.1fs)",
                 discovery_state["scan_count"], len(bare_ips), len(internal), dns_ok, created, duration)

        # Publish report if there's something interesting
        if dns_ok > 0 or created > 0:
            from plugger_report import publish_report
            sev = "info"
            if created > 0:
                sev = "warning"
            lines = [
                f"**Scan #{discovery_state['scan_count']}** completed in {duration:.1f}s",
                f"- Bare IPs found: **{len(bare_ips)}** ({len(internal)} internal, {external_count} external)",
                f"- DNS resolved: **{dns_ok}** / {dns_ok + dns_fail}",
                f"- Already known: {already_exists}",
            ]
            if created > 0:
                lines.append(f"- **Workloads created: {created}** ({labeled} with labels)")
            elif len(hostname_groups) > 0 and MODE == "dry-run":
                lines.append(f"- Would create: {len(hostname_groups)} workloads (dry-run)")
            publish_report(
                title=f"Discovery: {dns_ok} resolved, {created} created" if created else f"Discovery: {dns_ok} IPs resolved",
                body="\n".join(lines),
                severity=sev,
                tags=["discovery", "dns", "scan"],
                data={"bare_ips": len(bare_ips), "internal": len(internal), "resolved": dns_ok, "created": created},
            )

    except Exception as e:
        log.exception("Scan failed")
        with state_lock:
            discovery_state["scanning"] = False
            discovery_state["error"] = str(e)

# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def save_state():
    try:
        data = {
            "created_ips": list(created_workload_ips),
            "dns_cache": {ip: [h, t] for ip, (h, t) in dns_cache.items()},
            "cumulative": discovery_state["cumulative"],
            "scan_count": discovery_state["scan_count"],
        }
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.rename(tmp, STATE_FILE)
    except Exception as e:
        log.warning("Failed to save state: %s", e)


def load_state():
    global created_workload_ips, dns_cache
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
        created_workload_ips = set(data.get("created_ips", []))
        for ip, (h, t) in data.get("dns_cache", {}).items():
            dns_cache[ip] = (h, t)
        discovery_state["cumulative"] = data.get("cumulative", discovery_state["cumulative"])
        discovery_state["scan_count"] = data.get("scan_count", 0)
        log.info("Loaded state: %d created IPs, %d DNS cache entries",
                 len(created_workload_ips), len(dns_cache))
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("Failed to load state: %s", e)

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Discovery</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px;height:6px} ::-webkit-scrollbar-track{background:#11111b} ::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.tab-btn{cursor:pointer;padding:8px 16px;font-size:14px;font-weight:500;border-radius:8px 8px 0 0;color:#6c7086;border:1px solid transparent;border-bottom:none}
.tab-btn:hover{color:#cdd6f4} .tab-btn.active{color:#89b4fa;background:#1e1e2e;border-color:#313244}
.tab-panel{display:none} .tab-panel.active{display:block}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-6 py-8">

<!-- Header -->
<div class="flex items-center justify-between mb-8">
  <div>
    <h1 class="text-2xl font-bold text-white">Network Discovery</h1>
    <p class="text-sm text-gray-500 mt-1">Scan traffic flows for unknown IPs, resolve hostnames, create unmanaged workloads</p>
  </div>
  <div class="flex items-center gap-3">
    <span id="mode-badge" class="text-xs px-3 py-1 rounded-full font-medium"></span>
    <span id="status-badge" class="flex items-center gap-1.5 text-sm">
      <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
      <span id="status-text" class="text-gray-400">Loading...</span>
    </span>
    <button onclick="triggerScan()" class="px-3 py-1.5 text-sm rounded bg-blue-700 hover:bg-blue-600 text-white transition-colors">Scan Now</button>
  </div>
</div>

<!-- Stats -->
<div class="grid grid-cols-2 lg:grid-cols-6 gap-4 mb-8">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-bare" class="text-2xl font-bold text-blue-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Bare IPs Found</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-internal" class="text-2xl font-bold text-purple-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Internal IPs</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-resolved" class="text-2xl font-bold text-green-400">--</div>
    <div class="text-xs text-gray-500 mt-1">DNS Resolved</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-created" class="text-2xl font-bold text-cyan-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Workloads Created</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-rate" class="text-2xl font-bold text-yellow-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Resolution Rate</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-labeled" class="text-2xl font-bold text-pink-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Labels Inferred</div>
  </div>
</div>

<!-- Tabs -->
<div class="mb-0 flex border-b border-gray-700">
  <button class="tab-btn active" onclick="showTab('overview')">Overview</button>
  <button class="tab-btn" onclick="showTab('discovered')">Discovered IPs</button>
  <button class="tab-btn" onclick="showTab('activity')">Activity</button>
</div>

<!-- Overview tab -->
<div id="tab-overview" class="tab-panel active bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Discovery Funnel</h3>
      <div style="height:280px"><canvas id="chart-funnel"></canvas></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Subnet Breakdown</h3>
      <div style="height:280px"><canvas id="chart-subnets"></canvas></div>
    </div>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">DNS Performance</h3>
      <div id="dns-stats" class="grid grid-cols-2 gap-3 text-sm"></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Scan History</h3>
      <div style="height:200px"><canvas id="chart-history"></canvas></div>
    </div>
  </div>
</div>

<!-- Discovered IPs tab -->
<div id="tab-discovered" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="flex items-center justify-between mb-4">
    <h2 class="text-lg font-semibold text-white">Discovered IPs</h2>
    <div class="flex items-center gap-3">
      <select id="disc-filter" onchange="renderDiscovered()" class="bg-dark-700 text-sm border border-gray-600 rounded px-3 py-1.5 text-gray-300">
        <option value="all">All Status</option>
        <option value="pending">Pending</option>
        <option value="created">Created</option>
        <option value="unresolved">Unresolved</option>
        <option value="exists">Already Exists</option>
      </select>
      <input type="text" id="disc-search" placeholder="Search IP or hostname..." oninput="renderDiscovered()" class="bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-500 w-48">
    </div>
  </div>
  <div class="overflow-x-auto max-h-[500px] overflow-y-auto">
    <table class="w-full text-sm">
      <thead class="sticky top-0 bg-dark-800 z-10"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
        <th class="px-3 py-2">IP</th>
        <th class="px-3 py-2">Hostname</th>
        <th class="px-3 py-2">Subnet</th>
        <th class="px-3 py-2">Status</th>
        <th class="px-3 py-2">Labels</th>
        <th class="px-3 py-2">Direction</th>
        <th class="px-3 py-2">Services</th>
        <th class="px-3 py-2 text-right">Flows</th>
      </tr></thead>
      <tbody id="disc-table-body"></tbody>
    </table>
  </div>
  <div id="disc-footer" class="mt-3 text-xs text-gray-500"></div>
</div>

<!-- Activity tab -->
<div id="tab-activity" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <h2 class="text-lg font-semibold text-white mb-4">Recent Activity</h2>
  <div id="activity-feed" class="space-y-2 max-h-[500px] overflow-y-auto"></div>
</div>

<!-- Footer -->
<div id="footer" class="text-xs text-gray-600 text-center mt-4"></div>

</div>

<script>
const BASE = location.pathname.replace(/\/+$/, '');
const charts = {};
let lastData = null;

function showTab(name) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  event.target.classList.add('active');
}

function initCharts() {
  charts.funnel = new Chart(document.getElementById('chart-funnel'), {
    type: 'bar',
    data: {
      labels: ['Bare IPs', 'Internal', 'Resolved', 'Created', 'Labeled'],
      datasets: [{
        data: [0,0,0,0,0],
        backgroundColor: ['#89b4fa', '#cba6f7', '#a6e3a1', '#94e2d5', '#f5c2e7'],
        borderWidth: 0, borderRadius: 6
      }]
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#31324422' }, ticks: { color: '#6b7280' } },
        y: { grid: { display: false }, ticks: { color: '#cdd6f4', font: { size: 12 } } }
      }
    }
  });

  charts.subnets = new Chart(document.getElementById('chart-subnets'), {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: ['#89b4fa','#cba6f7','#a6e3a1','#f9e2af','#f38ba8','#94e2d5'], borderWidth: 0 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: '55%', plugins: { legend: { position: 'bottom', labels: { color: '#a6adc8', font: { size: 11 } } } } }
  });

  charts.history = new Chart(document.getElementById('chart-history'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'Bare IPs', data: [], borderColor: '#89b4fa', backgroundColor: '#89b4fa22', fill: true, tension: 0.3 },
        { label: 'Resolved', data: [], borderColor: '#a6e3a1', fill: false, tension: 0.3 },
        { label: 'Created', data: [], borderColor: '#94e2d5', fill: false, tension: 0.3 }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#9ca3af', usePointStyle: true, font: { size: 10 } } } },
      scales: {
        x: { grid: { color: '#31324422' }, ticks: { color: '#6b7280', maxTicksLimit: 8, font: { size: 10 } } },
        y: { grid: { color: '#31324422' }, ticks: { color: '#6b7280' }, beginAtZero: true }
      }
    }
  });
}

function statusBadge(status) {
  const colors = { created: 'green', pending: 'yellow', unresolved: 'red', exists: 'gray', failed: 'red' };
  const c = colors[status] || 'gray';
  return `<span class="px-2 py-0.5 rounded text-xs font-medium bg-${c}-900/50 text-${c}-400">${status}</span>`;
}

function labelsHtml(labels) {
  if (!labels || !Object.keys(labels).length) return '<span class="text-gray-600">—</span>';
  return Object.entries(labels).map(([k,v]) => `<span class="text-xs px-1.5 py-0.5 rounded bg-dark-700 text-gray-300">${k}:${v}</span>`).join(' ');
}

function renderAll(data) {
  lastData = data;
  const f = data.funnel || {};
  const dns = data.dns_stats || {};

  // Mode badge
  const modeEl = document.getElementById('mode-badge');
  if (data.mode === 'auto-create') {
    modeEl.textContent = 'AUTO-CREATE';
    modeEl.className = 'text-xs px-3 py-1 rounded-full font-medium bg-green-900/50 text-green-400 border border-green-700';
  } else {
    modeEl.textContent = 'DRY-RUN';
    modeEl.className = 'text-xs px-3 py-1 rounded-full font-medium bg-yellow-900/50 text-yellow-400 border border-yellow-700';
  }

  // Status
  const dot = document.getElementById('status-dot');
  const txt = document.getElementById('status-text');
  if (data.scanning) { dot.className = 'w-2.5 h-2.5 rounded-full bg-yellow-500 animate-pulse'; txt.textContent = 'Scanning...'; }
  else if (data.error) { dot.className = 'w-2.5 h-2.5 rounded-full bg-red-500'; txt.textContent = 'Error'; }
  else { dot.className = 'w-2.5 h-2.5 rounded-full bg-green-500'; txt.textContent = 'Active'; }

  // Stats
  document.getElementById('stat-bare').textContent = f.unique_bare_ips || 0;
  document.getElementById('stat-internal').textContent = f.internal || 0;
  document.getElementById('stat-resolved').textContent = f.resolved || 0;
  document.getElementById('stat-created').textContent = f.created || 0;
  const total = (f.resolved||0) + (f.unresolved||0);
  document.getElementById('stat-rate').textContent = total ? Math.round(f.resolved/total*100)+'%' : '—';
  document.getElementById('stat-labeled').textContent = f.labeled || 0;

  // Funnel chart
  charts.funnel.data.datasets[0].data = [f.unique_bare_ips||0, f.internal||0, f.resolved||0, f.created||0, f.labeled||0];
  charts.funnel.update('none');

  // Subnet chart
  const sb = data.subnet_breakdown || [];
  charts.subnets.data.labels = sb.map(s => s.subnet);
  charts.subnets.data.datasets[0].data = sb.map(s => s.ips);
  charts.subnets.update('none');

  // DNS stats
  document.getElementById('dns-stats').innerHTML = `
    <div class="bg-dark-700 rounded-lg p-3"><div class="text-lg font-bold text-white">${dns.total_queries||0}</div><div class="text-xs text-gray-500">Total Queries</div></div>
    <div class="bg-dark-700 rounded-lg p-3"><div class="text-lg font-bold text-green-400">${dns.successful||0}</div><div class="text-xs text-gray-500">Successful</div></div>
    <div class="bg-dark-700 rounded-lg p-3"><div class="text-lg font-bold text-red-400">${dns.failed||0}</div><div class="text-xs text-gray-500">Failed</div></div>
    <div class="bg-dark-700 rounded-lg p-3"><div class="text-lg font-bold text-yellow-400">${dns.timeout||0}</div><div class="text-xs text-gray-500">Timeouts</div></div>
    <div class="bg-dark-700 rounded-lg p-3"><div class="text-lg font-bold text-blue-400">${(dns.avg_latency_ms||0).toFixed(0)}ms</div><div class="text-xs text-gray-500">Avg Latency</div></div>
    <div class="bg-dark-700 rounded-lg p-3"><div class="text-lg font-bold text-purple-400">${dns.cache_hits||0}</div><div class="text-xs text-gray-500">Cache Hits</div></div>
  `;

  // History chart
  const hist = (data.cumulative||{}).scan_history || [];
  charts.history.data.labels = hist.map(h => new Date(h.timestamp).toLocaleTimeString());
  charts.history.data.datasets[0].data = hist.map(h => h.bare_ips);
  charts.history.data.datasets[1].data = hist.map(h => h.resolved);
  charts.history.data.datasets[2].data = hist.map(h => h.created);
  charts.history.update('none');

  renderDiscovered();
  renderActivity();

  // Footer
  const cum = data.cumulative || {};
  document.getElementById('footer').textContent = `Scan #${data.scan_count||0} · ${data.last_scan ? new Date(data.last_scan).toLocaleTimeString() : 'never'} · ${cum.total_ips_discovered||0} total IPs discovered · ${cum.total_workloads_created||0} workloads created`;
}

function renderDiscovered() {
  if (!lastData) return;
  const filter = document.getElementById('disc-filter').value;
  const search = document.getElementById('disc-search').value.toLowerCase();
  let items = lastData.discovered || [];
  if (filter !== 'all') items = items.filter(d => d.status === filter);
  if (search) items = items.filter(d => d.ip.includes(search) || (d.hostname||'').toLowerCase().includes(search));

  document.getElementById('disc-table-body').innerHTML = items.slice(0, 200).map(d => `
    <tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
      <td class="px-3 py-2 font-mono text-xs text-gray-300">${d.ip}</td>
      <td class="px-3 py-2 text-xs">${d.hostname ? `<code class="text-blue-400">${d.hostname}</code>` : '<span class="text-gray-600">—</span>'}</td>
      <td class="px-3 py-2 text-xs text-gray-400">${d.subnet||'—'}</td>
      <td class="px-3 py-2">${statusBadge(d.status)}</td>
      <td class="px-3 py-2">${labelsHtml(d.labels)}</td>
      <td class="px-3 py-2 text-xs text-gray-400">${(d.directions||[]).join(', ')}</td>
      <td class="px-3 py-2 text-xs text-gray-500">${(d.services||[]).join(', ')||'—'}</td>
      <td class="px-3 py-2 text-right font-mono text-xs text-gray-400">${(d.flow_count||0).toLocaleString()}</td>
    </tr>
  `).join('');
  document.getElementById('disc-footer').textContent = `Showing ${Math.min(items.length, 200)} of ${items.length} discovered IPs`;
}

function renderActivity() {
  if (!lastData) return;
  const items = lastData.activity || [];
  const icons = { created: '&#x2705;', pending: '&#x23F3;', failed: '&#x274C;', resolved: '&#x1F50D;', skipped: '&#x23ED;' };
  document.getElementById('activity-feed').innerHTML = items.map(a => `
    <div class="flex items-start gap-3 px-3 py-2 rounded-lg bg-dark-900 border border-gray-700/30">
      <span class="text-sm mt-0.5">${icons[a.action]||'&#x2139;'}</span>
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2 text-xs">
          <span class="text-gray-500">${new Date(a.timestamp).toLocaleTimeString()}</span>
          ${statusBadge(a.action)}
          <code class="text-gray-400">${a.ip}</code>
          ${a.hostname ? `<span class="text-blue-400">${a.hostname}</span>` : ''}
        </div>
        <div class="text-xs text-gray-500 mt-0.5 truncate">${a.detail||''}</div>
      </div>
    </div>
  `).join('');
}

async function triggerScan() {
  try {
    document.getElementById('status-dot').className = 'w-2.5 h-2.5 rounded-full bg-yellow-500 animate-pulse';
    document.getElementById('status-text').textContent = 'Scan triggered...';
    await fetch(BASE+'/api/scan', {method:'POST'});
  } catch(e) { console.error(e); }
}

async function fetchData() {
  try {
    const resp = await fetch(BASE+'/api/state');
    const data = await resp.json();
    renderAll(data);
  } catch(e) { console.error('Fetch failed:', e); }
}

initCharts();
fetchData();
setInterval(fetchData, 15000);
</script>
</body></html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class DiscoveryHandler(BaseHTTPRequestHandler):
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
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path == "/":
            self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
        elif path == "/healthz":
            with state_lock:
                healthy = discovery_state["error"] is None
            self._send(200, json.dumps({"status": "healthy" if healthy else "degraded"}))
        elif path == "/api/state":
            with state_lock:
                data = json.loads(json.dumps(discovery_state, default=str))
            self._send(200, json.dumps(data, default=str))
        elif path == "/api/export/json":
            with state_lock:
                data = json.loads(json.dumps(discovery_state, default=str))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=network-discovery-export.json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2, default=str).encode())
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if path == "/api/scan":
            with state_lock:
                if discovery_state["scanning"]:
                    self._send(409, json.dumps({"error": "Scan already in progress"}))
                    return
            threading.Thread(target=lambda: (scan_traffic(pce_client), save_state()), daemon=True).start()
            self._send(200, json.dumps({"status": "scan_triggered"}))
        elif path == "/api/create":
            if MODE != "auto-create":
                self._send(400, json.dumps({"error": "Plugin is in dry-run mode. Set MODE=auto-create to create workloads."}))
                return
            try:
                req = json.loads(body)
            except Exception:
                self._send(400, json.dumps({"error": "Invalid JSON"}))
                return
            ip = req.get("ip", "")
            if not ip:
                self._send(400, json.dumps({"error": "ip is required"}))
                return
            hostname = dns_cache.get(ip, (None,))[0]
            if not hostname:
                hostname, _, _, _ = resolve_dns(ip)
            if not hostname:
                self._send(400, json.dumps({"error": f"Cannot resolve {ip}"}))
                return
            labels_dict = infer_labels(hostname)
            label_hrefs = []
            for key, value in labels_dict.items():
                href = ensure_label(pce_client, key, value)
                if href:
                    label_hrefs.append({"href": href})
            body_wl = {
                "name": hostname,
                "hostname": hostname,
                "interfaces": [{"address": ip, "friendly_name": "eth0"}],
                "service_provider": "plugger-network-discovery",
                "description": "Discovered from traffic flows by plugger network-discovery",
            }
            if label_hrefs:
                body_wl["labels"] = label_hrefs
            try:
                resp = pce_client.post("/workloads", json=body_wl)
                if resp.status_code in (200, 201):
                    created_workload_ips.add(ip)
                    save_state()
                    self._send(200, json.dumps({"status": "created", "hostname": hostname, "labels": labels_dict}))
                else:
                    self._send(resp.status_code, json.dumps({"error": f"PCE returned {resp.status_code}"}))
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def log_message(self, fmt, *args):
        pass


# ---------------------------------------------------------------------------
# Poller
# ---------------------------------------------------------------------------

def poller_loop(pce):
    while True:
        time.sleep(POLL_INTERVAL)
        scan_traffic(pce)
        save_state()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global pce_client
    log.info("Starting network-discovery...")
    log.info("Config: mode=%s, subnets=%s, dns=%s, poll=%ds, lookback=%dh",
             MODE, INTERNAL_SUBNETS_STR, DNS_SERVER or "system", POLL_INTERVAL, LOOKBACK_HOURS)
    if LABEL_RULES:
        log.info("Label rules: %d patterns loaded", len(LABEL_RULES))

    load_state()
    pce_client = get_pce()
    log.info("Connected to PCE: %s", pce_client.base_url)

    # Initial scan
    scan_traffic(pce_client)
    save_state()

    # Background poller
    threading.Thread(target=poller_loop, args=(pce_client,), daemon=True).start()

    # HTTP server
    server = HTTPServer(("0.0.0.0", HTTP_PORT), DiscoveryHandler)
    log.info("Dashboard on http://0.0.0.0:%d", HTTP_PORT)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        save_state()
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
