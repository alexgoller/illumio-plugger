#!/usr/bin/env python3
"""
Remedy CMDB Sync — Sync BMC Helix/Remedy CMDB CIs to Illumio labels.

Connects to a Remedy CMDB via REST API, discovers configuration items
(BMC_ComputerSystem by default), maps CI attributes to Illumio labels
using configurable rules, and optionally syncs labels to PCE workloads.

Two modes:
  - analytics (default): Read-only discovery and feasibility analysis
  - sync: Apply discovered labels to matching PCE workloads

NOTE: This plugin is UNTESTED against a live Remedy instance.
      The API integration follows BMC Helix CMDB REST API documentation.
      Please report issues at https://github.com/alexgoller/illumio-plugger/issues
"""

import json
import logging
import os
import re
import signal
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import requests

from illumio import PolicyComputeEngine

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("remedy-cmdb-sync")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REMEDY_HOST = os.environ.get("REMEDY_HOST", "")
REMEDY_PORT = os.environ.get("REMEDY_PORT", "8443")
REMEDY_USER = os.environ.get("REMEDY_USER", "")
REMEDY_PASSWORD = os.environ.get("REMEDY_PASSWORD", "")
REMEDY_TLS_VERIFY = os.environ.get("REMEDY_TLS_SKIP_VERIFY", "true").lower() != "true"
REMEDY_CI_CLASS = os.environ.get("REMEDY_CI_CLASS", "BMC_ComputerSystem")
REMEDY_NAMESPACE = os.environ.get("REMEDY_NAMESPACE", "BMC.CORE")
REMEDY_DATASET = os.environ.get("REMEDY_DATASET", "BMC.ASSET")
REMEDY_QUALIFICATION = os.environ.get("REMEDY_QUALIFICATION", "")

MODE = os.environ.get("MODE", "analytics").lower()
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "3600"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

# ---------------------------------------------------------------------------
# Default mapping rules
# ---------------------------------------------------------------------------
DEFAULT_RULES = [
    # Environment from CMDB Environment field
    {"source": "Environment", "pattern": r"(?i)\bprod(uction)?\b", "target": "env", "value": "prod", "priority": 10},
    {"source": "Environment", "pattern": r"(?i)\bdev(elopment)?\b", "target": "env", "value": "dev", "priority": 10},
    {"source": "Environment", "pattern": r"(?i)\btest(ing)?\b", "target": "env", "value": "test", "priority": 10},
    {"source": "Environment", "pattern": r"(?i)\bstag(e|ing)\b", "target": "env", "value": "staging", "priority": 10},
    {"source": "Environment", "pattern": r"(?i)\bqa\b", "target": "env", "value": "qa", "priority": 10},
    {"source": "Environment", "pattern": r"(?i)\buat\b", "target": "env", "value": "uat", "priority": 10},
    # App from BusinessService / Category
    {"source": "BusinessService", "pattern": r".+", "target": "app", "value": "$0", "priority": 10},
    {"source": "Category", "pattern": r".+", "target": "app", "value": "$0", "priority": 5},
    # Location from Site/Location field
    {"source": "Site", "pattern": r".+", "target": "loc", "value": "$0", "priority": 10},
    {"source": "Location", "pattern": r".+", "target": "loc", "value": "$0", "priority": 5},
    # Role from CI type/category patterns
    {"source": "ShortDescription", "pattern": r"(?i)\b(web|http|apache|nginx|iis)\b", "target": "role", "value": "web", "priority": 5},
    {"source": "ShortDescription", "pattern": r"(?i)\b(db|database|sql|oracle|postgres|mysql|mongo)\b", "target": "role", "value": "db", "priority": 5},
    {"source": "ShortDescription", "pattern": r"(?i)\b(app|application|tomcat|jboss|weblogic)\b", "target": "role", "value": "app", "priority": 5},
    {"source": "ShortDescription", "pattern": r"(?i)\b(dns|domain\s*name)\b", "target": "role", "value": "dns", "priority": 5},
    {"source": "ShortDescription", "pattern": r"(?i)\b(mail|smtp|exchange)\b", "target": "role", "value": "mail", "priority": 5},
    {"source": "ShortDescription", "pattern": r"(?i)\b(file|filer|nas|nfs|cifs)\b", "target": "role", "value": "filer", "priority": 5},
    {"source": "ShortDescription", "pattern": r"(?i)\b(dc|domain\s*controller|active\s*directory)\b", "target": "role", "value": "dc", "priority": 5},
    {"source": "ShortDescription", "pattern": r"(?i)\b(jump|bastion|gateway)\b", "target": "role", "value": "jumpbox", "priority": 5},
    {"source": "ShortDescription", "pattern": r"(?i)\b(monitor|nagios|zabbix|splunk|siem)\b", "target": "role", "value": "monitoring", "priority": 5},
    # Role from HostName patterns (lower priority fallback)
    {"source": "HostName", "pattern": r"(?i)^(web|www|http)", "target": "role", "value": "web", "priority": 3},
    {"source": "HostName", "pattern": r"(?i)^(db|sql|ora)", "target": "role", "value": "db", "priority": 3},
    {"source": "HostName", "pattern": r"(?i)^(app|srv)", "target": "role", "value": "app", "priority": 3},
]

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
report_state = {
    "last_scan": None,
    "scan_count": 0,
    "scanning": False,
    "error": None,
    "scan_requested": False,
    "mode": MODE,
    "remedy_status": "unknown",
    "cis": [],
    "summary": {},
    "label_coverage": {},
    "mapping_rules": [],
    "match_results": [],
    "sync_results": [],
}

label_cache = {}  # href -> {key, value}

# ---------------------------------------------------------------------------
# Remedy CMDB REST API client
# ---------------------------------------------------------------------------

class RemedyClient:
    """BMC Helix/Remedy CMDB REST API client with JWT auth."""

    def __init__(self, host, port, user, password, verify_tls=False):
        self.base_url = f"https://{host}:{port}"
        self.user = user
        self.password = password
        self.verify = verify_tls
        self.token = None
        self.session = requests.Session()
        self.session.verify = verify_tls

    def login(self):
        """Authenticate and obtain JWT token."""
        url = f"{self.base_url}/api/jwt/login"
        try:
            resp = self.session.post(url, data={"username": self.user, "password": self.password})
            resp.raise_for_status()
            self.token = resp.text.strip()
            self.session.headers["Authorization"] = f"AR-JWT {self.token}"
            log.info("Remedy login successful")
            return True
        except requests.RequestException as e:
            log.error("Remedy login failed: %s", e)
            return False

    def logout(self):
        """Release JWT token."""
        if not self.token:
            return
        try:
            url = f"{self.base_url}/api/jwt/logout"
            self.session.post(url)
        except Exception:
            pass
        self.token = None

    def query_cis(self, dataset, namespace, class_name, qualification="", limit=500):
        """Query CMDB configuration items with pagination."""
        all_cis = []
        offset = 0
        attrs = [
            "Name", "HostName", "IpAddress", "OperatingSystem",
            "ShortDescription", "Category", "Status",
            "Environment", "BusinessService", "Site", "Location",
            "Owner", "ManagedBy", "Domain",
            "SerialNumber", "Manufacturer", "Model",
        ]

        while True:
            url = f"{self.base_url}/api/cmdb/v1.0/instances/{dataset}/{namespace}/{class_name}"
            params = {
                "offset": offset,
                "limit": limit,
                "attributes": ",".join(attrs),
                "dataset_mask": "0",
                "num_matches": "true",
            }
            if qualification:
                params["qualification"] = qualification

            try:
                resp = self.session.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                log.error("CMDB query failed at offset %d: %s", offset, e)
                break
            except json.JSONDecodeError as e:
                log.error("CMDB response parse error: %s", e)
                break

            instances = data.get("instances", [])
            for inst in instances:
                ci = inst.get("attributes", {})
                ci["_instance_id"] = inst.get("instance_id", "")
                ci["_class"] = class_name
                all_cis.append(ci)

            total = data.get("total_count", len(all_cis))
            offset += len(instances)
            log.info("Fetched %d/%d CIs", offset, total)

            if not instances or offset >= total:
                break

        return all_cis


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
            cache[href] = {"key": lbl.get("key", ""), "value": lbl.get("value", "")}
        label_cache = cache
        return labels
    except Exception as e:
        log.error("Failed to fetch labels: %s", e)
        return []


def fetch_workloads(pce):
    try:
        resp = pce.get("/workloads", params={"max_results": 10000})
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        log.error("Failed to fetch workloads: %s", e)
    return []


# ---------------------------------------------------------------------------
# Mapping engine
# ---------------------------------------------------------------------------

def load_mapping_rules():
    custom = os.environ.get("MAPPING_RULES", "").strip()
    if custom:
        try:
            rules = json.loads(custom)
            log.info("Loaded %d custom mapping rules", len(rules))
            return rules
        except json.JSONDecodeError as e:
            log.error("Invalid MAPPING_RULES JSON: %s", e)
    return DEFAULT_RULES


def apply_rules(ci, rules):
    """Apply mapping rules to a CI and return derived labels."""
    labels = {}  # target -> {value, source, priority, pattern}

    for rule in sorted(rules, key=lambda r: -r.get("priority", 0)):
        source_field = rule.get("source", "")
        pattern = rule.get("pattern", "")
        target = rule.get("target", "")
        value_template = rule.get("value", "$0")
        priority = rule.get("priority", 0)

        if not source_field or not pattern or not target:
            continue

        source_value = ci.get(source_field, "") or ""
        if not source_value:
            continue

        match = re.search(pattern, source_value)
        if not match:
            continue

        # Check priority — only override if higher
        existing = labels.get(target)
        if existing and existing["priority"] >= priority:
            continue

        # Resolve value template
        if value_template == "$0":
            resolved = match.group(0)
        elif value_template.startswith("$"):
            try:
                group = int(value_template[1:])
                resolved = match.group(group)
            except (IndexError, ValueError):
                resolved = match.group(0)
        else:
            resolved = value_template

        # Normalize label value (lowercase, strip, replace spaces)
        resolved = resolved.strip().lower().replace(" ", "-")
        if resolved:
            labels[target] = {
                "value": resolved,
                "source": source_field,
                "pattern": pattern,
                "priority": priority,
            }

    return labels


# ---------------------------------------------------------------------------
# Analysis and sync
# ---------------------------------------------------------------------------

def process_cis(cis, rules, workloads):
    """Apply rules to CIs and build analytics/match results."""
    label_coverage = defaultdict(lambda: {"total": 0, "mapped": 0, "values": Counter()})
    results = []
    required_keys = ["app", "env", "role", "loc"]

    # Build workload lookup by hostname (lowercase)
    wl_by_hostname = {}
    for wl in workloads:
        hn = (wl.get("hostname") or "").lower()
        if hn:
            wl_by_hostname[hn] = wl
        # Also index by IP
        for iface in wl.get("interfaces", []):
            ip = iface.get("address", "")
            if ip:
                wl_by_hostname[ip] = wl

    for ci in cis:
        hostname = (ci.get("HostName") or ci.get("Name") or "(unknown)").strip()
        ip = (ci.get("IpAddress") or "").strip()
        os_info = ci.get("OperatingSystem", "") or ""
        status = ci.get("Status", "") or ""
        desc = ci.get("ShortDescription", "") or ""

        derived_labels = apply_rules(ci, rules)

        # Track coverage
        for key in required_keys:
            label_coverage[key]["total"] += 1
            if key in derived_labels:
                label_coverage[key]["mapped"] += 1
                label_coverage[key]["values"][derived_labels[key]["value"]] += 1

        # Match to PCE workload
        match_key = hostname.lower()
        matched_wl = wl_by_hostname.get(match_key)
        if not matched_wl and ip:
            matched_wl = wl_by_hostname.get(ip)

        # Get existing PCE labels
        existing_labels = {}
        if matched_wl:
            for lbl in matched_wl.get("labels", []):
                href = lbl.get("href", "")
                resolved = label_cache.get(href, {})
                if resolved:
                    existing_labels[resolved["key"]] = resolved["value"]

        result = {
            "hostname": hostname,
            "ip": ip,
            "os": os_info,
            "status": status,
            "description": desc,
            "cmdb_fields": {
                "Environment": ci.get("Environment", ""),
                "BusinessService": ci.get("BusinessService", ""),
                "Category": ci.get("Category", ""),
                "Site": ci.get("Site", ""),
                "Location": ci.get("Location", ""),
                "Owner": ci.get("Owner", ""),
            },
            "derived_labels": {k: v["value"] for k, v in derived_labels.items()},
            "label_details": derived_labels,
            "pce_matched": matched_wl is not None,
            "pce_hostname": matched_wl.get("hostname", "") if matched_wl else "",
            "pce_href": matched_wl.get("href", "") if matched_wl else "",
            "existing_labels": existing_labels,
            "changes_needed": {},
        }

        # Determine what would change
        for key, val in result["derived_labels"].items():
            existing = existing_labels.get(key, "")
            if existing != val:
                result["changes_needed"][key] = {"from": existing or "(none)", "to": val}

        results.append(result)

    fully_mapped = sum(1 for r in results if all(k in r["derived_labels"] for k in required_keys))
    pce_matched = sum(1 for r in results if r["pce_matched"])
    changes_needed = sum(1 for r in results if r["changes_needed"])

    summary = {
        "total_cis": len(cis),
        "fully_mapped": fully_mapped,
        "fully_mapped_pct": round(fully_mapped / max(len(cis), 1) * 100, 1),
        "pce_matched": pce_matched,
        "pce_matched_pct": round(pce_matched / max(len(cis), 1) * 100, 1),
        "changes_needed": changes_needed,
        "label_coverage": {
            k: {"total": v["total"], "mapped": v["mapped"],
                "pct": round(v["mapped"] / max(v["total"], 1) * 100, 1),
                "top_values": dict(v["values"].most_common(10))}
            for k, v in label_coverage.items()
        },
    }

    return results, summary


def sync_labels(pce, results):
    """Apply derived labels to PCE workloads (sync mode only)."""
    sync_results = []
    all_labels = fetch_labels(pce)

    # Build label href lookup
    label_href_map = {}  # (key, value) -> href
    for lbl in all_labels:
        label_href_map[(lbl.get("key", ""), lbl.get("value", ""))] = lbl.get("href", "")

    for result in results:
        if not result["pce_matched"] or not result["changes_needed"]:
            continue

        wl_href = result["pce_href"]
        hostname = result["hostname"]

        try:
            # Fetch current workload
            resp = pce.get(wl_href)
            if resp.status_code != 200:
                sync_results.append({"hostname": hostname, "status": "error", "error": f"GET {resp.status_code}"})
                continue

            wl = resp.json()
            current_labels = list(wl.get("labels", []))

            for key, change in result["changes_needed"].items():
                new_value = change["to"]
                target_href = label_href_map.get((key, new_value))

                # Create label if it doesn't exist
                if not target_href:
                    try:
                        create_resp = pce.post("/labels", json={"key": key, "value": new_value})
                        if create_resp.status_code in (200, 201):
                            created = create_resp.json()
                            target_href = created.get("href", "")
                            label_href_map[(key, new_value)] = target_href
                        else:
                            sync_results.append({"hostname": hostname, "status": "error",
                                                 "error": f"Create label {key}={new_value}: {create_resp.status_code}"})
                            continue
                    except Exception as e:
                        sync_results.append({"hostname": hostname, "status": "error", "error": str(e)})
                        continue

                # Remove existing label with same key
                current_labels = [l for l in current_labels
                                  if label_cache.get(l.get("href", ""), {}).get("key") != key]

                # Add new label
                current_labels.append({"href": target_href})

            # Update workload
            clean_labels = [{"href": l["href"]} for l in current_labels]
            put_resp = pce.put(wl_href, json={"labels": clean_labels})
            if put_resp.status_code in (200, 204):
                sync_results.append({
                    "hostname": hostname,
                    "status": "synced",
                    "changes": result["changes_needed"],
                })
            else:
                sync_results.append({
                    "hostname": hostname,
                    "status": "error",
                    "error": f"PUT {put_resp.status_code}",
                })

        except Exception as e:
            log.error("Sync failed for %s: %s", hostname, e)
            sync_results.append({"hostname": hostname, "status": "error", "error": str(e)})

    return sync_results


# ---------------------------------------------------------------------------
# Scan orchestrator
# ---------------------------------------------------------------------------

def run_scan(pce, remedy):
    """Run a full CMDB scan and analysis."""
    rules = load_mapping_rules()

    # Connect to Remedy
    log.info("Connecting to Remedy CMDB at %s...", REMEDY_HOST)
    if not remedy.login():
        raise RuntimeError("Remedy login failed")

    try:
        # Query CIs
        log.info("Querying %s CIs...", REMEDY_CI_CLASS)
        cis = remedy.query_cis(REMEDY_DATASET, REMEDY_NAMESPACE, REMEDY_CI_CLASS, REMEDY_QUALIFICATION)
        log.info("Fetched %d CIs from CMDB", len(cis))

        # Fetch PCE workloads + labels
        fetch_labels(pce)
        workloads = fetch_workloads(pce)
        log.info("Fetched %d PCE workloads", len(workloads))

        # Process
        results, summary = process_cis(cis, rules, workloads)

        # Sync if enabled
        sync_results = []
        if MODE == "sync":
            log.info("Sync mode: applying labels to PCE...")
            sync_results = sync_labels(pce, results)
            synced = sum(1 for r in sync_results if r["status"] == "synced")
            errors = sum(1 for r in sync_results if r["status"] == "error")
            log.info("Sync complete: %d synced, %d errors", synced, errors)

        with state_lock:
            report_state["last_scan"] = datetime.now(timezone.utc).isoformat()
            report_state["scan_count"] += 1
            report_state["remedy_status"] = "connected"
            report_state["cis"] = results
            report_state["summary"] = summary
            report_state["mapping_rules"] = rules
            report_state["match_results"] = [r for r in results if r["pce_matched"]]
            report_state["sync_results"] = sync_results
            report_state["error"] = None

    finally:
        remedy.logout()


# ---------------------------------------------------------------------------
# Background poller
# ---------------------------------------------------------------------------

def poller_loop(pce, remedy):
    while True:
        do_scan = False
        with state_lock:
            if report_state["scan_requested"]:
                report_state["scan_requested"] = False
                do_scan = True

        if do_scan or report_state["last_scan"] is None:
            pass
        else:
            time.sleep(30)
            try:
                last = datetime.fromisoformat(report_state["last_scan"].replace("Z", "+00:00"))
                elapsed = (datetime.now(timezone.utc) - last).total_seconds()
                if elapsed < SCAN_INTERVAL:
                    continue
            except (ValueError, TypeError, AttributeError):
                pass

        try:
            with state_lock:
                report_state["scanning"] = True
                report_state["error"] = None

            run_scan(pce, remedy)

            with state_lock:
                report_state["scanning"] = False

            log.info("Scan complete. %d CIs, %d matched to PCE",
                     report_state["summary"].get("total_cis", 0),
                     report_state["summary"].get("pce_matched", 0))

        except Exception as e:
            log.error("Scan failed: %s", e, exc_info=True)
            with state_lock:
                report_state["scanning"] = False
                report_state["error"] = str(e)
                report_state["remedy_status"] = "error"

        time.sleep(60)


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Remedy CMDB Sync</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>
tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}
</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#11111b}::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.tab-btn{cursor:pointer;padding:0.5rem 1rem;font-size:0.875rem;border-bottom:2px solid transparent;color:#a6adc8;transition:all 0.15s}
.tab-btn:hover{color:#cdd6f4}.tab-btn.active{color:#89b4fa;border-color:#89b4fa}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}.scanning{animation:pulse 2s infinite}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-6">

<!-- Header -->
<div class="flex items-center justify-between mb-8">
  <div>
    <h1 class="text-2xl font-bold text-white flex items-center gap-2">
      <svg class="w-6 h-6 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/></svg>
      Remedy CMDB Sync
    </h1>
    <div class="flex items-center gap-2 mt-1">
      <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
      <span id="status-text" class="text-sm text-gray-400">Loading...</span>
    </div>
  </div>
  <div class="flex items-center gap-3">
    <span id="mode-badge" class="text-xs px-3 py-1 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30 font-medium">analytics</span>
    <button onclick="triggerScan()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Scan Now</button>
  </div>
</div>

<!-- Banner: untested -->
<div class="bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-3 mb-6 text-sm text-amber-300">
  <strong>Note:</strong> This plugin has not been tested against a live Remedy instance. Please verify API connectivity and report issues.
</div>

<!-- Stats -->
<div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8" id="stats">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-cis" class="text-3xl font-bold text-blue-400">—</div>
    <div class="text-sm text-gray-400 mt-1">CMDB CIs</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-matched" class="text-3xl font-bold text-green-400">—</div>
    <div class="text-sm text-gray-400 mt-1">PCE Matched</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-mapped" class="text-3xl font-bold text-purple-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Fully Mapped</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-changes" class="text-3xl font-bold text-yellow-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Changes Needed</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-synced" class="text-3xl font-bold text-cyan-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Synced</div>
  </div>
</div>

<!-- Tabs -->
<div class="flex gap-1 border-b border-gray-700 mb-6">
  <button class="tab-btn active" onclick="showTab('coverage')">Coverage</button>
  <button class="tab-btn" onclick="showTab('cis')">CIs</button>
  <button class="tab-btn" onclick="showTab('matches')">Matches</button>
  <button class="tab-btn" onclick="showTab('rules')">Rules</button>
  <button class="tab-btn" onclick="showTab('sync')">Sync Log</button>
</div>

<!-- Tab: Coverage -->
<div id="tab-coverage" class="tab-content">
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-300 mb-3">Label Coverage</h3>
      <div style="height:280px"><canvas id="chart-coverage"></canvas></div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-300 mb-3">Top Values</h3>
      <div id="top-values" class="space-y-4 max-h-[280px] overflow-y-auto"></div>
    </div>
  </div>
</div>

<!-- Tab: CIs -->
<div id="tab-cis" class="tab-content hidden">
  <div class="bg-dark-800 rounded-xl border border-gray-700">
    <div class="p-4 border-b border-gray-700 flex items-center gap-3">
      <input id="ci-search" type="text" placeholder="Search CIs..." oninput="renderCIs()"
             class="bg-dark-900 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-300 w-64">
      <span id="ci-count" class="text-xs text-gray-500"></span>
    </div>
    <div class="max-h-[500px] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-dark-800">
          <tr class="text-left text-xs text-gray-400 uppercase">
            <th class="px-4 py-3">Hostname</th>
            <th class="px-4 py-3">IP</th>
            <th class="px-4 py-3">OS</th>
            <th class="px-4 py-3">Labels</th>
            <th class="px-4 py-3">PCE</th>
          </tr>
        </thead>
        <tbody id="ci-table"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Tab: Matches -->
<div id="tab-matches" class="tab-content hidden">
  <div class="bg-dark-800 rounded-xl border border-gray-700">
    <div class="max-h-[500px] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-dark-800">
          <tr class="text-left text-xs text-gray-400 uppercase">
            <th class="px-4 py-3">CMDB Hostname</th>
            <th class="px-4 py-3">PCE Hostname</th>
            <th class="px-4 py-3">Derived Labels</th>
            <th class="px-4 py-3">Changes</th>
          </tr>
        </thead>
        <tbody id="match-table"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Tab: Rules -->
<div id="tab-rules" class="tab-content hidden">
  <div class="bg-dark-800 rounded-xl border border-gray-700">
    <div class="max-h-[500px] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-dark-800">
          <tr class="text-left text-xs text-gray-400 uppercase">
            <th class="px-4 py-3">Source</th>
            <th class="px-4 py-3">Pattern</th>
            <th class="px-4 py-3">Target</th>
            <th class="px-4 py-3">Value</th>
            <th class="px-4 py-3">Priority</th>
          </tr>
        </thead>
        <tbody id="rules-table"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Tab: Sync -->
<div id="tab-sync" class="tab-content hidden">
  <div class="bg-dark-800 rounded-xl border border-gray-700">
    <div class="max-h-[500px] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-dark-800">
          <tr class="text-left text-xs text-gray-400 uppercase">
            <th class="px-4 py-3">Hostname</th>
            <th class="px-4 py-3">Status</th>
            <th class="px-4 py-3">Details</th>
          </tr>
        </thead>
        <tbody id="sync-table"></tbody>
      </table>
    </div>
  </div>
</div>

</div>

<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\\/plugins\\/[^/]+\\/ui/);return m?m[0]:''})();
let data=null;let chartCoverage=null;

function showTab(id){
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+id).classList.remove('hidden');
  event.target.classList.add('active');
}

function formatNum(n){if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toLocaleString()}
function timeAgo(ts){if(!ts)return'—';const d=(Date.now()-new Date(ts).getTime())/1000;if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago'}

function update(d){
  data=d;
  // Status
  const dot=document.getElementById('status-dot');
  const txt=document.getElementById('status-text');
  if(d.scanning){dot.className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning';txt.textContent='Scanning...';}
  else if(d.error){dot.className='w-2.5 h-2.5 rounded-full bg-red-500';txt.textContent='Error: '+d.error;}
  else if(d.last_scan){dot.className='w-2.5 h-2.5 rounded-full bg-green-500';txt.textContent=`Remedy: ${d.remedy_status} | Last scan: ${timeAgo(d.last_scan)} | ${d.scan_count} scans`;}
  else{dot.className='w-2.5 h-2.5 rounded-full bg-gray-500';txt.textContent='Not scanned yet';}

  document.getElementById('mode-badge').textContent=d.mode;
  const s=d.summary||{};
  document.getElementById('stat-cis').textContent=formatNum(s.total_cis||0);
  document.getElementById('stat-matched').textContent=formatNum(s.pce_matched||0);
  document.getElementById('stat-mapped').textContent=s.fully_mapped_pct?s.fully_mapped_pct+'%':'—';
  document.getElementById('stat-changes').textContent=formatNum(s.changes_needed||0);
  const synced=d.sync_results?d.sync_results.filter(r=>r.status==='synced').length:0;
  document.getElementById('stat-synced').textContent=d.mode==='sync'?formatNum(synced):'—';

  renderCoverage(s.label_coverage||{});
  renderCIs();
  renderMatches();
  renderRules(d.mapping_rules||[]);
  renderSyncLog(d.sync_results||[]);
}

function renderCoverage(lc){
  const keys=['app','env','role','loc'];
  const pcts=keys.map(k=>lc[k]?lc[k].pct:0);
  const colors=['#93c5fd','#a78bfa','#f9a8d4','#fbbf24'];

  const ctx=document.getElementById('chart-coverage').getContext('2d');
  if(chartCoverage)chartCoverage.destroy();
  chartCoverage=new Chart(ctx,{type:'bar',data:{labels:keys.map(k=>k.charAt(0).toUpperCase()+k.slice(1)),datasets:[{label:'Coverage %',data:pcts,backgroundColor:colors,borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#a6adc8'},grid:{display:false}},y:{max:100,ticks:{color:'#6c7086',callback:v=>v+'%'},grid:{color:'rgba(69,71,90,0.3)'}}}}});

  let html='';
  for(const key of keys){
    const cov=lc[key];
    if(!cov)continue;
    const vals=cov.top_values||{};
    html+=`<div><div class="text-xs font-semibold text-gray-300 mb-1">${key} (${cov.mapped}/${cov.total})</div>`;
    html+=Object.entries(vals).slice(0,5).map(([v,c])=>`<span class="inline-block text-xs bg-dark-700 text-gray-300 rounded px-2 py-0.5 mr-1 mb-1">${v} (${c})</span>`).join('');
    html+='</div>';
  }
  document.getElementById('top-values').innerHTML=html;
}

function renderCIs(){
  if(!data)return;
  const q=(document.getElementById('ci-search').value||'').toLowerCase();
  const cis=data.cis||[];
  const filtered=q?cis.filter(c=>(c.hostname+c.ip+c.os+c.description).toLowerCase().includes(q)):cis;
  document.getElementById('ci-count').textContent=filtered.length+' of '+cis.length+' CIs';

  document.getElementById('ci-table').innerHTML=filtered.slice(0,200).map(ci=>{
    const labels=Object.entries(ci.derived_labels||{}).map(([k,v])=>`<span class="inline-block text-xs bg-blue-500/15 text-blue-300 rounded px-1.5 py-0.5 mr-1">${k}:${v}</span>`).join('')||'<span class="text-gray-600">—</span>';
    const pce=ci.pce_matched?'<span class="text-green-400 text-xs">&#10003; '+ci.pce_hostname+'</span>':'<span class="text-gray-600 text-xs">—</span>';
    return`<tr class="border-b border-gray-700/50 hover:bg-dark-900"><td class="px-4 py-2.5 text-gray-300">${ci.hostname}</td><td class="px-4 py-2.5 text-gray-400">${ci.ip}</td><td class="px-4 py-2.5 text-gray-400 text-xs">${ci.os||'—'}</td><td class="px-4 py-2.5">${labels}</td><td class="px-4 py-2.5">${pce}</td></tr>`;
  }).join('');
}

function renderMatches(){
  if(!data)return;
  const matches=data.match_results||[];
  document.getElementById('match-table').innerHTML=matches.map(m=>{
    const labels=Object.entries(m.derived_labels||{}).map(([k,v])=>`<span class="inline-block text-xs bg-blue-500/15 text-blue-300 rounded px-1.5 py-0.5 mr-1">${k}:${v}</span>`).join('');
    const changes=Object.entries(m.changes_needed||{}).map(([k,c])=>`<span class="inline-block text-xs bg-yellow-500/15 text-yellow-300 rounded px-1.5 py-0.5 mr-1">${k}: ${c.from} → ${c.to}</span>`).join('')||'<span class="text-gray-600 text-xs">no changes</span>';
    return`<tr class="border-b border-gray-700/50 hover:bg-dark-900"><td class="px-4 py-2.5 text-gray-300">${m.hostname}</td><td class="px-4 py-2.5 text-gray-300">${m.pce_hostname}</td><td class="px-4 py-2.5">${labels}</td><td class="px-4 py-2.5">${changes}</td></tr>`;
  }).join('')||'<tr><td colspan="4" class="px-4 py-8 text-center text-gray-500">No matches found</td></tr>';
}

function renderRules(rules){
  document.getElementById('rules-table').innerHTML=rules.map(r=>`<tr class="border-b border-gray-700/50"><td class="px-4 py-2.5 text-gray-300">${r.source}</td><td class="px-4 py-2.5 text-gray-400 font-mono text-xs">${r.pattern}</td><td class="px-4 py-2.5"><span class="text-xs bg-blue-500/15 text-blue-300 rounded px-1.5 py-0.5">${r.target}</span></td><td class="px-4 py-2.5 text-gray-300">${r.value}</td><td class="px-4 py-2.5 text-gray-400">${r.priority}</td></tr>`).join('');
}

function renderSyncLog(results){
  if(!results.length){document.getElementById('sync-table').innerHTML='<tr><td colspan="3" class="px-4 py-8 text-center text-gray-500">No sync activity'+(data&&data.mode==='analytics'?' (analytics mode)':'')+'</td></tr>';return;}
  document.getElementById('sync-table').innerHTML=results.map(r=>{
    const badge=r.status==='synced'?'bg-green-500/15 text-green-300':'bg-red-500/15 text-red-300';
    const detail=r.status==='synced'?Object.entries(r.changes||{}).map(([k,c])=>`${k}: ${c.from} → ${c.to}`).join(', '):r.error||'';
    return`<tr class="border-b border-gray-700/50"><td class="px-4 py-2.5 text-gray-300">${r.hostname}</td><td class="px-4 py-2.5"><span class="text-xs ${badge} rounded px-2 py-0.5">${r.status}</span></td><td class="px-4 py-2.5 text-gray-400 text-xs">${detail}</td></tr>`;
  }).join('');
}

async function fetchData(){
  try{
    const resp=await fetch(BASE+'/api/scan');
    const d=await resp.json();
    update(d);
  }catch(e){
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-red-500';
    document.getElementById('status-text').textContent='Connection error';
  }
}

async function triggerScan(){
  try{
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning';
    document.getElementById('status-text').textContent='Scan triggered...';
    await fetch(BASE+'/api/scan/trigger',{method:'POST'});
  }catch(e){}
}

fetchData();
setInterval(fetchData,30000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class SyncHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path == "/" or path == "":
            self._send(200, DASHBOARD_HTML, "text/html")
        elif path == "/healthz":
            self._send(200, json.dumps({"status": "healthy"}))
        elif path == "/api/scan":
            with state_lock:
                self._send(200, json.dumps(report_state, default=str))
        elif path == "/api/config":
            config = {
                "remedy_host": REMEDY_HOST,
                "remedy_port": REMEDY_PORT,
                "ci_class": REMEDY_CI_CLASS,
                "namespace": REMEDY_NAMESPACE,
                "dataset": REMEDY_DATASET,
                "mode": MODE,
                "scan_interval": SCAN_INTERVAL,
            }
            self._send(200, json.dumps(config))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        if path == "/api/scan/trigger":
            with state_lock:
                if report_state["scanning"]:
                    self._send(409, json.dumps({"error": "Scan already in progress"}))
                    return
                report_state["scan_requested"] = True
            self._send(200, json.dumps({"status": "scan_requested"}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("Remedy CMDB Sync starting...")
    log.info("Config: mode=%s, remedy=%s:%s, class=%s, interval=%ds",
             MODE, REMEDY_HOST, REMEDY_PORT, REMEDY_CI_CLASS, SCAN_INTERVAL)

    if not REMEDY_HOST:
        log.warning("REMEDY_HOST not set — will show empty dashboard until configured")

    pce = get_pce()
    remedy = RemedyClient(REMEDY_HOST, REMEDY_PORT, REMEDY_USER, REMEDY_PASSWORD, REMEDY_TLS_VERIFY)

    poller = threading.Thread(target=poller_loop, args=(pce, remedy), daemon=True)
    poller.start()

    server = HTTPServer(("0.0.0.0", HTTP_PORT), SyncHandler)
    log.info("Dashboard listening on http://0.0.0.0:%d", HTTP_PORT)

    def shutdown(sig, frame):
        log.info("Shutting down...")
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
