#!/usr/bin/env python3
"""
fortigate-sync -- Sync Illumio workloads to FortiGate firewalls.

Two sync methods:
  1. RSSO (RADIUS SSO) -- sends RADIUS Accounting packets to inject workload
     IPs into FortiGate's RSSO authentication table.
  2. REST API -- creates/updates/deletes FortiGate address objects and address
     groups based on Illumio workload labels.

RSSO sync based on illumio-to-fortigate-sync by ruckle-o:
  https://github.com/ruckle-o/illumio-to-fortigate-sync
"""

import hashlib
import json
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import requests
from illumio import PolicyComputeEngine

import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
log = logging.getLogger("fortigate-sync")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
FG_HOST = os.environ.get("FG_HOST", "")
FG_RSSO_PORT = int(os.environ.get("FG_RSSO_PORT", "1813"))
FG_RSSO_SECRET = os.environ.get("FG_RSSO_SECRET", "")
FG_API_TOKEN = os.environ.get("FG_API_TOKEN", "")
FG_VDOM = os.environ.get("FG_VDOM", "root")
SYNC_MODE = os.environ.get("SYNC_MODE", "rsso").lower()  # rsso | objects | both
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "300"))
DEFAULT_RSSO_GROUP = os.environ.get("DEFAULT_RSSO_GROUP", "ILLUMIO_WORKLOADS")
ADDRESS_PREFIX = os.environ.get("ADDRESS_PREFIX", "illumio-")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

# LABEL_GROUPS: JSON array mapping label filters to RSSO groups.
# [{"labels": {"env": "prod", "role": "web"}, "group": "ILLUMIO_PROD_WEB"}, ...]
LABEL_GROUPS = []
_lg = os.environ.get("LABEL_GROUPS", "").strip()
if _lg:
    try:
        LABEL_GROUPS = json.loads(_lg)
    except json.JSONDecodeError:
        log.warning("Invalid LABEL_GROUPS JSON, ignoring")

STATE_FILE = os.environ.get("STATE_FILE", "/data/rsso_state.json")

# ---------------------------------------------------------------------------
# RADIUS dictionary (inline)
# ---------------------------------------------------------------------------
# pyrad needs a dictionary file; we write a minimal one at startup.
RADIUS_DICT_PATH = "/tmp/radius_dictionary"
RADIUS_DICT_CONTENT = """\
ATTRIBUTE	User-Name	1	string
ATTRIBUTE	Framed-IP-Address	8	ipaddr
ATTRIBUTE	Class	25	string
ATTRIBUTE	Acct-Status-Type	40	integer
ATTRIBUTE	Acct-Session-Id	44	string

VALUE	Acct-Status-Type	Start	1
VALUE	Acct-Status-Type	Stop	2
"""


def write_radius_dict():
    """Write the inline RADIUS dictionary to a temp file for pyrad."""
    try:
        with open(RADIUS_DICT_PATH, "w") as f:
            f.write(RADIUS_DICT_CONTENT)
    except Exception as e:
        log.warning("Could not write RADIUS dictionary: %s", e)


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
sync_state = {
    "last_sync": None,
    "last_sync_duration": 0,
    "sync_count": 0,
    "syncing": False,
    "error": None,
    "fg_status": "unknown",
    "sync_mode": SYNC_MODE,
    "rsso": {
        "total_ips": 0,
        "groups": {},          # group_name -> {count, ips, last_sync}
        "starts_sent": 0,
        "stops_sent": 0,
    },
    "objects": {
        "address_objects": 0,
        "address_groups": 0,
        "created": 0,
        "deleted": 0,
    },
    "workloads": [],           # [{hostname, ip, labels, group, addr_name, status}]
    "sync_history": [],        # last 20 syncs
}

label_cache = {}  # href -> {key, value}

# Persistent RSSO state: {ip: {hostname, group, synced_at}}
rsso_state = {}


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
    except Exception as e:
        log.warning("Failed to fetch labels: %s", e)


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
# Label-to-group mapping
# ---------------------------------------------------------------------------

def match_group(labels):
    """Return the RSSO group name for a workload's labels.

    Iterates LABEL_GROUPS looking for the first entry whose label filter
    matches the workload labels.  Falls back to DEFAULT_RSSO_GROUP.
    """
    for mapping in LABEL_GROUPS:
        filter_labels = mapping.get("labels", {})
        group_name = mapping.get("group", "")
        if not filter_labels or not group_name:
            continue
        match = True
        for key, value in filter_labels.items():
            if labels.get(key) != value:
                match = False
                break
        if match:
            return group_name
    return DEFAULT_RSSO_GROUP


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def load_rsso_state():
    global rsso_state
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
            rsso_state = data.get("synced_ips", {})
            log.info("Loaded RSSO state: %d IPs", len(rsso_state))
    except FileNotFoundError:
        rsso_state = {}
    except Exception as e:
        log.warning("Failed to load RSSO state: %s", e)
        rsso_state = {}


def save_rsso_state():
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        data = {
            "last_sync": datetime.now(timezone.utc).isoformat(),
            "synced_ips": rsso_state,
        }
        with open(STATE_FILE, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        log.warning("Failed to save RSSO state: %s", e)


# ---------------------------------------------------------------------------
# RSSO (RADIUS SSO) via pyrad
# ---------------------------------------------------------------------------

def send_rsso_packet(ip, hostname, group, acct_type="Start"):
    """Send a RADIUS Accounting packet to the FortiGate.

    acct_type: "Start" to add an IP, "Stop" to remove it.
    """
    if not FG_HOST or not FG_RSSO_SECRET:
        return False, "FG_HOST or FG_RSSO_SECRET not configured"

    try:
        client = Client(
            server=FG_HOST,
            authport=0,
            acctport=FG_RSSO_PORT,
            secret=FG_RSSO_SECRET.encode(),
            dict=Dictionary(RADIUS_DICT_PATH),
        )
        client.timeout = 10

        pkt = client.CreateAcctPacket()
        pkt["User-Name"] = hostname
        pkt["Framed-IP-Address"] = ip
        pkt["Class"] = group.encode()
        pkt["Acct-Status-Type"] = acct_type
        session_id = hashlib.md5(f"{ip}:{group}".encode()).hexdigest()[:16]
        pkt["Acct-Session-Id"] = session_id

        client.SendPacket(pkt)
        return True, None
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# FortiGate REST API (address objects / groups)
# ---------------------------------------------------------------------------

def fg_api_request(method, endpoint, payload=None):
    """Make a FortiGate REST API call."""
    if not FG_HOST or not FG_API_TOKEN:
        return None, "FG_HOST or FG_API_TOKEN not configured"

    base_url = f"https://{FG_HOST}/api/v2/cmdb/firewall"
    url = f"{base_url}/{endpoint}?vdom={FG_VDOM}"
    headers = {"Authorization": f"Bearer {FG_API_TOKEN}"}

    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, verify=False, timeout=30)
        elif method == "POST":
            resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
        elif method == "PUT":
            resp = requests.put(url, headers=headers, json=payload, verify=False, timeout=30)
        elif method == "DELETE":
            resp = requests.delete(url, headers=headers, verify=False, timeout=30)
        else:
            return None, f"Unknown method: {method}"

        return resp, None
    except Exception as e:
        return None, str(e)


def fg_get_address_objects():
    """Fetch all address objects with the Illumio prefix."""
    resp, err = fg_api_request("GET", "address")
    if err:
        return [], err
    if resp.status_code != 200:
        return [], f"HTTP {resp.status_code}"
    try:
        results = resp.json().get("results", [])
        return [o for o in results if o.get("name", "").startswith(ADDRESS_PREFIX)], None
    except Exception as e:
        return [], str(e)


def fg_create_address_object(hostname, ip, labels):
    """Create a FortiGate address object for a workload."""
    name = f"{ADDRESS_PREFIX}{hostname}"
    comment_parts = [f"{k}={v}" for k, v in sorted(labels.items())]
    comment = f"Illumio: {', '.join(comment_parts)}" if comment_parts else "Illumio workload"

    payload = {
        "name": name,
        "type": "ipmask",
        "subnet": f"{ip} 255.255.255.255",
        "comment": comment,
    }
    resp, err = fg_api_request("POST", "address", payload)
    if err:
        return False, err
    if resp.status_code in (200, 201):
        return True, None
    # If it already exists, try updating
    if resp.status_code == 500 or resp.status_code == 409:
        resp2, err2 = fg_api_request("PUT", f"address/{name}", payload)
        if err2:
            return False, err2
        if resp2.status_code in (200, 204):
            return True, None
        return False, f"PUT HTTP {resp2.status_code}"
    return False, f"HTTP {resp.status_code}"


def fg_delete_address_object(name):
    """Delete a FortiGate address object."""
    resp, err = fg_api_request("DELETE", f"address/{name}")
    if err:
        return False, err
    if resp.status_code in (200, 204):
        return True, None
    return False, f"HTTP {resp.status_code}"


def fg_create_address_group(group_name, members):
    """Create/update a FortiGate address group."""
    name = f"{ADDRESS_PREFIX}grp-{group_name}"
    member_list = [{"name": m} for m in members]

    payload = {
        "name": name,
        "member": member_list,
        "comment": "Managed by Illumio Plugger",
    }

    resp, err = fg_api_request("POST", "addrgrp", payload)
    if err:
        return False, err
    if resp.status_code in (200, 201):
        return True, None
    # If it exists, update
    if resp.status_code == 500 or resp.status_code == 409:
        resp2, err2 = fg_api_request("PUT", f"addrgrp/{name}", payload)
        if err2:
            return False, err2
        if resp2.status_code in (200, 204):
            return True, None
        return False, f"PUT HTTP {resp2.status_code}"
    return False, f"HTTP {resp.status_code}"


def fg_check_health():
    """Check FortiGate API connectivity."""
    if not FG_HOST or not FG_API_TOKEN:
        return False, "Not configured"
    try:
        url = f"https://{FG_HOST}/api/v2/cmdb/system/status?vdom={FG_VDOM}"
        headers = {"Authorization": f"Bearer {FG_API_TOKEN}"}
        resp = requests.get(url, headers=headers, verify=False, timeout=10)
        if resp.status_code == 200:
            return True, None
        return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Sync logic
# ---------------------------------------------------------------------------

def run_sync(pce):
    """Full sync cycle: fetch workloads, push RSSO + address objects."""
    global rsso_state
    with state_lock:
        if sync_state["syncing"]:
            return
        sync_state["syncing"] = True

    start_time = time.time()

    try:
        log.info("Starting sync (mode=%s)...", SYNC_MODE)

        if not label_cache:
            fetch_labels(pce)

        # Check FortiGate connectivity
        do_rsso = SYNC_MODE in ("rsso", "both")
        do_objects = SYNC_MODE in ("objects", "both")

        fg_status = "unknown"
        if do_objects:
            healthy, err = fg_check_health()
            fg_status = "connected" if healthy else f"error: {err}"
            if not healthy:
                log.warning("FortiGate API not reachable: %s", err)
        if do_rsso:
            if FG_HOST and FG_RSSO_SECRET:
                fg_status = "rsso-configured" if fg_status == "unknown" else fg_status
            else:
                fg_status = "rsso-not-configured"

        with state_lock:
            sync_state["fg_status"] = fg_status

        # Fetch workloads from PCE
        try:
            resp = pce.get("/workloads", params={"max_results": 10000})
            workloads = resp.json() if resp.status_code == 200 else []
        except Exception as e:
            log.error("Failed to fetch workloads: %s", e)
            with state_lock:
                sync_state["error"] = str(e)
                sync_state["syncing"] = False
            return

        if not isinstance(workloads, list):
            workloads = []

        log.info("Fetched %d workloads from PCE", len(workloads))

        # Build current IP -> {hostname, group, labels} mapping
        current_ips = {}
        group_members = defaultdict(list)  # group -> [hostnames]
        wl_details = []

        for wl in workloads:
            hostname = wl.get("hostname") or wl.get("name") or "(unnamed)"
            if not wl.get("online", False):
                continue

            labels = resolve_labels(wl)
            group = match_group(labels)

            interfaces = wl.get("interfaces", [])
            for iface in interfaces:
                ip = iface.get("address", "")
                if not ip or ip.startswith("127.") or ip.startswith("169.254."):
                    continue

                current_ips[ip] = {
                    "hostname": hostname,
                    "group": group,
                    "labels": labels,
                }
                group_members[group].append(hostname)
                addr_name = f"{ADDRESS_PREFIX}{hostname}" if do_objects else ""
                wl_details.append({
                    "hostname": hostname,
                    "ip": ip,
                    "labels": labels,
                    "group": group,
                    "addr_name": addr_name,
                    "status": "pending",
                })

        log.info("Found %d online workload IPs in %d groups",
                 len(current_ips), len(group_members))

        # Determine additions and removals
        previous_ips = set(rsso_state.keys())
        current_ip_set = set(current_ips.keys())
        new_ips = current_ip_set - previous_ips
        removed_ips = previous_ips - current_ip_set

        starts_sent = 0
        stops_sent = 0
        objects_created = 0
        objects_deleted = 0

        # --- RSSO sync ---
        if do_rsso:
            # Send Start for new IPs
            for ip in new_ips:
                info = current_ips[ip]
                ok, err = send_rsso_packet(ip, info["hostname"], info["group"], "Start")
                if ok:
                    starts_sent += 1
                    log.debug("RSSO Start: %s (%s) -> %s", ip, info["hostname"], info["group"])
                else:
                    log.warning("RSSO Start failed for %s: %s", ip, err)

            # Send Start for IPs whose group changed
            for ip in current_ip_set & previous_ips:
                old_group = rsso_state.get(ip, {}).get("group", "")
                new_group = current_ips[ip]["group"]
                if old_group != new_group:
                    # Stop old group, start new
                    old_hostname = rsso_state.get(ip, {}).get("hostname", "")
                    send_rsso_packet(ip, old_hostname, old_group, "Stop")
                    stops_sent += 1
                    ok, err = send_rsso_packet(ip, current_ips[ip]["hostname"], new_group, "Start")
                    if ok:
                        starts_sent += 1

            # Send Stop for removed IPs
            for ip in removed_ips:
                info = rsso_state.get(ip, {})
                hostname = info.get("hostname", "unknown")
                group = info.get("group", DEFAULT_RSSO_GROUP)
                ok, err = send_rsso_packet(ip, hostname, group, "Stop")
                if ok:
                    stops_sent += 1
                    log.debug("RSSO Stop: %s (%s)", ip, hostname)
                else:
                    log.warning("RSSO Stop failed for %s: %s", ip, err)

            log.info("RSSO: %d Start, %d Stop packets sent", starts_sent, stops_sent)

        # --- REST API address objects ---
        if do_objects and FG_API_TOKEN:
            # Create/update address objects for current workloads
            seen_names = set()
            for ip, info in current_ips.items():
                ok, err = fg_create_address_object(info["hostname"], ip, info["labels"])
                if ok:
                    objects_created += 1
                    seen_names.add(f"{ADDRESS_PREFIX}{info['hostname']}")
                else:
                    log.warning("Failed to create address object for %s: %s",
                                info["hostname"], err)

            # Create/update address groups
            groups_created = 0
            for group_name, members in group_members.items():
                member_names = [f"{ADDRESS_PREFIX}{h}" for h in members]
                ok, err = fg_create_address_group(group_name, member_names)
                if ok:
                    groups_created += 1
                else:
                    log.warning("Failed to create address group %s: %s",
                                group_name, err)

            # Delete stale address objects (IPs removed from Illumio)
            for ip in removed_ips:
                info = rsso_state.get(ip, {})
                hostname = info.get("hostname", "")
                if hostname:
                    name = f"{ADDRESS_PREFIX}{hostname}"
                    ok, err = fg_delete_address_object(name)
                    if ok:
                        objects_deleted += 1

            log.info("Objects: %d created/updated, %d deleted, %d groups",
                     objects_created, objects_deleted, groups_created)
        else:
            groups_created = 0

        # Update RSSO state
        now_iso = datetime.now(timezone.utc).isoformat()
        new_rsso_state = {}
        for ip, info in current_ips.items():
            new_rsso_state[ip] = {
                "hostname": info["hostname"],
                "group": info["group"],
                "synced_at": now_iso,
            }

        rsso_state = new_rsso_state
        save_rsso_state()

        # Update workload detail statuses
        for wl in wl_details:
            wl["status"] = "synced"

        # Build group summary
        group_summary = {}
        for group_name, members in group_members.items():
            group_ips = [ip for ip, info in current_ips.items() if info["group"] == group_name]
            group_summary[group_name] = {
                "count": len(members),
                "ips": group_ips[:50],
                "last_sync": now_iso,
            }

        duration = round(time.time() - start_time, 2)

        sync_entry = {
            "timestamp": now_iso,
            "duration": duration,
            "total_ips": len(current_ips),
            "new_ips": len(new_ips),
            "removed_ips": len(removed_ips),
            "groups": len(group_members),
            "starts_sent": starts_sent,
            "stops_sent": stops_sent,
            "objects_created": objects_created,
            "objects_deleted": objects_deleted,
            "error": None,
        }

        with state_lock:
            sync_state["last_sync"] = now_iso
            sync_state["last_sync_duration"] = duration
            sync_state["sync_count"] += 1
            sync_state["syncing"] = False
            sync_state["error"] = None
            sync_state["rsso"]["total_ips"] = len(current_ips)
            sync_state["rsso"]["groups"] = group_summary
            sync_state["rsso"]["starts_sent"] = starts_sent
            sync_state["rsso"]["stops_sent"] = stops_sent
            sync_state["objects"]["address_objects"] = objects_created
            sync_state["objects"]["address_groups"] = groups_created
            sync_state["objects"]["created"] = objects_created
            sync_state["objects"]["deleted"] = objects_deleted
            sync_state["workloads"] = wl_details
            sync_state["sync_history"] = (sync_state["sync_history"] + [sync_entry])[-20:]

        log.info("Sync #%d complete in %.1fs: %d IPs, %d new, %d removed",
                 sync_state["sync_count"], duration, len(current_ips),
                 len(new_ips), len(removed_ips))

    except Exception as e:
        log.exception("Sync failed")
        with state_lock:
            sync_state["error"] = str(e)
            sync_state["syncing"] = False


def poller_loop(pce):
    while True:
        try:
            run_sync(pce)
        except Exception:
            log.exception("Sync loop error")
        time.sleep(SYNC_INTERVAL)


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FortiGate Sync</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#11111b}
::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.tab-btn{cursor:pointer;padding:8px 16px;font-size:14px;font-weight:500;border-radius:8px 8px 0 0;border:1px solid transparent;color:#6c7086;transition:all .2s}
.tab-btn:hover{color:#cdd6f4;background:rgba(49,50,68,0.5)}
.tab-btn.active{color:#89b4fa;background:#1e1e2e;border-color:#313244;border-bottom-color:#1e1e2e}
.tab-panel{display:none}
.tab-panel.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeIn .3s ease-out}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.syncing-indicator{animation:pulse 2s infinite}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-6">

<!-- Header -->
<div class="flex items-center justify-between mb-6 fade-in">
  <div>
    <h1 class="text-2xl font-bold text-white flex items-center gap-2">
      <svg class="w-7 h-7 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
      FortiGate Sync
    </h1>
    <div class="flex items-center gap-2 mt-1">
      <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
      <span id="status-text" class="text-sm text-gray-400">Loading...</span>
    </div>
    <div class="text-xs text-gray-500 mt-1">
      RSSO sync based on <a href="https://github.com/ruckle-o/illumio-to-fortigate-sync" class="text-blue-400 hover:text-blue-300">illumio-to-fortigate-sync</a> by ruckle-o
    </div>
  </div>
  <div class="flex items-center gap-3">
    <div id="fg-status" class="text-sm"></div>
    <button onclick="triggerSync()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Sync Now</button>
    <a id="export-link" href="/api/export/json" class="bg-dark-700 hover:bg-dark-800 text-gray-300 px-4 py-1.5 rounded text-sm border border-gray-600 inline-block no-underline">Export</a>
  </div>
</div>

<!-- Stats -->
<div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8" id="stats-row">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-ips" class="text-3xl font-bold text-blue-400">--</div>
    <div class="text-sm text-gray-500 mt-1">Synced IPs</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-groups" class="text-3xl font-bold text-green-400">--</div>
    <div class="text-sm text-gray-500 mt-1">RSSO Groups</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-objects" class="text-3xl font-bold text-purple-400">--</div>
    <div class="text-sm text-gray-500 mt-1">Address Objects</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-syncs" class="text-3xl font-bold text-yellow-400">--</div>
    <div class="text-sm text-gray-500 mt-1">Total Syncs</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-duration" class="text-3xl font-bold text-red-400">--</div>
    <div class="text-sm text-gray-500 mt-1">Last Duration</div>
  </div>
</div>

<!-- Tabs -->
<div class="mb-0 flex border-b border-gray-700" id="tab-bar"></div>

<!-- Tab: Sync Status -->
<div id="tab-sync" class="tab-panel active bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">IPs per Group</h3>
      <div style="height:280px"><canvas id="chart-groups"></canvas></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Sync History</h3>
      <div style="height:280px"><canvas id="chart-history"></canvas></div>
    </div>
  </div>
  <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Overall Status</h3>
    <div id="sync-status-detail" class="space-y-2"></div>
  </div>
</div>

<!-- Tab: Workloads -->
<div id="tab-workloads" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="flex items-center justify-between mb-4">
    <h2 class="text-lg font-semibold text-white">Synced Workloads</h2>
    <input type="text" id="wl-search" placeholder="Search hostname, IP, label..." oninput="renderWorkloads()" class="bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-500 w-64">
  </div>
  <div class="overflow-x-auto max-h-[600px] overflow-y-auto">
    <table class="w-full text-sm">
      <thead class="sticky top-0 bg-dark-800 z-10"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
        <th class="px-3 py-2">Hostname</th>
        <th class="px-3 py-2">IP</th>
        <th class="px-3 py-2">Labels</th>
        <th class="px-3 py-2">RSSO Group</th>
        <th class="px-3 py-2">Address Object</th>
        <th class="px-3 py-2">Status</th>
      </tr></thead>
      <tbody id="wl-table-body"></tbody>
    </table>
  </div>
  <div id="wl-footer" class="mt-3 text-xs text-gray-500"></div>
</div>

<!-- Tab: RSSO Groups -->
<div id="tab-rsso" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <h2 class="text-lg font-semibold text-white mb-4">RSSO Groups</h2>
  <div id="rsso-groups-container" class="space-y-4"></div>
</div>

<!-- Tab: Address Objects (only visible when objects mode) -->
<div id="tab-objects" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <h2 class="text-lg font-semibold text-white mb-4">FortiGate Address Objects</h2>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Address Objects</h3>
      <div id="addr-objects-container" class="space-y-2 max-h-[400px] overflow-y-auto"></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Address Groups</h3>
      <div id="addr-groups-container" class="space-y-2 max-h-[400px] overflow-y-auto"></div>
    </div>
  </div>
  <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
    <div class="flex items-center justify-between">
      <div>
        <span class="text-sm text-gray-400">Created/Updated:</span>
        <span id="obj-created" class="text-sm font-semibold text-green-400 ml-1">--</span>
      </div>
      <div>
        <span class="text-sm text-gray-400">Deleted:</span>
        <span id="obj-deleted" class="text-sm font-semibold text-red-400 ml-1">--</span>
      </div>
    </div>
  </div>
</div>

<!-- Tab: Configuration -->
<div id="tab-config" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <h2 class="text-lg font-semibold text-white mb-4">Configuration</h2>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Current Settings</h3>
      <div id="config-settings" class="space-y-2"></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Label Group Mappings</h3>
      <div id="config-label-groups" class="space-y-2 max-h-[400px] overflow-y-auto"></div>
    </div>
  </div>
</div>

<!-- Footer -->
<div class="text-center text-xs text-gray-600 py-4">
  FortiGate Sync &mdash; Powered by Illumio Plugger &mdash; Auto-refreshes every 15s
</div>

</div>

<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\/plugins\/[^/]+\/ui/);return m?m[0]:''})();
let stateData=null;
let charts={};
let currentTab='sync';

function timeAgo(ts){
  if(!ts)return '--';
  const d=(Date.now()-new Date(ts).getTime())/1000;
  if(d<60)return 'just now';
  if(d<3600)return Math.floor(d/60)+'m ago';
  if(d<86400)return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}

function labelsStr(labels){
  if(!labels||!Object.keys(labels).length)return '<span class="text-gray-600">--</span>';
  return Object.entries(labels).map(([k,v])=>'<span class="text-xs px-1.5 py-0.5 rounded bg-dark-700 text-gray-400">'+k+':'+v+'</span>').join(' ');
}

function statusBadge(s){
  const map={synced:{c:'#a6e3a1',l:'Synced'},pending:{c:'#f9e2af',l:'Pending'},error:{c:'#f38ba8',l:'Error'}};
  const info=map[s]||map.pending;
  return '<span class="px-2 py-0.5 rounded text-xs font-medium" style="background:'+info.c+'22;color:'+info.c+';border:1px solid '+info.c+'44">'+info.l+'</span>';
}

// Tabs
function buildTabs(syncMode){
  const tabs=[
    {id:'sync',label:'Sync Status'},
    {id:'workloads',label:'Workloads'},
    {id:'rsso',label:'RSSO Groups'},
  ];
  if(syncMode==='objects'||syncMode==='both'){
    tabs.push({id:'objects',label:'Address Objects'});
  }
  tabs.push({id:'config',label:'Configuration'});
  document.getElementById('tab-bar').innerHTML=tabs.map(t=>
    '<button class="tab-btn'+(t.id===currentTab?' active':'')+'" onclick="showTab(\''+t.id+'\')">'+t.label+'</button>'
  ).join('');
}

function showTab(name){
  currentTab=name;
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  const panel=document.getElementById('tab-'+name);
  if(panel)panel.classList.add('active');
  const tabs=document.querySelectorAll('.tab-btn');
  tabs.forEach(b=>{if(b.textContent.toLowerCase().replace(/\s/g,'').includes(name))b.classList.add('active');});
  // Re-match by data
  buildTabs(stateData?stateData.sync_mode:'rsso');
}

// Charts
function initCharts(){
  charts.groups=new Chart(document.getElementById('chart-groups'),{
    type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#89b4fa44',borderColor:'#89b4fa',borderWidth:1,borderRadius:4}]},
    options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280'}},y:{grid:{display:false},ticks:{color:'#a6adc8',font:{size:11,family:'monospace'}}}}}
  });
  charts.history=new Chart(document.getElementById('chart-history'),{
    type:'line',data:{labels:[],datasets:[
      {label:'Total IPs',data:[],borderColor:'#89b4fa',backgroundColor:'#89b4fa22',fill:true,tension:0.3,pointRadius:3},
      {label:'New',data:[],borderColor:'#a6e3a1',backgroundColor:'#a6e3a122',fill:false,tension:0.3,pointRadius:2},
      {label:'Removed',data:[],borderColor:'#f38ba8',backgroundColor:'#f38ba822',fill:false,tension:0.3,pointRadius:2},
    ]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#9ca3af',usePointStyle:true,font:{size:11}}}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280',font:{size:10}}},y:{grid:{color:'#31324422'},ticks:{color:'#6b7280'},beginAtZero:true}}}
  });
}

// Render
function renderAll(data){
  if(!data){return;}
  stateData=data;

  buildTabs(data.sync_mode||'rsso');

  // Status header
  const dot=document.getElementById('status-dot');
  const syncing=data.syncing;
  dot.className='w-2.5 h-2.5 rounded-full '+(syncing?'bg-yellow-500 syncing-indicator':data.error?'bg-red-500':'bg-green-500');
  document.getElementById('status-text').textContent=(syncing?'Syncing... ':'')+'Sync #'+(data.sync_count||0)+' · '+timeAgo(data.last_sync)+(data.error?' · Error: '+data.error:'');

  // FG status
  const fgSt=data.fg_status||'unknown';
  const fgOk=fgSt.includes('connected')||fgSt.includes('configured');
  document.getElementById('fg-status').innerHTML='<span class="px-2 py-0.5 rounded text-xs '+(fgOk?'bg-green-900/50 text-green-400':'bg-red-900/50 text-red-400')+'">FG: '+fgSt+'</span>';

  // Stats
  const rsso=data.rsso||{};
  const objs=data.objects||{};
  document.getElementById('stat-ips').textContent=rsso.total_ips||0;
  document.getElementById('stat-groups').textContent=Object.keys(rsso.groups||{}).length;
  document.getElementById('stat-objects').textContent=objs.address_objects||0;
  document.getElementById('stat-syncs').textContent=data.sync_count||0;
  document.getElementById('stat-duration').textContent=(data.last_sync_duration||0)+'s';

  // Export link
  document.getElementById('export-link').href=BASE+'/api/export/json';

  renderSyncTab(data);
  renderWorkloads();
  renderRSSO(data);
  renderObjects(data);
  renderConfig(data);
}

function renderSyncTab(data){
  const rsso=data.rsso||{};
  const groups=rsso.groups||{};
  const history=data.sync_history||[];

  // Groups chart
  const gEntries=Object.entries(groups).sort((a,b)=>b[1].count-a[1].count).slice(0,15);
  charts.groups.data.labels=gEntries.map(e=>e[0]);
  charts.groups.data.datasets[0].data=gEntries.map(e=>e[1].count);
  charts.groups.update('none');

  // History chart
  charts.history.data.labels=history.map(h=>new Date(h.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}));
  charts.history.data.datasets[0].data=history.map(h=>h.total_ips);
  charts.history.data.datasets[1].data=history.map(h=>h.new_ips);
  charts.history.data.datasets[2].data=history.map(h=>h.removed_ips);
  charts.history.update('none');

  // Sync status detail
  const lastSync=history.length?history[history.length-1]:null;
  document.getElementById('sync-status-detail').innerHTML=`
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <div class="bg-dark-700/50 rounded px-3 py-2"><div class="text-xs text-gray-500">Mode</div><div class="text-sm font-semibold text-white">${data.sync_mode||'rsso'}</div></div>
      <div class="bg-dark-700/50 rounded px-3 py-2"><div class="text-xs text-gray-500">RSSO Starts</div><div class="text-sm font-semibold text-green-400">${rsso.starts_sent||0}</div></div>
      <div class="bg-dark-700/50 rounded px-3 py-2"><div class="text-xs text-gray-500">RSSO Stops</div><div class="text-sm font-semibold text-red-400">${rsso.stops_sent||0}</div></div>
      <div class="bg-dark-700/50 rounded px-3 py-2"><div class="text-xs text-gray-500">Last Error</div><div class="text-sm font-semibold ${data.error?'text-red-400':'text-green-400'}">${data.error||'None'}</div></div>
    </div>
    ${lastSync?`<div class="mt-3 text-xs text-gray-500">Last sync: ${lastSync.total_ips} IPs, ${lastSync.new_ips} new, ${lastSync.removed_ips} removed in ${lastSync.duration}s</div>`:''}
  `;
}

function renderWorkloads(){
  if(!stateData)return;
  const search=(document.getElementById('wl-search').value||'').toLowerCase();
  let wls=stateData.workloads||[];
  if(search){
    wls=wls.filter(w=>{
      const lstr=Object.entries(w.labels||{}).map(([k,v])=>k+':'+v).join(' ').toLowerCase();
      return (w.hostname||'').toLowerCase().includes(search)||(w.ip||'').includes(search)||lstr.includes(search)||(w.group||'').toLowerCase().includes(search);
    });
  }
  const shown=wls.slice(0,500);
  document.getElementById('wl-table-body').innerHTML=shown.map(w=>`
    <tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
      <td class="px-3 py-2"><code class="text-xs">${w.hostname||'--'}</code></td>
      <td class="px-3 py-2 text-xs text-gray-400 font-mono">${w.ip||'--'}</td>
      <td class="px-3 py-2">${labelsStr(w.labels)}</td>
      <td class="px-3 py-2"><span class="text-xs px-2 py-0.5 rounded bg-blue-900/30 text-blue-400 border border-blue-800/30">${w.group||'--'}</span></td>
      <td class="px-3 py-2 text-xs text-gray-500 font-mono">${w.addr_name||'--'}</td>
      <td class="px-3 py-2">${statusBadge(w.status)}</td>
    </tr>
  `).join('')||'<tr><td colspan="6" class="px-3 py-4 text-center text-gray-600">No workloads synced yet</td></tr>';
  document.getElementById('wl-footer').textContent='Showing '+shown.length+' of '+wls.length+' workloads';
}

function renderRSSO(data){
  const groups=data.rsso?.groups||{};
  const entries=Object.entries(groups).sort((a,b)=>b[1].count-a[1].count);
  if(!entries.length){
    document.getElementById('rsso-groups-container').innerHTML='<div class="text-gray-600 text-sm">No RSSO groups yet. Waiting for first sync.</div>';
    return;
  }
  document.getElementById('rsso-groups-container').innerHTML=entries.map(([name,info])=>{
    const ips=(info.ips||[]).slice(0,20);
    return `<div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-semibold text-blue-400 font-mono">${name}</h3>
        <span class="text-xs text-gray-500">${info.count} member${info.count!==1?'s':''} · ${timeAgo(info.last_sync)}</span>
      </div>
      <div class="flex flex-wrap gap-1">
        ${ips.map(ip=>'<span class="text-xs px-2 py-0.5 rounded bg-dark-700 text-gray-400 font-mono">'+ip+'</span>').join('')}
        ${info.ips&&info.ips.length>20?'<span class="text-xs text-gray-600">+'+(info.ips.length-20)+' more</span>':''}
      </div>
    </div>`;
  }).join('');
}

function renderObjects(data){
  const objs=data.objects||{};
  document.getElementById('obj-created').textContent=objs.created||0;
  document.getElementById('obj-deleted').textContent=objs.deleted||0;

  // Address objects from workloads
  const wls=data.workloads||[];
  const addrWls=wls.filter(w=>w.addr_name);
  document.getElementById('addr-objects-container').innerHTML=addrWls.length?addrWls.map(w=>`
    <div class="flex items-center justify-between bg-dark-700/50 rounded px-3 py-2">
      <code class="text-xs text-orange-300">${w.addr_name}</code>
      <span class="text-xs text-gray-500 font-mono">${w.ip}</span>
    </div>
  `).join(''):'<div class="text-gray-600 text-sm">No address objects created yet</div>';

  // Address groups from RSSO groups
  const groups=data.rsso?.groups||{};
  const gEntries=Object.entries(groups);
  document.getElementById('addr-groups-container').innerHTML=gEntries.length?gEntries.map(([name,info])=>`
    <div class="bg-dark-700/50 rounded px-3 py-2">
      <div class="text-xs text-purple-400 font-mono mb-1">illumio-grp-${name}</div>
      <div class="text-xs text-gray-500">${info.count} member${info.count!==1?'s':''}</div>
    </div>
  `).join(''):'<div class="text-gray-600 text-sm">No address groups created yet</div>';
}

function renderConfig(data){
  const settings=[
    ['FortiGate Host',data._config?.fg_host||'--'],
    ['Sync Mode',data.sync_mode||'rsso'],
    ['RSSO Port',data._config?.rsso_port||'--'],
    ['VDOM',data._config?.vdom||'--'],
    ['Address Prefix',data._config?.address_prefix||'--'],
    ['Sync Interval',data._config?.sync_interval||'--'],
    ['Default RSSO Group',data._config?.default_group||'--'],
    ['PCE Host',data._config?.pce_host||'--'],
  ];
  document.getElementById('config-settings').innerHTML=settings.map(([k,v])=>`
    <div class="flex items-center justify-between bg-dark-700/50 rounded px-3 py-2">
      <span class="text-xs text-gray-500">${k}</span>
      <span class="text-xs font-mono text-gray-300">${v}</span>
    </div>
  `).join('');

  const labelGroups=data._config?.label_groups||[];
  document.getElementById('config-label-groups').innerHTML=labelGroups.length?labelGroups.map(lg=>`
    <div class="bg-dark-700/50 rounded px-3 py-2">
      <div class="flex items-center justify-between mb-1">
        <span class="text-xs font-mono text-blue-400">${lg.group||'--'}</span>
      </div>
      <div class="flex flex-wrap gap-1">
        ${Object.entries(lg.labels||{}).map(([k,v])=>'<span class="text-xs px-1.5 py-0.5 rounded bg-dark-800 text-gray-400">'+k+'='+v+'</span>').join('')}
      </div>
    </div>
  `).join(''):'<div class="text-gray-600 text-sm">No label group mappings configured. All workloads go to default group: '+(data._config?.default_group||'ILLUMIO_WORKLOADS')+'</div>';
}

async function fetchData(){
  try{
    const resp=await fetch(BASE+'/api/state');
    const data=await resp.json();
    renderAll(data);
  }catch(e){console.error('Fetch failed:',e);}
}

async function triggerSync(){
  try{
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-yellow-500 syncing-indicator';
    document.getElementById('status-text').textContent='Sync triggered...';
    await fetch(BASE+'/api/sync',{method:'POST'});
    setTimeout(fetchData,2000);
  }catch(e){console.error(e);}
}

initCharts();
fetchData();
setInterval(fetchData,15000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class FortiGateHandler(BaseHTTPRequestHandler):
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

    def _build_config(self):
        """Build safe config dict (no secrets)."""
        return {
            "fg_host": FG_HOST or "(not set)",
            "rsso_port": FG_RSSO_PORT,
            "vdom": FG_VDOM,
            "address_prefix": ADDRESS_PREFIX,
            "sync_interval": f"{SYNC_INTERVAL}s",
            "default_group": DEFAULT_RSSO_GROUP,
            "pce_host": os.environ.get("PCE_HOST", "(not set)"),
            "label_groups": LABEL_GROUPS,
        }

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/" or path == "":
            self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")

        elif path == "/healthz":
            with state_lock:
                healthy = sync_state["error"] is None
            status = "healthy" if healthy else "degraded"
            self._send(200, json.dumps({
                "status": status,
                "last_sync": sync_state.get("last_sync"),
                "sync_count": sync_state.get("sync_count", 0),
            }))

        elif path == "/api/state":
            with state_lock:
                data = dict(sync_state)
                data["_config"] = self._build_config()
            self._send(200, json.dumps(data, default=str))

        elif path == "/api/groups":
            with state_lock:
                groups = sync_state["rsso"]["groups"]
            self._send(200, json.dumps(groups, default=str))

        elif path == "/api/export/json":
            with state_lock:
                data = dict(sync_state)
                data["_config"] = self._build_config()
                data["rsso_state"] = rsso_state
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition",
                             "attachment; filename=fortigate-sync-export.json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data, default=str, indent=2).encode())

        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/sync":
            with state_lock:
                if sync_state["syncing"]:
                    self._send(409, json.dumps({"error": "Sync already in progress"}))
                    return
            threading.Thread(target=run_sync, args=(pce_client,), daemon=True).start()
            self._send(200, json.dumps({"status": "sync_triggered"}))

        else:
            self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

pce_client = None


def main():
    global pce_client

    log.info("FortiGate Sync starting...")
    log.info("Config: sync_mode=%s, sync_interval=%ds, fg_host=%s, rsso_port=%d, vdom=%s",
             SYNC_MODE, SYNC_INTERVAL, FG_HOST or "(not set)", FG_RSSO_PORT, FG_VDOM)
    log.info("Label groups configured: %d", len(LABEL_GROUPS))
    log.info("Default RSSO group: %s", DEFAULT_RSSO_GROUP)

    # Write RADIUS dictionary
    write_radius_dict()

    # Load persistent state
    load_rsso_state()

    # Connect to PCE
    pce_client = get_pce()
    log.info("Connected to PCE: %s", pce_client.base_url)

    # Initial sync
    run_sync(pce_client)

    # Background poller
    poller = threading.Thread(target=poller_loop, args=(pce_client,), daemon=True)
    poller.start()

    # HTTP server
    server = HTTPServer(("0.0.0.0", HTTP_PORT), FortiGateHandler)
    log.info("Dashboard listening on http://0.0.0.0:%d", HTTP_PORT)

    def shutdown(sig, frame):
        log.info("Shutting down...")
        save_rsso_state()
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server.serve_forever()
    log.info("Stopped.")


if __name__ == "__main__":
    main()
