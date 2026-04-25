#!/usr/bin/env python3
"""
Infoblox IPAM Sync — Bi-directional sync between Illumio labels and Infoblox EAs.

Modes:
  - analytics (default): Read-only preview of matches and changes
  - illumio-to-infoblox: Push Illumio labels as extensible attributes on host records
  - infoblox-to-illumio: Pull Infoblox EAs and apply as Illumio labels

NOTE: This plugin is UNTESTED against a live Infoblox instance.
"""

import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, quote

import requests
from illumio import PolicyComputeEngine

# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("infoblox-ipam-sync")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
INFOBLOX_HOST = os.environ.get("INFOBLOX_HOST", "")
INFOBLOX_USER = os.environ.get("INFOBLOX_USER", "")
INFOBLOX_PASSWORD = os.environ.get("INFOBLOX_PASSWORD", "")
INFOBLOX_WAPI_VERSION = os.environ.get("INFOBLOX_WAPI_VERSION", "v2.12")
INFOBLOX_SSL_VERIFY = os.environ.get("INFOBLOX_SSL_VERIFY", "false").lower() == "true"

MODE = os.environ.get("MODE", "analytics").lower()
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "3600"))
MATCH_BY = os.environ.get("MATCH_BY", "ip").lower()
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))
CREATE_EA_DEFS = os.environ.get("CREATE_EA_DEFS", "true").lower() == "true"
SYNC_IPLISTS = os.environ.get("SYNC_IPLISTS", "true").lower() == "true"
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

# Label mapping: Illumio key -> Infoblox EA name
DEFAULT_LABEL_MAPPING = {"app": "IllumioApp", "env": "IllumioEnv", "role": "IllumioRole", "loc": "IllumioLoc"}
LABEL_MAPPING = DEFAULT_LABEL_MAPPING.copy()
_lm = os.environ.get("LABEL_MAPPING", "").strip()
if _lm:
    try:
        LABEL_MAPPING = json.loads(_lm)
    except json.JSONDecodeError:
        log.warning("Invalid LABEL_MAPPING JSON, using defaults")

# Reverse mapping: Infoblox EA name -> Illumio label key
REVERSE_MAPPING = {}
_rm = os.environ.get("REVERSE_MAPPING", "").strip()
if _rm:
    try:
        REVERSE_MAPPING = json.loads(_rm)
    except json.JSONDecodeError:
        log.warning("Invalid REVERSE_MAPPING JSON")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
state = {
    "last_scan": None, "scan_count": 0, "scanning": False,
    "scan_requested": False, "error": None, "mode": MODE,
    "infoblox_status": "not configured",
    "matches": [], "unmatched_pce": [], "unmatched_ib": [],
    "summary": {}, "sync_results": [],
    "iplist_defs": [], "iplist_results": [],
}

label_cache = {}


# ---------------------------------------------------------------------------
# Infoblox WAPI client
# ---------------------------------------------------------------------------

class InfobloxClient:
    """Infoblox WAPI REST client with session cookie reuse."""

    def __init__(self, host, user, password, version="v2.12", verify=False):
        self.base_url = f"https://{host}/wapi/{version}"
        self.user = user
        self.password = password
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.verify = verify
        self.authenticated = False

    def _url(self, path):
        return f"{self.base_url}/{path}"

    def login(self):
        """Authenticate and cache session cookie."""
        try:
            resp = self.session.get(self._url("grid"), timeout=15)
            resp.raise_for_status()
            self.authenticated = True
            log.info("Infoblox login successful")
            return True
        except requests.RequestException as e:
            log.error("Infoblox login failed: %s", e)
            return False

    def logout(self):
        if self.authenticated:
            try:
                self.session.post(self._url("logout"), timeout=10)
            except Exception:
                pass
            self.authenticated = False

    def get_host_records(self, max_results=500):
        """Fetch all host records with extensible attributes, paginated."""
        all_records = []
        params = {
            "_return_fields+": "extattrs",
            "_paging": "1",
            "_return_as_object": "1",
            "_max_results": str(max_results),
        }
        resp = self.session.get(self._url("record:host"), params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        all_records.extend(data.get("result", []))

        while "next_page_id" in data:
            resp = self.session.get(self._url("record:host"),
                                    params={"_page_id": data["next_page_id"]}, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            all_records.extend(data.get("result", []))

        return all_records

    def ensure_ea_definitions(self, ea_names):
        """Create EA definitions if they don't exist."""
        resp = self.session.get(self._url("extensibleattributedef"),
                                params={"_return_fields": "name"}, timeout=30)
        resp.raise_for_status()
        existing = {ea["name"] for ea in resp.json()}

        for name in ea_names:
            if name not in existing:
                body = {"name": name, "type": "STRING",
                        "comment": f"Synced by Illumio Plugger"}
                try:
                    r = self.session.post(self._url("extensibleattributedef"),
                                          json=body, timeout=15)
                    r.raise_for_status()
                    log.info("Created EA definition: %s", name)
                except requests.RequestException as e:
                    log.warning("Failed to create EA %s: %s", name, e)

    def update_extattrs(self, ref, extattrs):
        """Update extensible attributes on an object (partial update)."""
        resp = self.session.put(self._url(ref), json={"extattrs+": extattrs}, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def batch_update_extattrs(self, updates):
        """Batch update EAs using the request object. updates = [(ref, extattrs), ...]"""
        results = []
        for i in range(0, len(updates), BATCH_SIZE):
            batch = updates[i:i + BATCH_SIZE]
            body = [{"method": "PUT", "object": ref,
                     "data": {"extattrs+": eas}} for ref, eas in batch]
            try:
                resp = self.session.post(self._url("request"), json=body, timeout=60)
                resp.raise_for_status()
                results.extend(resp.json())
            except requests.RequestException as e:
                log.error("Batch update failed at offset %d: %s", i, e)
                results.extend([{"error": str(e)}] * len(batch))
        return results

    def search_host_by_ip(self, ip):
        """Find host record by IPv4 address."""
        resp = self.session.get(self._url("record:host"),
                                params={"ipv4addr": ip, "_return_fields+": "extattrs"},
                                timeout=15)
        resp.raise_for_status()
        records = resp.json()
        return records[0] if records else None

    def search_host_by_name(self, hostname):
        """Find host record by hostname (regex)."""
        resp = self.session.get(self._url("record:host"),
                                params={"name~": hostname, "_return_fields+": "extattrs"},
                                timeout=15)
        resp.raise_for_status()
        records = resp.json()
        return records[0] if records else None

    def get_networks(self, max_results=500):
        """Fetch all networks with extensible attributes, paginated."""
        all_nets = []
        params = {
            "_return_fields+": "extattrs,comment",
            "_paging": "1",
            "_return_as_object": "1",
            "_max_results": str(max_results),
        }
        resp = self.session.get(self._url("network"), params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        all_nets.extend(data.get("result", []))

        while "next_page_id" in data:
            resp = self.session.get(self._url("network"),
                                    params={"_page_id": data["next_page_id"]}, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            all_nets.extend(data.get("result", []))

        return all_nets


# ---------------------------------------------------------------------------
# PCE helpers
# ---------------------------------------------------------------------------

def get_pce():
    pce = PolicyComputeEngine(
        url=os.environ["PCE_HOST"],
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(username=os.environ["PCE_API_KEY"], password=os.environ["PCE_API_SECRET"])
    verify = os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() != "true"
    pce.set_tls_settings(verify=verify)
    return pce


def fetch_labels(pce):
    global label_cache
    try:
        resp = pce.get("/labels")
        labels = resp.json() if resp.status_code == 200 else []
        label_cache = {lbl["href"]: {"key": lbl["key"], "value": lbl["value"]} for lbl in labels}
    except Exception as e:
        log.error("Failed to fetch labels: %s", e)


def get_workload_labels(wl):
    labels = {}
    for lbl in wl.get("labels", []):
        resolved = label_cache.get(lbl.get("href", ""))
        if resolved:
            labels[resolved["key"]] = resolved["value"]
    return labels


def get_workload_ips(wl):
    return [iface["address"] for iface in wl.get("interfaces", []) if iface.get("address")]


# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------

def build_matches(workloads, host_records):
    """Match PCE workloads to Infoblox host records."""
    # Index Infoblox hosts by IP and hostname
    ib_by_ip = {}
    ib_by_name = {}
    for hr in host_records:
        name = hr.get("name", "").lower()
        ib_by_name[name] = hr
        for addr_obj in hr.get("ipv4addrs", []):
            ip = addr_obj.get("ipv4addr", "")
            if ip:
                ib_by_ip[ip] = hr

    matches = []
    unmatched_pce = []

    for wl in workloads:
        hostname = (wl.get("hostname") or "").lower()
        ips = get_workload_ips(wl)
        labels = get_workload_labels(wl)
        matched_hr = None

        # Match by IP
        if MATCH_BY in ("ip", "both"):
            for ip in ips:
                if ip in ib_by_ip:
                    matched_hr = ib_by_ip[ip]
                    break

        # Match by hostname
        if not matched_hr and MATCH_BY in ("hostname", "both"):
            if hostname in ib_by_name:
                matched_hr = ib_by_name[hostname]
            else:
                for ib_name in ib_by_name:
                    if hostname and hostname in ib_name:
                        matched_hr = ib_by_name[ib_name]
                        break

        if matched_hr:
            existing_eas = matched_hr.get("extattrs", {})
            matches.append({
                "hostname": wl.get("hostname", ""),
                "ips": ips,
                "pce_labels": labels,
                "pce_href": wl.get("href", ""),
                "ib_name": matched_hr.get("name", ""),
                "ib_ref": matched_hr.get("_ref", ""),
                "ib_extattrs": {k: v.get("value", "") for k, v in existing_eas.items()},
                "changes": {},
            })
        else:
            unmatched_pce.append({
                "hostname": wl.get("hostname", ""),
                "ips": ips,
                "labels": labels,
            })

    # Find Infoblox hosts not matched to any workload
    matched_refs = {m["ib_ref"] for m in matches}
    unmatched_ib = [{"name": hr.get("name", ""), "ips": [a.get("ipv4addr", "") for a in hr.get("ipv4addrs", [])]}
                    for hr in host_records if hr.get("_ref", "") not in matched_refs]

    return matches, unmatched_pce, unmatched_ib


def compute_changes_illumio_to_infoblox(matches):
    """For each match, compute what EAs would change on Infoblox."""
    for m in matches:
        changes = {}
        for illumio_key, ea_name in LABEL_MAPPING.items():
            illumio_val = m["pce_labels"].get(illumio_key, "")
            current_ea = m["ib_extattrs"].get(ea_name, "")
            if illumio_val and illumio_val != current_ea:
                changes[ea_name] = {"from": current_ea or "(none)", "to": illumio_val}
        m["changes"] = changes


def compute_changes_infoblox_to_illumio(matches):
    """For each match, compute what labels would change on PCE."""
    for m in matches:
        changes = {}
        for ea_name, illumio_key in REVERSE_MAPPING.items():
            ea_val = m["ib_extattrs"].get(ea_name, "")
            current_label = m["pce_labels"].get(illumio_key, "")
            if ea_val and ea_val != current_label:
                changes[illumio_key] = {"from": current_label or "(none)", "to": ea_val}
        m["changes"] = changes


# ---------------------------------------------------------------------------
# Sync executors
# ---------------------------------------------------------------------------

def sync_illumio_to_infoblox(ib_client, matches):
    """Push Illumio labels as EAs on Infoblox host records."""
    results = []
    updates = []
    now = datetime.now(timezone.utc).isoformat()

    for m in matches:
        if not m["changes"]:
            continue
        eas = {ea_name: {"value": change["to"]} for ea_name, change in m["changes"].items()}
        eas["IllumioManaged"] = {"value": "true"}
        eas["IllumioSyncTime"] = {"value": now}
        updates.append((m["ib_ref"], eas))

    if not updates:
        return [{"status": "no_changes", "count": 0}]

    log.info("Syncing %d EA updates to Infoblox...", len(updates))
    batch_results = ib_client.batch_update_extattrs(updates)

    for i, (ref, eas) in enumerate(updates):
        hostname = next((m["hostname"] for m in matches if m["ib_ref"] == ref), ref)
        br = batch_results[i] if i < len(batch_results) else "unknown"
        if isinstance(br, str) and "error" not in br.lower():
            results.append({"hostname": hostname, "status": "synced"})
        elif isinstance(br, dict) and "error" in br:
            results.append({"hostname": hostname, "status": "error", "error": br["error"]})
        else:
            results.append({"hostname": hostname, "status": "synced"})

    return results


def sync_infoblox_to_illumio(pce, matches):
    """Pull Infoblox EAs and apply as Illumio labels."""
    results = []
    all_labels = label_cache

    label_href_map = {}
    try:
        resp = pce.get("/labels")
        for lbl in resp.json() if resp.status_code == 200 else []:
            label_href_map[(lbl["key"], lbl["value"])] = lbl["href"]
    except Exception:
        pass

    for m in matches:
        if not m["changes"]:
            continue
        wl_href = m["pce_href"]
        hostname = m["hostname"]

        try:
            resp = pce.get(wl_href)
            if resp.status_code != 200:
                results.append({"hostname": hostname, "status": "error", "error": f"GET {resp.status_code}"})
                continue

            wl = resp.json()
            current_labels = list(wl.get("labels", []))

            for illumio_key, change in m["changes"].items():
                new_value = change["to"]
                target_href = label_href_map.get((illumio_key, new_value))

                if not target_href:
                    try:
                        cr = pce.post("/labels", json={"key": illumio_key, "value": new_value})
                        if cr.status_code in (200, 201):
                            target_href = cr.json().get("href", "")
                            label_href_map[(illumio_key, new_value)] = target_href
                    except Exception:
                        continue

                if target_href:
                    current_labels = [l for l in current_labels
                                      if label_cache.get(l.get("href", ""), {}).get("key") != illumio_key]
                    current_labels.append({"href": target_href})

            clean = [{"href": l["href"]} for l in current_labels]
            pr = pce.put(wl_href, json={"labels": clean})
            if pr.status_code in (200, 204):
                results.append({"hostname": hostname, "status": "synced"})
            else:
                results.append({"hostname": hostname, "status": "error", "error": f"PUT {pr.status_code}"})

        except Exception as e:
            results.append({"hostname": hostname, "status": "error", "error": str(e)})

    return results


# ---------------------------------------------------------------------------
# IP List sync: Infoblox networks → Illumio IP Lists
# ---------------------------------------------------------------------------

IP_LIST_PREFIX = "infoblox-"


def build_iplist_definitions(networks):
    """Build IP List definitions from Infoblox network objects."""
    ip_lists = []
    for net in networks:
        network_cidr = net.get("network", "")
        if not network_cidr:
            continue

        comment = net.get("comment", "")
        extattrs = net.get("extattrs", {})

        # Build a descriptive name from EAs or comment
        name_parts = []
        for ea_name in ("Site", "Location", "Department", "Environment", "Function"):
            val = extattrs.get(ea_name, {}).get("value", "")
            if val:
                name_parts.append(val)

        if name_parts:
            display_name = "-".join(name_parts)
        elif comment:
            display_name = comment.replace(" ", "-").lower()[:50]
        else:
            display_name = network_cidr.replace("/", "_").replace(".", "-")

        ip_list_name = f"{IP_LIST_PREFIX}{display_name}"

        # Extract all EA values for description
        ea_desc = ", ".join(f"{k}={v.get('value', '')}" for k, v in extattrs.items() if v.get("value"))

        ip_lists.append({
            "name": ip_list_name,
            "network": network_cidr,
            "comment": comment,
            "extattrs": {k: v.get("value", "") for k, v in extattrs.items()},
            "ea_description": ea_desc,
            "description": f"Synced from Infoblox | {network_cidr} | {ea_desc}" if ea_desc else f"Synced from Infoblox | {network_cidr}",
        })

    return ip_lists


def sync_iplists_to_illumio(pce, iplist_defs):
    """Create/update Illumio IP Lists from Infoblox network definitions."""
    results = []

    # Get existing IP lists
    try:
        resp = pce.get("/sec_policy/draft/ip_lists")
        existing = resp.json() if resp.status_code == 200 else []
    except Exception:
        existing = []

    existing_by_name = {ipl.get("name", ""): ipl for ipl in existing}

    for ipdef in iplist_defs:
        target_name = ipdef["name"]
        ip_ranges = [{"from_ip": ipdef["network"], "exclusion": False}]
        body = {
            "name": target_name,
            "description": ipdef["description"],
            "ip_ranges": ip_ranges,
        }

        try:
            if target_name in existing_by_name:
                # Update existing
                href = existing_by_name[target_name]["href"]
                resp = pce.put(href, json={"description": ipdef["description"], "ip_ranges": ip_ranges})
                if resp.status_code in (200, 204):
                    results.append({"name": target_name, "network": ipdef["network"], "status": "updated"})
                else:
                    results.append({"name": target_name, "network": ipdef["network"], "status": "error",
                                    "error": f"PUT {resp.status_code}"})
            else:
                # Create new
                resp = pce.post("/sec_policy/draft/ip_lists", json=body)
                if resp.status_code in (200, 201):
                    results.append({"name": target_name, "network": ipdef["network"], "status": "created"})
                else:
                    results.append({"name": target_name, "network": ipdef["network"], "status": "error",
                                    "error": f"POST {resp.status_code}"})
        except Exception as e:
            results.append({"name": target_name, "network": ipdef["network"], "status": "error", "error": str(e)})

    return results


# ---------------------------------------------------------------------------
# Scan orchestrator
# ---------------------------------------------------------------------------

def run_scan(pce, ib_client):
    fetch_labels(pce)
    resp = pce.get("/workloads", params={"max_results": 10000})
    workloads = resp.json() if resp.status_code == 200 else []
    log.info("Fetched %d PCE workloads", len(workloads))

    host_records = []
    networks = []
    ib_status = "not configured"

    if ib_client and INFOBLOX_HOST:
        try:
            if ib_client.login():
                ib_status = "connected"
                if CREATE_EA_DEFS and MODE == "illumio-to-infoblox":
                    ea_names = list(LABEL_MAPPING.values()) + ["IllumioManaged", "IllumioSyncTime"]
                    ib_client.ensure_ea_definitions(ea_names)
                host_records = ib_client.get_host_records()
                log.info("Fetched %d Infoblox host records", len(host_records))
                if SYNC_IPLISTS:
                    networks = ib_client.get_networks()
                    log.info("Fetched %d Infoblox networks", len(networks))
                ib_client.logout()
        except Exception as e:
            log.error("Infoblox error: %s", e)
            ib_status = f"error: {e}"

    matches, unmatched_pce, unmatched_ib = build_matches(workloads, host_records)
    log.info("Matched: %d, Unmatched PCE: %d, Unmatched IB: %d",
             len(matches), len(unmatched_pce), len(unmatched_ib))

    # Compute changes
    if MODE == "illumio-to-infoblox":
        compute_changes_illumio_to_infoblox(matches)
    elif MODE == "infoblox-to-illumio":
        compute_changes_infoblox_to_illumio(matches)
    else:
        compute_changes_illumio_to_infoblox(matches)

    changes_needed = sum(1 for m in matches if m["changes"])

    # Execute sync
    sync_results = []
    if MODE == "illumio-to-infoblox" and ib_client and ib_status == "connected":
        try:
            ib_client.login()
            sync_results = sync_illumio_to_infoblox(ib_client, matches)
            ib_client.logout()
            synced = sum(1 for r in sync_results if r.get("status") == "synced")
            ib_status = f"synced ({synced} updated)"
        except Exception as e:
            log.error("Sync to Infoblox failed: %s", e)
            ib_status = f"sync error: {e}"

    elif MODE == "infoblox-to-illumio" and REVERSE_MAPPING:
        sync_results = sync_infoblox_to_illumio(pce, matches)
        synced = sum(1 for r in sync_results if r.get("status") == "synced")
        ib_status = f"synced ({synced} labeled)"

    # IP List sync: Infoblox networks → Illumio IP Lists
    iplist_defs = build_iplist_definitions(networks) if networks else []
    iplist_results = []
    if SYNC_IPLISTS and MODE in ("infoblox-to-illumio", "analytics") and iplist_defs:
        if MODE == "infoblox-to-illumio":
            iplist_results = sync_iplists_to_illumio(pce, iplist_defs)
            created = sum(1 for r in iplist_results if r["status"] == "created")
            updated = sum(1 for r in iplist_results if r["status"] == "updated")
            log.info("IP List sync: %d created, %d updated", created, updated)
        else:
            log.info("IP List preview: %d networks → %d IP Lists (analytics mode)", len(networks), len(iplist_defs))

    summary = {
        "total_workloads": len(workloads),
        "total_host_records": len(host_records),
        "total_networks": len(networks),
        "matched": len(matches),
        "unmatched_pce": len(unmatched_pce),
        "unmatched_ib": len(unmatched_ib),
        "changes_needed": changes_needed,
        "match_pct": round(len(matches) / max(len(workloads), 1) * 100, 1),
        "iplist_count": len(iplist_defs),
        "iplist_synced": sum(1 for r in iplist_results if r.get("status") in ("created", "updated")),
    }

    with state_lock:
        state["matches"] = matches[:500]
        state["unmatched_pce"] = unmatched_pce[:200]
        state["unmatched_ib"] = unmatched_ib[:200]
        state["summary"] = summary
        state["sync_results"] = sync_results
        state["iplist_defs"] = iplist_defs[:200]
        state["iplist_results"] = iplist_results
        state["infoblox_status"] = ib_status
        state["last_scan"] = datetime.now(timezone.utc).isoformat()
        state["scan_count"] += 1
        state["error"] = None


# ---------------------------------------------------------------------------
# Poller
# ---------------------------------------------------------------------------

def poller_loop(pce, ib_client):
    while True:
        do_scan = False
        with state_lock:
            if state["scan_requested"]:
                state["scan_requested"] = False
                do_scan = True
        if do_scan or state["last_scan"] is None:
            pass
        else:
            time.sleep(30)
            try:
                last = datetime.fromisoformat(state["last_scan"].replace("Z", "+00:00"))
                if (datetime.now(timezone.utc) - last).total_seconds() < SCAN_INTERVAL:
                    continue
            except (ValueError, TypeError, AttributeError):
                pass
        try:
            with state_lock:
                state["scanning"] = True
                state["error"] = None
            run_scan(pce, ib_client)
            with state_lock:
                state["scanning"] = False
            s = state["summary"]
            log.info("Scan complete: %d matched, %d unmatched, %d changes",
                     s["matched"], s["unmatched_pce"], s["changes_needed"])
        except Exception as e:
            log.error("Scan failed: %s", e, exc_info=True)
            with state_lock:
                state["scanning"] = False
                state["error"] = str(e)
        time.sleep(60)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Infoblox IPAM Sync</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,sans-serif}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#11111b}::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.tab-btn{cursor:pointer;padding:0.5rem 1rem;font-size:0.875rem;border-bottom:2px solid transparent;color:#a6adc8;transition:all 0.15s}
.tab-btn:hover{color:#cdd6f4}.tab-btn.active{color:#89b4fa;border-color:#89b4fa}
.ip-tag{display:inline-block;font-family:monospace;font-size:0.75rem;background:#313244;color:#a6e3a1;padding:2px 6px;border-radius:3px;margin:1px}
.ea-tag{display:inline-block;font-size:0.75rem;background:rgba(250,179,135,0.15);color:#fab387;padding:2px 6px;border-radius:3px;margin:1px;border:1px solid rgba(250,179,135,0.2)}
.lbl-tag{display:inline-block;font-size:0.75rem;background:rgba(137,180,250,0.15);color:#93c5fd;padding:2px 6px;border-radius:3px;margin:1px;border:1px solid rgba(137,180,250,0.2)}
.chg-tag{display:inline-block;font-size:0.75rem;background:rgba(249,226,175,0.15);color:#f9e2af;padding:2px 6px;border-radius:3px;margin:1px;border:1px solid rgba(249,226,175,0.2)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}.scanning{animation:pulse 2s infinite}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-6">
<div class="flex items-center justify-between mb-8">
  <div>
    <h1 class="text-2xl font-bold text-white flex items-center gap-2">
      <svg class="w-6 h-6 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/></svg>
      Infoblox IPAM Sync
    </h1>
    <div class="flex items-center gap-2 mt-1">
      <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
      <span id="status-text" class="text-sm text-gray-400">Loading...</span>
    </div>
  </div>
  <div class="flex items-center gap-3">
    <span id="mode-badge" class="text-xs px-3 py-1 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30 font-medium"></span>
    <button onclick="triggerScan()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Scan Now</button>
  </div>
</div>
<div class="bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-3 mb-6 text-sm text-amber-300">
  <strong>Untested:</strong> This plugin has not been validated against a live Infoblox instance.
</div>
<div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div id="s-wl" class="text-3xl font-bold text-blue-400">—</div><div class="text-sm text-gray-400 mt-1">PCE Workloads</div></div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div id="s-ib" class="text-3xl font-bold text-orange-400">—</div><div class="text-sm text-gray-400 mt-1">IB Host Records</div></div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div id="s-match" class="text-3xl font-bold text-green-400">—</div><div class="text-sm text-gray-400 mt-1">Matched</div></div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div id="s-chg" class="text-3xl font-bold text-yellow-400">—</div><div class="text-sm text-gray-400 mt-1">Changes Needed</div></div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div id="s-pct" class="text-3xl font-bold text-purple-400">—</div><div class="text-sm text-gray-400 mt-1">Match Rate</div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 lg:col-span-1"><h3 class="text-sm font-semibold text-gray-300 mb-3">Match Distribution</h3><div style="height:200px"><canvas id="chart-match"></canvas></div></div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 lg:col-span-2" id="mapping-info">
    <h3 class="text-sm font-semibold text-gray-300 mb-3">Label ↔ EA Mapping</h3>
    <div id="mapping-table" class="text-sm"></div>
  </div>
</div>
<div class="flex gap-1 border-b border-gray-700 mb-6">
  <button class="tab-btn active" onclick="showTab(this,'matches')">Matches</button>
  <button class="tab-btn" onclick="showTab(this,'unmatched')">Unmatched</button>
  <button class="tab-btn" onclick="showTab(this,'iplists')">IP Lists</button>
  <button class="tab-btn" onclick="showTab(this,'sync')">Sync Log</button>
</div>
<div id="tab-matches" class="tab-content">
  <div class="bg-dark-800 rounded-xl border border-gray-700"><div class="max-h-[500px] overflow-y-auto">
    <table class="w-full text-sm"><thead class="sticky top-0 bg-dark-800"><tr class="text-left text-xs text-gray-400 uppercase">
      <th class="px-4 py-3">Hostname</th><th class="px-4 py-3">IPs</th><th class="px-4 py-3">Illumio Labels</th><th class="px-4 py-3">Infoblox EAs</th><th class="px-4 py-3">Changes</th>
    </tr></thead><tbody id="match-table"></tbody></table>
  </div></div>
</div>
<div id="tab-unmatched" class="tab-content hidden">
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-4"><h3 class="text-white font-semibold mb-3">PCE Workloads (no Infoblox match)</h3>
      <div class="max-h-[400px] overflow-y-auto"><table class="w-full text-sm"><thead><tr class="text-xs text-gray-400 uppercase"><th class="px-3 py-2 text-left">Hostname</th><th class="px-3 py-2 text-left">IPs</th></tr></thead><tbody id="unmatched-pce"></tbody></table></div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-4"><h3 class="text-white font-semibold mb-3">Infoblox Hosts (no PCE match)</h3>
      <div class="max-h-[400px] overflow-y-auto"><table class="w-full text-sm"><thead><tr class="text-xs text-gray-400 uppercase"><th class="px-3 py-2 text-left">Name</th><th class="px-3 py-2 text-left">IPs</th></tr></thead><tbody id="unmatched-ib"></tbody></table></div>
    </div>
  </div>
</div>
<div id="tab-iplists" class="tab-content hidden">
  <div class="bg-dark-800 rounded-xl border border-gray-700"><div class="max-h-[500px] overflow-y-auto">
    <table class="w-full text-sm"><thead class="sticky top-0 bg-dark-800"><tr class="text-xs text-gray-400 uppercase text-left">
      <th class="px-4 py-3">IP List Name</th><th class="px-4 py-3">Network</th><th class="px-4 py-3">Infoblox EAs</th><th class="px-4 py-3" id="ipl-sync-col" style="display:none">Status</th>
    </tr></thead><tbody id="iplist-table"></tbody></table>
  </div></div>
</div>
<div id="tab-sync" class="tab-content hidden">
  <div class="bg-dark-800 rounded-xl border border-gray-700"><div class="max-h-[400px] overflow-y-auto">
    <table class="w-full text-sm"><thead class="sticky top-0 bg-dark-800"><tr class="text-xs text-gray-400 uppercase text-left"><th class="px-4 py-3">Hostname</th><th class="px-4 py-3">Status</th><th class="px-4 py-3">Details</th></tr></thead><tbody id="sync-table"></tbody></table>
  </div></div>
</div>
</div>
<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\/plugins\/[^/]+\/ui/);return m?m[0]:''})();
let D=null,chartMatch=null;
function fmt(n){if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toLocaleString()}
function timeAgo(ts){if(!ts)return'—';const d=(Date.now()-new Date(ts).getTime())/1000;if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago'}
function showTab(btn,id){document.querySelectorAll('.tab-content').forEach(t=>t.classList.add('hidden'));document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));document.getElementById('tab-'+id).classList.remove('hidden');btn.classList.add('active')}

function update(d){
  D=d;
  const dot=document.getElementById('status-dot'),txt=document.getElementById('status-text');
  if(d.scanning){dot.className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning';txt.textContent='Scanning...';}
  else if(d.error){dot.className='w-2.5 h-2.5 rounded-full bg-red-500';txt.textContent='Error: '+d.error;}
  else if(d.last_scan){dot.className='w-2.5 h-2.5 rounded-full bg-green-500';txt.textContent=d.infoblox_status+' | '+timeAgo(d.last_scan);}
  else{dot.className='w-2.5 h-2.5 rounded-full bg-gray-500';txt.textContent='Not scanned yet';}
  document.getElementById('mode-badge').textContent=d.mode;
  const s=d.summary||{};
  document.getElementById('s-wl').textContent=fmt(s.total_workloads||0);
  document.getElementById('s-ib').textContent=fmt(s.total_host_records||0);
  document.getElementById('s-match').textContent=fmt(s.matched||0);
  document.getElementById('s-chg').textContent=fmt(s.changes_needed||0);
  document.getElementById('s-pct').textContent=(s.match_pct||0)+'%';

  // Chart
  const ctx=document.getElementById('chart-match').getContext('2d');
  if(chartMatch)chartMatch.destroy();
  chartMatch=new Chart(ctx,{type:'doughnut',data:{labels:['Matched','Unmatched PCE','Unmatched IB'],datasets:[{data:[s.matched||0,s.unmatched_pce||0,s.unmatched_ib||0],backgroundColor:['#a6e3a1','#f38ba8','#fab387'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,cutout:'55%',plugins:{legend:{position:'bottom',labels:{color:'#a6adc8',font:{size:11}}}}}});

  // Matches table
  document.getElementById('match-table').innerHTML=(d.matches||[]).map(m=>{
    const ips=m.ips.slice(0,3).map(ip=>`<span class="ip-tag">${ip}</span>`).join('');
    const lbls=Object.entries(m.pce_labels||{}).map(([k,v])=>`<span class="lbl-tag">${k}:${v}</span>`).join('');
    const eas=Object.entries(m.ib_extattrs||{}).filter(([k])=>k.startsWith('Illumio')).map(([k,v])=>`<span class="ea-tag">${k}:${v}</span>`).join('')||'<span class="text-gray-600">—</span>';
    const chgs=Object.entries(m.changes||{}).map(([k,c])=>`<span class="chg-tag">${k}: ${c.from} → ${c.to}</span>`).join('')||'<span class="text-gray-600">no changes</span>';
    return`<tr class="border-b border-gray-700/50 hover:bg-dark-900"><td class="px-4 py-2.5 text-gray-300">${m.hostname}<br><span class="text-xs text-gray-500">${m.ib_name}</span></td><td class="px-4 py-2.5">${ips}</td><td class="px-4 py-2.5">${lbls}</td><td class="px-4 py-2.5">${eas}</td><td class="px-4 py-2.5">${chgs}</td></tr>`;
  }).join('')||'<tr><td colspan="5" class="px-4 py-8 text-center text-gray-500">No matches yet</td></tr>';

  // Unmatched
  document.getElementById('unmatched-pce').innerHTML=(d.unmatched_pce||[]).map(u=>`<tr class="border-b border-gray-700/50"><td class="px-3 py-2 text-gray-300">${u.hostname}</td><td class="px-3 py-2">${u.ips.slice(0,2).map(ip=>`<span class="ip-tag">${ip}</span>`).join('')}</td></tr>`).join('');
  document.getElementById('unmatched-ib').innerHTML=(d.unmatched_ib||[]).map(u=>`<tr class="border-b border-gray-700/50"><td class="px-3 py-2 text-gray-300">${u.name}</td><td class="px-3 py-2">${u.ips.slice(0,2).map(ip=>`<span class="ip-tag">${ip}</span>`).join('')}</td></tr>`).join('');

  // IP Lists
  const ipls=d.iplist_defs||[];
  const iplResults={};for(const r of(d.iplist_results||[]))iplResults[r.name]=r;
  if(d.mode!=='analytics'&&d.iplist_results?.length)document.getElementById('ipl-sync-col').style.display='';
  document.getElementById('iplist-table').innerHTML=ipls.length?ipls.map(ipl=>{
    const eas=Object.entries(ipl.extattrs||{}).filter(([,v])=>v).map(([k,v])=>`<span class="ea-tag">${k}:${v}</span>`).join('')||'<span class="text-gray-600">—</span>';
    const sr2=iplResults[ipl.name];
    const syncCell=sr2?`<td class="px-4 py-2.5"><span class="text-xs ${sr2.status==='error'?'bg-red-500/15 text-red-300':'bg-green-500/15 text-green-300'} rounded px-2 py-0.5">${sr2.status}</span></td>`:'';
    return`<tr class="border-b border-gray-700/50 hover:bg-dark-900"><td class="px-4 py-2.5 text-gray-300">${ipl.name}</td><td class="px-4 py-2.5"><span class="ip-tag">${ipl.network}</span></td><td class="px-4 py-2.5">${eas}</td>${syncCell}</tr>`;
  }).join(''):'<tr><td colspan="4" class="px-4 py-8 text-center text-gray-500">No Infoblox networks found</td></tr>';

  // Sync log
  const sr=d.sync_results||[];
  document.getElementById('sync-table').innerHTML=sr.length?sr.map(r=>{
    const badge=r.status==='synced'?'bg-green-500/15 text-green-300':'bg-red-500/15 text-red-300';
    return`<tr class="border-b border-gray-700/50"><td class="px-4 py-2.5 text-gray-300">${r.hostname||'—'}</td><td class="px-4 py-2.5"><span class="text-xs ${badge} rounded px-2 py-0.5">${r.status}</span></td><td class="px-4 py-2.5 text-gray-400 text-xs">${r.error||''}</td></tr>`;
  }).join(''):'<tr><td colspan="3" class="px-4 py-8 text-center text-gray-500">No sync activity'+(d.mode==='analytics'?' (analytics mode)':'')+'</td></tr>';
}

async function fetchData(){try{const r=await fetch(BASE+'/api/state');update(await r.json())}catch(e){}}
async function triggerScan(){try{await fetch(BASE+'/api/scan',{method:'POST'})}catch(e){}}
fetchData();setInterval(fetchData,15000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): log.debug(fmt, *args)
    def _send(self, code, body, ct="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)
    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/": self._send(200, DASHBOARD_HTML, "text/html")
        elif path == "/healthz": self._send(200, json.dumps({"status": "healthy"}))
        elif path == "/api/state":
            with state_lock: self._send(200, json.dumps(state, default=str))
        else: self._send(404, json.dumps({"error": "Not found"}))
    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        if path == "/api/scan":
            with state_lock: state["scan_requested"] = True
            self._send(200, json.dumps({"status": "scan_requested"}))
        else: self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("Infoblox IPAM Sync starting...")
    log.info("Config: mode=%s, host=%s, match_by=%s, interval=%ds",
             MODE, INFOBLOX_HOST or "(not set)", MATCH_BY, SCAN_INTERVAL)

    pce = get_pce()
    ib_client = InfobloxClient(INFOBLOX_HOST, INFOBLOX_USER, INFOBLOX_PASSWORD,
                                INFOBLOX_WAPI_VERSION, INFOBLOX_SSL_VERIFY) if INFOBLOX_HOST else None

    poller = threading.Thread(target=poller_loop, args=(pce, ib_client), daemon=True)
    poller.start()

    server = HTTPServer(("0.0.0.0", HTTP_PORT), Handler)
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
