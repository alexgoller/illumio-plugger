#!/usr/bin/env python3
"""
ZTNA Sync — Sync Illumio workloads to ZTNA application definitions.

Collects workloads from the PCE, groups by label (app|env), discovers
listening ports from traffic data, and creates/updates ZTNA application
segments on Zscaler ZPA, Netskope NPA, Cloudflare Access, or Cisco
Secure Access.

Two modes:
  - analytics (default): Preview what would be created/updated
  - sync: Push application definitions to the ZTNA platform

NOTE: This plugin is UNTESTED against live ZTNA platforms.
"""

import json
import logging
import os
import re
import signal
import sys
import threading
import time
from base64 import b64encode
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import requests
from illumio import PolicyComputeEngine
from illumio.explorer import TrafficQuery

# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("ztna-sync")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ZTNA_PROVIDER = os.environ.get("ZTNA_PROVIDER", "").lower()
MODE = os.environ.get("MODE", "analytics").lower()
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "3600"))
GROUP_BY = [k.strip() for k in os.environ.get("GROUP_BY", "app,env").split(",")]
PORT_SOURCE = os.environ.get("PORT_SOURCE", "traffic")
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "168"))
NAMING_PATTERN = os.environ.get("NAMING_PATTERN", "{app}-{env}")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

LABEL_FILTER = {}
_lf = os.environ.get("LABEL_FILTER", "").strip()
if _lf:
    try:
        LABEL_FILTER = json.loads(_lf)
    except json.JSONDecodeError:
        log.warning("Invalid LABEL_FILTER JSON, ignoring")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
state = {
    "last_scan": None,
    "scan_count": 0,
    "scanning": False,
    "scan_requested": False,
    "error": None,
    "mode": MODE,
    "provider": ZTNA_PROVIDER,
    "provider_status": "not configured",
    "applications": [],
    "summary": {},
    "sync_results": [],
}

label_cache = {}


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


def matches_filter(labels):
    if not LABEL_FILTER:
        return True
    for key, allowed in LABEL_FILTER.items():
        if labels.get(key) not in allowed:
            return False
    return True


# ---------------------------------------------------------------------------
# Application grouping
# ---------------------------------------------------------------------------

def build_applications(pce):
    """Group workloads into ZTNA application definitions."""
    fetch_labels(pce)

    # Fetch workloads
    resp = pce.get("/workloads", params={"max_results": 10000})
    workloads = resp.json() if resp.status_code == 200 else []
    log.info("Fetched %d workloads", len(workloads))

    # Fetch traffic for port discovery
    ports_by_dst = defaultdict(set)  # dst_ip -> set of (port, proto)
    if PORT_SOURCE == "traffic":
        try:
            end = datetime.now(timezone.utc)
            start = end - timedelta(hours=LOOKBACK_HOURS)
            tq = TrafficQuery.build(
                start_date=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                end_date=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                policy_decisions=["allowed", "potentially_blocked"],
                max_results=50000,
            )
            flows = pce.get_traffic_flows_async("plugger-ztna-sync", tq)
            for f in flows:
                flow = f.to_json() if hasattr(f, "to_json") else (f.__dict__ if hasattr(f, "__dict__") else f)
                if isinstance(flow, str):
                    flow = json.loads(flow)
                dst = flow.get("dst", {})
                svc = flow.get("service", {})
                dst_wl = dst.get("workload", {})
                if not dst_wl:
                    continue
                for iface in dst_wl.get("interfaces", []):
                    ip = iface.get("address", "")
                    if ip and isinstance(svc, dict):
                        port = svc.get("port")
                        proto = svc.get("proto", 6)
                        if port and port > 0:
                            proto_str = {6: "tcp", 17: "udp"}.get(proto, str(proto))
                            ports_by_dst[ip].add((port, proto_str))
            log.info("Analyzed traffic: %d destination IPs with ports", len(ports_by_dst))
        except Exception as e:
            log.error("Traffic query failed: %s", e)

    # Group workloads by label keys
    groups = defaultdict(lambda: {"workloads": [], "ips": set(), "ports": set(), "labels": {}})

    for wl in workloads:
        labels = get_workload_labels(wl)
        if not matches_filter(labels):
            continue

        group_key_parts = [labels.get(k, "") for k in GROUP_BY]
        if not any(group_key_parts):
            continue
        group_key = "|".join(group_key_parts)

        groups[group_key]["workloads"].append(wl.get("hostname", ""))
        groups[group_key]["labels"] = {k: labels.get(k, "") for k in GROUP_BY}

        # Add all label keys for naming
        for k, v in labels.items():
            if k not in groups[group_key]["labels"]:
                groups[group_key]["labels"][k] = v

        for ip in get_workload_ips(wl):
            groups[group_key]["ips"].add(ip)
            if ip in ports_by_dst:
                groups[group_key]["ports"].update(ports_by_dst[ip])

    # Build application definitions
    applications = []
    for group_key, data in sorted(groups.items()):
        labels = data["labels"]
        name = NAMING_PATTERN
        for k, v in labels.items():
            name = name.replace(f"{{{k}}}", v or "unknown")
        # Clean up any remaining placeholders
        name = re.sub(r"\{[^}]+\}", "unknown", name)
        name = re.sub(r"-+", "-", name).strip("-").lower()

        ips = sorted(data["ips"])
        ports = sorted(data["ports"])

        # Separate TCP and UDP
        tcp_ports = sorted(set(p for p, proto in ports if proto == "tcp"))
        udp_ports = sorted(set(p for p, proto in ports if proto == "udp"))

        applications.append({
            "name": name,
            "group_key": group_key,
            "labels": labels,
            "ips": ips,
            "ip_count": len(ips),
            "tcp_ports": tcp_ports,
            "udp_ports": udp_ports,
            "port_count": len(tcp_ports) + len(udp_ports),
            "workload_count": len(data["workloads"]),
            "workloads": sorted(set(data["workloads"]))[:20],
        })

    log.info("Built %d ZTNA application definitions", len(applications))
    return applications


# ---------------------------------------------------------------------------
# ZTNA Provider: Zscaler ZPA
# ---------------------------------------------------------------------------

class ZscalerProvider:
    name = "zscaler"

    def __init__(self):
        self.client_id = os.environ.get("ZPA_CLIENT_ID", "")
        self.client_secret = os.environ.get("ZPA_CLIENT_SECRET", "")
        self.customer_id = os.environ.get("ZPA_CUSTOMER_ID", "")
        self.vanity_domain = os.environ.get("ZPA_VANITY_DOMAIN", "")
        self.cloud = os.environ.get("ZPA_CLOUD", "PRODUCTION")
        self.connector_group_id = os.environ.get("ZPA_CONNECTOR_GROUP_ID", "")
        self.token = None
        self.base_url = "https://config.private.zscaler.com"

    def is_configured(self):
        return bool(self.client_id and self.client_secret and self.customer_id)

    def authenticate(self):
        if self.vanity_domain:
            url = f"https://{self.vanity_domain}.zslogin.net/oauth2/v1/token"
            resp = requests.post(url, data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": "https://api.zscaler.com",
            })
            resp.raise_for_status()
            self.token = resp.json()["access_token"]
            self.base_url = "https://api.zsapi.net"
        else:
            url = f"{self.base_url}/signin"
            resp = requests.post(url, json={
                "apiKey": self.client_id,
                "username": self.client_id,
                "password": self.client_secret,
            })
            resp.raise_for_status()
            self.token = resp.text.strip('"')

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def _api(self, method, path, json_data=None):
        url = f"{self.base_url}/zpa/mgmtconfig/v1/admin/customers/{self.customer_id}{path}"
        resp = requests.request(method, url, headers=self._headers(), json=json_data)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def list_apps(self):
        data = self._api("GET", "/application")
        return data.get("list", [])

    def create_app(self, app_def):
        tcp_ranges = []
        for p in app_def["tcp_ports"]:
            tcp_ranges.extend([str(p), str(p)])
        udp_ranges = []
        for p in app_def["udp_ports"]:
            udp_ranges.extend([str(p), str(p)])

        body = {
            "name": f"illumio-{app_def['name']}",
            "description": f"Synced from Illumio | {app_def['group_key']}",
            "domainNames": app_def["ips"],
            "tcpPortRanges": tcp_ranges or ["0", "0"],
            "udpPortRanges": udp_ranges,
            "enabled": True,
            "bypassType": "NEVER",
            "healthReporting": "ON_ACCESS",
            "icmpAccessType": "NONE",
        }

        if self.connector_group_id:
            body["serverGroups"] = [{"id": self.connector_group_id}]

        return self._api("POST", "/application", body)

    def update_app(self, app_id, app_def):
        tcp_ranges = []
        for p in app_def["tcp_ports"]:
            tcp_ranges.extend([str(p), str(p)])
        udp_ranges = []
        for p in app_def["udp_ports"]:
            udp_ranges.extend([str(p), str(p)])

        body = {
            "domainNames": app_def["ips"],
            "tcpPortRanges": tcp_ranges or ["0", "0"],
            "udpPortRanges": udp_ranges,
            "description": f"Synced from Illumio | {app_def['group_key']} | {datetime.now(timezone.utc).isoformat()}",
        }
        return self._api("PUT", f"/application/{app_id}", body)


# ---------------------------------------------------------------------------
# ZTNA Provider: Netskope NPA
# ---------------------------------------------------------------------------

class NetskopeProvider:
    name = "netskope"

    def __init__(self):
        self.tenant = os.environ.get("NETSKOPE_TENANT", "")
        self.api_token = os.environ.get("NETSKOPE_API_TOKEN", "")
        self.publisher_id = os.environ.get("NETSKOPE_PUBLISHER_ID", "")

    def is_configured(self):
        return bool(self.tenant and self.api_token)

    def authenticate(self):
        pass  # Token-based, no login needed

    def _url(self, path):
        return f"https://{self.tenant}.goskope.com{path}"

    def _headers(self):
        return {"Netskope-Api-Token": self.api_token, "Content-Type": "application/json"}

    def list_apps(self):
        resp = requests.get(self._url("/api/v2/steering/apps/private"), headers=self._headers())
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", data.get("private_apps", []))

    def create_app(self, app_def):
        protocols = []
        for p in app_def["tcp_ports"]:
            protocols.append({"port": str(p), "type": "tcp"})
        for p in app_def["udp_ports"]:
            protocols.append({"port": str(p), "type": "udp"})

        body = {
            "app_name": f"illumio-{app_def['name']}",
            "host": ", ".join(app_def["ips"]),
            "protocols": protocols or [{"port": "443", "type": "tcp"}],
            "use_publisher_dns": False,
            "clientless_access": False,
            "is_user_portal_app": False,
        }

        if self.publisher_id:
            body["publishers"] = [{"publisher_id": self.publisher_id}]

        resp = requests.post(self._url("/api/v2/steering/apps/private"),
                             headers=self._headers(), json=body)
        resp.raise_for_status()
        return resp.json()

    def update_app(self, app_id, app_def):
        protocols = []
        for p in app_def["tcp_ports"]:
            protocols.append({"port": str(p), "type": "tcp"})
        for p in app_def["udp_ports"]:
            protocols.append({"port": str(p), "type": "udp"})

        body = {
            "host": ", ".join(app_def["ips"]),
            "protocols": protocols or [{"port": "443", "type": "tcp"}],
        }

        resp = requests.put(self._url(f"/api/v2/steering/apps/private/{app_id}"),
                            headers=self._headers(), json=body)
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# ZTNA Provider: Cloudflare Access
# ---------------------------------------------------------------------------

class CloudflareProvider:
    name = "cloudflare"

    def __init__(self):
        self.api_token = os.environ.get("CF_API_TOKEN", "")
        self.account_id = os.environ.get("CF_ACCOUNT_ID", "")

    def is_configured(self):
        return bool(self.api_token and self.account_id)

    def authenticate(self):
        pass  # Token-based

    def _url(self, path):
        return f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}{path}"

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"}

    def list_apps(self):
        resp = requests.get(self._url("/access/apps"), headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("result", [])

    def create_app(self, app_def):
        destinations = []
        for ip in app_def["ips"]:
            cidr = f"{ip}/32" if "/" not in ip else ip
            for p in app_def["tcp_ports"]:
                destinations.append({"type": "private", "cidr": cidr, "l4_protocol": "tcp", "port_range": str(p)})
            for p in app_def["udp_ports"]:
                destinations.append({"type": "private", "cidr": cidr, "l4_protocol": "udp", "port_range": str(p)})

        body = {
            "name": f"illumio-{app_def['name']}",
            "type": "self_hosted",
            "domain": f"{app_def['name']}.internal",
            "destinations": destinations[:100],  # CF limit
            "session_duration": "24h",
        }

        resp = requests.post(self._url("/access/apps"), headers=self._headers(), json=body)
        resp.raise_for_status()
        return resp.json().get("result", {})

    def update_app(self, app_id, app_def):
        destinations = []
        for ip in app_def["ips"]:
            cidr = f"{ip}/32" if "/" not in ip else ip
            for p in app_def["tcp_ports"]:
                destinations.append({"type": "private", "cidr": cidr, "l4_protocol": "tcp", "port_range": str(p)})
            for p in app_def["udp_ports"]:
                destinations.append({"type": "private", "cidr": cidr, "l4_protocol": "udp", "port_range": str(p)})

        body = {"destinations": destinations[:100]}
        resp = requests.put(self._url(f"/access/apps/{app_id}"), headers=self._headers(), json=body)
        resp.raise_for_status()
        return resp.json().get("result", {})


# ---------------------------------------------------------------------------
# ZTNA Provider: Cisco Secure Access
# ---------------------------------------------------------------------------

class CiscoProvider:
    name = "cisco"

    def __init__(self):
        self.api_key = os.environ.get("CISCO_API_KEY", "")
        self.api_secret = os.environ.get("CISCO_API_SECRET", "")
        self.token = None

    def is_configured(self):
        return bool(self.api_key and self.api_secret)

    def authenticate(self):
        auth = b64encode(f"{self.api_key}:{self.api_secret}".encode()).decode()
        resp = requests.post("https://api.sse.cisco.com/auth/v2/token",
                             headers={"Authorization": f"Basic {auth}",
                                      "Content-Type": "application/x-www-form-urlencoded"},
                             data="grant_type=client_credentials")
        resp.raise_for_status()
        self.token = resp.json()["access_token"]

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def list_apps(self):
        resp = requests.get("https://api.sse.cisco.com/deployments/v2/privateresources",
                            headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("data", [])

    def create_app(self, app_def):
        protocol_ports = []
        for p in app_def["tcp_ports"]:
            protocol_ports.append({"protocol": "TCP", "ports": str(p)})
        for p in app_def["udp_ports"]:
            protocol_ports.append({"protocol": "UDP", "ports": str(p)})

        body = {
            "name": f"illumio-{app_def['name']}",
            "description": f"Synced from Illumio | {app_def['group_key']}",
            "accessTypes": ["networkAccess"],
            "resourceAddresses": {
                "destinationAddr": [f"{ip}/32" if "/" not in ip else ip for ip in app_def["ips"]],
                "protocolPorts": protocol_ports or [{"protocol": "TCP", "ports": "443"}],
            },
        }

        resp = requests.post("https://api.sse.cisco.com/deployments/v2/privateresources",
                             headers=self._headers(), json=body)
        resp.raise_for_status()
        return resp.json()

    def update_app(self, app_id, app_def):
        protocol_ports = []
        for p in app_def["tcp_ports"]:
            protocol_ports.append({"protocol": "TCP", "ports": str(p)})
        for p in app_def["udp_ports"]:
            protocol_ports.append({"protocol": "UDP", "ports": str(p)})

        body = {
            "resourceAddresses": {
                "destinationAddr": [f"{ip}/32" if "/" not in ip else ip for ip in app_def["ips"]],
                "protocolPorts": protocol_ports or [{"protocol": "TCP", "ports": "443"}],
            },
        }

        resp = requests.put(f"https://api.sse.cisco.com/deployments/v2/privateresources/{app_id}",
                            headers=self._headers(), json=body)
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

PROVIDERS = {
    "zscaler": ZscalerProvider,
    "zpa": ZscalerProvider,
    "netskope": NetskopeProvider,
    "npa": NetskopeProvider,
    "cloudflare": CloudflareProvider,
    "cf": CloudflareProvider,
    "cisco": CiscoProvider,
}


def get_provider():
    cls = PROVIDERS.get(ZTNA_PROVIDER)
    if not cls:
        return None
    return cls()


# ---------------------------------------------------------------------------
# Sync logic
# ---------------------------------------------------------------------------

def sync_applications(provider, applications):
    """Push application definitions to ZTNA platform."""
    results = []

    try:
        provider.authenticate()
    except Exception as e:
        log.error("ZTNA authentication failed: %s", e)
        return [{"name": "(auth)", "status": "error", "error": f"Authentication failed: {e}"}]

    # Get existing apps
    try:
        existing = provider.list_apps()
        existing_by_name = {}
        for app in existing:
            name = app.get("name", app.get("app_name", ""))
            app_id = app.get("id", app.get("app_id", ""))
            existing_by_name[name] = app_id
    except Exception as e:
        log.error("Failed to list existing apps: %s", e)
        existing_by_name = {}

    for app_def in applications:
        target_name = f"illumio-{app_def['name']}"
        try:
            if target_name in existing_by_name:
                provider.update_app(existing_by_name[target_name], app_def)
                results.append({"name": app_def["name"], "status": "updated", "ztna_name": target_name})
                log.info("Updated: %s", target_name)
            else:
                provider.create_app(app_def)
                results.append({"name": app_def["name"], "status": "created", "ztna_name": target_name})
                log.info("Created: %s", target_name)
        except Exception as e:
            log.error("Sync failed for %s: %s", app_def["name"], e)
            results.append({"name": app_def["name"], "status": "error", "error": str(e), "ztna_name": target_name})

    return results


# ---------------------------------------------------------------------------
# Scan orchestrator
# ---------------------------------------------------------------------------

def run_scan(pce, provider):
    applications = build_applications(pce)

    provider_status = "not configured"
    sync_results = []

    if provider and provider.is_configured():
        provider_status = "configured"
        if MODE == "sync":
            sync_results = sync_applications(provider, applications)
            synced = sum(1 for r in sync_results if r["status"] in ("created", "updated"))
            errors = sum(1 for r in sync_results if r["status"] == "error")
            provider_status = f"synced ({synced} ok, {errors} errors)" if sync_results else "synced"
    elif provider:
        provider_status = "incomplete config"

    summary = {
        "total_applications": len(applications),
        "total_ips": sum(a["ip_count"] for a in applications),
        "total_ports": sum(a["port_count"] for a in applications),
        "total_workloads": sum(a["workload_count"] for a in applications),
        "provider": ZTNA_PROVIDER,
        "mode": MODE,
        "group_by": GROUP_BY,
        "naming_pattern": NAMING_PATTERN,
    }

    with state_lock:
        state["applications"] = applications
        state["summary"] = summary
        state["sync_results"] = sync_results
        state["provider_status"] = provider_status
        state["last_scan"] = datetime.now(timezone.utc).isoformat()
        state["scan_count"] += 1
        state["error"] = None


# ---------------------------------------------------------------------------
# Poller
# ---------------------------------------------------------------------------

def poller_loop(pce, provider):
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
            run_scan(pce, provider)
            with state_lock:
                state["scanning"] = False
            log.info("Scan complete: %d apps, provider=%s, mode=%s",
                     state["summary"]["total_applications"], ZTNA_PROVIDER, MODE)
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
<title>ZTNA Sync</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}
</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,sans-serif}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#11111b}::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.ip-tag{display:inline-block;font-family:monospace;font-size:0.75rem;background:#313244;color:#a6e3a1;padding:2px 6px;border-radius:3px;margin:1px}
.port-tag{display:inline-block;font-size:0.75rem;background:rgba(137,180,250,0.15);color:#93c5fd;padding:2px 6px;border-radius:3px;margin:1px;border:1px solid rgba(137,180,250,0.2)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}.scanning{animation:pulse 2s infinite}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-6">

<div class="flex items-center justify-between mb-8">
  <div>
    <h1 class="text-2xl font-bold text-white flex items-center gap-2">
      <svg class="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
      ZTNA Sync
    </h1>
    <div class="flex items-center gap-2 mt-1">
      <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
      <span id="status-text" class="text-sm text-gray-400">Loading...</span>
    </div>
  </div>
  <div class="flex items-center gap-3">
    <span id="provider-badge" class="text-xs px-3 py-1 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-medium"></span>
    <span id="mode-badge" class="text-xs px-3 py-1 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30 font-medium"></span>
    <button onclick="triggerScan()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Scan Now</button>
  </div>
</div>

<div class="bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-3 mb-6 text-sm text-amber-300">
  <strong>Untested:</strong> This plugin has not been validated against live ZTNA platforms. Verify in analytics mode first.
</div>

<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-apps" class="text-3xl font-bold text-blue-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Applications</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-ips" class="text-3xl font-bold text-green-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Total IPs</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-ports" class="text-3xl font-bold text-purple-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Total Ports</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-wl" class="text-3xl font-bold text-yellow-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Workloads</div>
  </div>
</div>

<div class="bg-dark-800 rounded-xl border border-gray-700 mb-6">
  <div class="p-4 border-b border-gray-700 flex items-center gap-3">
    <h2 class="text-white font-semibold">ZTNA Application Definitions</h2>
    <input id="search" type="text" placeholder="Search..." oninput="renderApps()"
           class="ml-auto bg-dark-900 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-300 w-56">
    <button onclick="copyJSON()" class="text-xs bg-dark-700 hover:bg-dark-900 text-gray-300 px-3 py-1.5 rounded border border-gray-600">Copy JSON</button>
  </div>
  <div class="overflow-x-auto max-h-[600px] overflow-y-auto">
    <table class="w-full text-sm">
      <thead class="sticky top-0 bg-dark-800 z-10">
        <tr class="text-left text-xs text-gray-400 uppercase">
          <th class="px-4 py-3">Application</th>
          <th class="px-4 py-3">Labels</th>
          <th class="px-4 py-3">IPs</th>
          <th class="px-4 py-3">Ports</th>
          <th class="px-4 py-3">Workloads</th>
          <th class="px-4 py-3" id="sync-col-header" style="display:none">Sync Status</th>
        </tr>
      </thead>
      <tbody id="app-table"></tbody>
    </table>
  </div>
</div>

</div>
<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\/plugins\/[^/]+\/ui/);return m?m[0]:''})();
let currentData=null;

function formatNum(n){if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toLocaleString()}
function timeAgo(ts){if(!ts)return'—';const d=(Date.now()-new Date(ts).getTime())/1000;if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago'}

function update(d){
  currentData=d;
  const dot=document.getElementById('status-dot');
  const txt=document.getElementById('status-text');
  if(d.scanning){dot.className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning';txt.textContent='Scanning...';}
  else if(d.error){dot.className='w-2.5 h-2.5 rounded-full bg-red-500';txt.textContent='Error: '+d.error;}
  else if(d.last_scan){dot.className='w-2.5 h-2.5 rounded-full bg-green-500';txt.textContent=d.provider_status+' | Last scan: '+timeAgo(d.last_scan);}
  else{dot.className='w-2.5 h-2.5 rounded-full bg-gray-500';txt.textContent='Not scanned yet';}

  document.getElementById('provider-badge').textContent=d.provider||'none';
  document.getElementById('mode-badge').textContent=d.mode||'analytics';

  const s=d.summary||{};
  document.getElementById('stat-apps').textContent=formatNum(s.total_applications||0);
  document.getElementById('stat-ips').textContent=formatNum(s.total_ips||0);
  document.getElementById('stat-ports').textContent=formatNum(s.total_ports||0);
  document.getElementById('stat-wl').textContent=formatNum(s.total_workloads||0);

  if(d.mode==='sync')document.getElementById('sync-col-header').style.display='';
  renderApps();
}

function renderApps(){
  if(!currentData)return;
  const q=(document.getElementById('search').value||'').toLowerCase();
  const apps=currentData.applications||[];
  const syncMap={};
  for(const r of(currentData.sync_results||[]))syncMap[r.name]=r;

  const filtered=q?apps.filter(a=>(a.name+' '+JSON.stringify(a.labels)+' '+a.ips.join(' ')).toLowerCase().includes(q)):apps;

  document.getElementById('app-table').innerHTML=filtered.map(a=>{
    const labels=Object.entries(a.labels).map(([k,v])=>`<span class="text-xs bg-violet-500/15 text-violet-300 rounded px-1.5 py-0.5 mr-1 border border-violet-500/20">${k}:${v}</span>`).join('');
    const ips=a.ips.slice(0,5).map(ip=>`<span class="ip-tag">${ip}</span>`).join('')+(a.ip_count>5?`<span class="text-xs text-gray-500 ml-1">+${a.ip_count-5}</span>`:'');
    const ports=[...a.tcp_ports.map(p=>`<span class="port-tag">${p}/tcp</span>`),...a.udp_ports.map(p=>`<span class="port-tag">${p}/udp</span>`)].join('')||'<span class="text-gray-600">none</span>';
    const sr=syncMap[a.name];
    const syncCell=currentData.mode==='sync'?`<td class="px-4 py-2.5">${sr?`<span class="text-xs ${sr.status==='error'?'bg-red-500/15 text-red-300':'bg-green-500/15 text-green-300'} rounded px-2 py-0.5">${sr.status}</span>`:'—'}</td>`:'';
    return`<tr class="border-b border-gray-700/50 hover:bg-dark-900">
      <td class="px-4 py-2.5"><span class="text-white font-medium">${a.name}</span><br><span class="text-xs text-gray-500">${a.workload_count} workloads</span></td>
      <td class="px-4 py-2.5">${labels}</td>
      <td class="px-4 py-2.5">${ips}</td>
      <td class="px-4 py-2.5">${ports}</td>
      <td class="px-4 py-2.5 text-gray-400">${a.workload_count}</td>
      ${syncCell}
    </tr>`;
  }).join('')||'<tr><td colspan="6" class="px-4 py-8 text-center text-gray-500">No applications. Run a scan first.</td></tr>';
}

function copyJSON(){
  if(!currentData||!currentData.applications)return;
  const exp={provider:currentData.provider,mode:currentData.mode,generated:currentData.last_scan,applications:currentData.applications};
  const ta=document.createElement('textarea');ta.value=JSON.stringify(exp,null,2);ta.style.position='fixed';ta.style.left='-9999px';
  document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);
  alert('JSON copied ('+currentData.applications.length+' applications)');
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
    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send(self, code, body, ct="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/":
            self._send(200, DASHBOARD_HTML, "text/html")
        elif path == "/healthz":
            self._send(200, json.dumps({"status": "healthy"}))
        elif path == "/api/state":
            with state_lock:
                self._send(200, json.dumps(state, default=str))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        if path == "/api/scan":
            with state_lock:
                state["scan_requested"] = True
            self._send(200, json.dumps({"status": "scan_requested"}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("ZTNA Sync starting...")
    log.info("Config: provider=%s, mode=%s, group_by=%s, interval=%ds",
             ZTNA_PROVIDER, MODE, GROUP_BY, SCAN_INTERVAL)

    pce = get_pce()
    provider = get_provider()

    if provider and provider.is_configured():
        log.info("ZTNA provider %s configured", ZTNA_PROVIDER)
    elif provider:
        log.warning("ZTNA provider %s partially configured — running in analytics only", ZTNA_PROVIDER)
    else:
        log.warning("No ZTNA provider configured — analytics mode only")

    poller = threading.Thread(target=poller_loop, args=(pce, provider), daemon=True)
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
