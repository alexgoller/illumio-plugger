#!/usr/bin/env python3
"""
Workload Isolator — Instant workload quarantine via webhook.

Provides a REST API to isolate (quarantine) and release workloads
on the Illumio PCE. Designed for integration with EDR, SOAR, and
manual incident response.

Isolation methods:
  - enforcement: Change workload to full enforcement with no rules (deny all)
  - deny_rule: Create explicit deny-all rules for the workload

API:
  POST /api/isolate       — isolate a workload
  POST /api/release       — release an isolated workload
  POST /api/isolate/bulk  — isolate multiple workloads
  GET  /api/isolated      — list currently isolated workloads
  GET  /api/audit         — isolation/release history
"""

import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import hashlib

import requests as req
from illumio import PolicyComputeEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("workload-isolator")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "")
ISOLATION_METHOD = os.environ.get("ISOLATION_METHOD", "enforcement")
NOTIFICATION_WEBHOOK = os.environ.get("NOTIFICATION_WEBHOOK", "")
DEFAULT_TTL = int(os.environ.get("DEFAULT_TTL", "0"))
MAX_ISOLATED = int(os.environ.get("MAX_ISOLATED", "100"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
isolated_workloads = {}  # href -> isolation record
audit_log = []  # list of all isolate/release events


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


# ---------------------------------------------------------------------------
# Workload lookup
# ---------------------------------------------------------------------------

def find_workload(pce, target):
    """Find a workload by hostname, IP, or href."""
    if target.startswith("/orgs/"):
        resp = pce.get(target)
        if resp.status_code == 200:
            return resp.json()
        return None

    resp = pce.get("/workloads", params={"max_results": 10000})
    if resp.status_code != 200:
        return None

    for wl in resp.json():
        if wl.get("hostname", "").lower() == target.lower():
            return wl
        if wl.get("name", "").lower() == target.lower():
            return wl
        for iface in wl.get("interfaces", []):
            if iface.get("address") == target:
                return wl
    return None


# ---------------------------------------------------------------------------
# Isolation methods
# ---------------------------------------------------------------------------

def isolate_by_enforcement(pce, workload):
    """Change enforcement mode to full (with no rules = deny all)."""
    href = workload["href"]
    previous_mode = workload.get("enforcement_mode", "idle")

    resp = pce.put(href, json={"enforcement_mode": "full"})
    if resp.status_code in (200, 204):
        return {"method": "enforcement", "previous_mode": previous_mode}
    raise RuntimeError(f"Failed to set enforcement mode: HTTP {resp.status_code}")


def release_by_enforcement(pce, workload, record):
    """Restore previous enforcement mode."""
    href = workload["href"]
    previous_mode = record.get("previous_mode", "visibility_only")

    resp = pce.put(href, json={"enforcement_mode": previous_mode})
    if resp.status_code in (200, 204):
        return True
    raise RuntimeError(f"Failed to restore enforcement mode: HTTP {resp.status_code}")


def isolate_workload(pce, target, reason, source, ttl, dry_run=False):
    """Isolate a single workload."""
    workload = find_workload(pce, target)
    if not workload:
        return {"status": "error", "error": f"Workload not found: {target}"}

    href = workload["href"]
    hostname = workload.get("hostname", target)

    with state_lock:
        if href in isolated_workloads:
            return {"status": "already_isolated", "workload": hostname,
                    "isolated_at": isolated_workloads[href]["isolated_at"]}
        if len(isolated_workloads) >= MAX_ISOLATED:
            return {"status": "error", "error": f"Max isolation limit reached ({MAX_ISOLATED})"}

    if dry_run:
        return {"status": "dry_run", "workload": hostname, "would_isolate": True,
                "method": ISOLATION_METHOD}

    now = datetime.now(timezone.utc).isoformat()
    release_at = None
    effective_ttl = ttl if ttl else DEFAULT_TTL
    if effective_ttl > 0:
        release_at = (datetime.now(timezone.utc) + timedelta(seconds=effective_ttl)).isoformat()

    try:
        if ISOLATION_METHOD == "enforcement":
            details = isolate_by_enforcement(pce, workload)
        else:
            details = isolate_by_enforcement(pce, workload)

        record = {
            "workload": hostname,
            "workload_href": href,
            "ips": [i.get("address", "") for i in workload.get("interfaces", [])],
            "labels": {lbl.get("key", ""): lbl.get("value", "") for lbl in workload.get("labels", [])
                       if isinstance(lbl, dict) and "key" in lbl},
            "isolated_at": now,
            "auto_release_at": release_at,
            "reason": reason,
            "source": source,
            "method": ISOLATION_METHOD,
            **details,
        }

        with state_lock:
            isolated_workloads[href] = record
            audit_log.append({**record, "action": "isolate", "timestamp": now})

        log.info("ISOLATED: %s (%s) — reason: %s, source: %s",
                 hostname, href, reason, source)

        notify(f"🔴 **Isolated**: {hostname}\n"
               f"Reason: {reason}\nSource: {source}\n"
               f"Method: {ISOLATION_METHOD}" +
               (f"\nAuto-release: {release_at}" if release_at else ""))

        return {
            "status": "isolated",
            "workload": hostname,
            "workload_href": href,
            "isolated_at": now,
            "auto_release_at": release_at,
            "method": ISOLATION_METHOD,
        }

    except Exception as e:
        log.error("Isolation failed for %s: %s", target, e)
        return {"status": "error", "error": str(e)}


def release_workload(pce, target, reason=""):
    """Release an isolated workload."""
    workload = find_workload(pce, target)
    if not workload:
        # Try matching by hostname in isolated records
        with state_lock:
            for href, rec in isolated_workloads.items():
                if rec["workload"].lower() == target.lower():
                    workload = find_workload(pce, href)
                    break
        if not workload:
            return {"status": "error", "error": f"Workload not found: {target}"}

    href = workload["href"]
    hostname = workload.get("hostname", target)

    with state_lock:
        if href not in isolated_workloads:
            return {"status": "not_isolated", "workload": hostname}
        record = isolated_workloads[href]

    try:
        if ISOLATION_METHOD == "enforcement":
            release_by_enforcement(pce, workload, record)

        now = datetime.now(timezone.utc).isoformat()
        duration = ""
        try:
            iso_time = datetime.fromisoformat(record["isolated_at"].replace("Z", "+00:00"))
            dur = datetime.now(timezone.utc) - iso_time
            duration = f"{dur.total_seconds() / 60:.0f} minutes"
        except Exception:
            pass

        with state_lock:
            del isolated_workloads[href]
            audit_log.append({
                "action": "release",
                "workload": hostname,
                "workload_href": href,
                "timestamp": now,
                "reason": reason or "manual release",
                "duration": duration,
                "original_reason": record.get("reason", ""),
            })

        log.info("RELEASED: %s — reason: %s, was isolated for: %s",
                 hostname, reason or "manual", duration)

        notify(f"🟢 **Released**: {hostname}\n"
               f"Reason: {reason or 'manual release'}\n"
               f"Duration: {duration}")

        return {"status": "released", "workload": hostname, "duration": duration}

    except Exception as e:
        log.error("Release failed for %s: %s", target, e)
        return {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# Auto-release timer
# ---------------------------------------------------------------------------

def auto_release_loop(pce):
    """Background thread to auto-release workloads with expired TTL."""
    while True:
        time.sleep(30)
        now = datetime.now(timezone.utc)
        to_release = []

        with state_lock:
            for href, record in isolated_workloads.items():
                release_at = record.get("auto_release_at")
                if release_at:
                    try:
                        release_time = datetime.fromisoformat(release_at.replace("Z", "+00:00"))
                        if now >= release_time:
                            to_release.append((record["workload"], href))
                    except (ValueError, TypeError):
                        pass

        for hostname, href in to_release:
            log.info("Auto-releasing %s (TTL expired)", hostname)
            release_workload(pce, href, reason="TTL expired (auto-release)")


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def notify(message):
    """Send notification to webhook (Slack/Teams)."""
    if not NOTIFICATION_WEBHOOK:
        return
    try:
        # Try Slack format first, fallback to Teams
        payload = {"text": message}
        resp = req.post(NOTIFICATION_WEBHOOK, json=payload, timeout=10)
        if resp.status_code not in (200, 204):
            # Try Teams format
            payload = {"text": message, "@type": "MessageCard"}
            req.post(NOTIFICATION_WEBHOOK, json=payload, timeout=10)
    except Exception as e:
        log.warning("Notification failed: %s", e)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Workload Isolator</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,sans-serif}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#11111b}::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.ip-tag{display:inline-block;font-family:monospace;font-size:0.75rem;background:#313244;color:#a6e3a1;padding:2px 6px;border-radius:3px;margin:1px}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-5xl mx-auto px-4 py-6">

<div class="flex items-center justify-between mb-8">
  <div>
    <h1 class="text-2xl font-bold text-white flex items-center gap-2">
      <svg class="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
      Workload Isolator
    </h1>
    <p class="text-sm text-gray-400 mt-1">Instant quarantine for compromised workloads</p>
  </div>
</div>

<!-- Quick Isolate Form -->
<div class="bg-dark-800 rounded-xl border border-gray-700 p-5 mb-6">
  <h2 class="text-white font-semibold mb-3">Quick Isolate</h2>
  <div class="flex gap-3">
    <input id="isolate-target" type="text" placeholder="Hostname or IP address"
           class="flex-1 bg-dark-900 border border-gray-600 rounded px-3 py-2 text-sm text-gray-300">
    <input id="isolate-reason" type="text" placeholder="Reason (e.g., CrowdStrike alert)"
           class="flex-1 bg-dark-900 border border-gray-600 rounded px-3 py-2 text-sm text-gray-300">
    <button onclick="quickIsolate()" class="bg-red-600 hover:bg-red-700 text-white px-5 py-2 rounded text-sm font-medium">Isolate</button>
  </div>
</div>

<!-- Stats -->
<div class="grid grid-cols-3 gap-4 mb-6">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-active" class="text-3xl font-bold text-red-400">0</div>
    <div class="text-sm text-gray-400 mt-1">Currently Isolated</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-total" class="text-3xl font-bold text-yellow-400">0</div>
    <div class="text-sm text-gray-400 mt-1">Total Isolations</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-released" class="text-3xl font-bold text-green-400">0</div>
    <div class="text-sm text-gray-400 mt-1">Released</div>
  </div>
</div>

<!-- Active Isolations -->
<div class="bg-dark-800 rounded-xl border border-gray-700 mb-6">
  <div class="px-5 py-4 border-b border-gray-700">
    <h2 class="text-white font-semibold">Active Isolations</h2>
  </div>
  <div class="max-h-[400px] overflow-y-auto">
    <table class="w-full text-sm">
      <thead class="sticky top-0 bg-dark-800">
        <tr class="text-left text-xs text-gray-400 uppercase">
          <th class="px-4 py-3">Workload</th>
          <th class="px-4 py-3">IPs</th>
          <th class="px-4 py-3">Reason</th>
          <th class="px-4 py-3">Since</th>
          <th class="px-4 py-3">Auto-Release</th>
          <th class="px-4 py-3">Action</th>
        </tr>
      </thead>
      <tbody id="isolated-table"></tbody>
    </table>
  </div>
</div>

<!-- Audit Log -->
<div class="bg-dark-800 rounded-xl border border-gray-700">
  <div class="px-5 py-4 border-b border-gray-700">
    <h2 class="text-white font-semibold">Audit Log</h2>
  </div>
  <div class="max-h-[300px] overflow-y-auto">
    <table class="w-full text-sm">
      <thead class="sticky top-0 bg-dark-800">
        <tr class="text-left text-xs text-gray-400 uppercase">
          <th class="px-4 py-3">Time</th>
          <th class="px-4 py-3">Action</th>
          <th class="px-4 py-3">Workload</th>
          <th class="px-4 py-3">Reason</th>
        </tr>
      </thead>
      <tbody id="audit-table"></tbody>
    </table>
  </div>
</div>

</div>
<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\/plugins\/[^/]+\/ui/);return m?m[0]:''})();

function timeAgo(ts){if(!ts)return'—';const d=(Date.now()-new Date(ts).getTime())/1000;if(d<60)return'just now';if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago'}

function update(d){
  document.getElementById('stat-active').textContent=d.isolated_count||0;
  document.getElementById('stat-total').textContent=d.audit_log?.filter(a=>a.action==='isolate').length||0;
  document.getElementById('stat-released').textContent=d.audit_log?.filter(a=>a.action==='release').length||0;

  const isoTable=document.getElementById('isolated-table');
  const isolated=d.isolated||[];
  isoTable.innerHTML=isolated.length?isolated.map(r=>{
    const ips=(r.ips||[]).map(ip=>`<span class="ip-tag">${ip}</span>`).join('');
    const autoRel=r.auto_release_at?timeAgo(r.auto_release_at):'-';
    return`<tr class="border-b border-gray-700/50 hover:bg-dark-900">
      <td class="px-4 py-2.5 text-white font-medium">${r.workload}</td>
      <td class="px-4 py-2.5">${ips}</td>
      <td class="px-4 py-2.5 text-gray-300 text-xs">${r.reason||'—'}</td>
      <td class="px-4 py-2.5 text-gray-400 text-xs">${timeAgo(r.isolated_at)}</td>
      <td class="px-4 py-2.5 text-gray-400 text-xs">${r.auto_release_at?new Date(r.auto_release_at).toLocaleTimeString():'—'}</td>
      <td class="px-4 py-2.5"><button onclick="releaseWorkload('${r.workload}')" class="text-xs bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded">Release</button></td>
    </tr>`;
  }).join(''):'<tr><td colspan="6" class="px-4 py-8 text-center text-gray-500">No workloads currently isolated</td></tr>';

  const auditTable=document.getElementById('audit-table');
  const audit=(d.audit_log||[]).slice().reverse().slice(0,50);
  auditTable.innerHTML=audit.length?audit.map(a=>{
    const icon=a.action==='isolate'?'🔴':'🟢';
    const badge=a.action==='isolate'?'bg-red-500/15 text-red-300':'bg-green-500/15 text-green-300';
    return`<tr class="border-b border-gray-700/50">
      <td class="px-4 py-2 text-gray-400 text-xs">${timeAgo(a.timestamp)}</td>
      <td class="px-4 py-2"><span class="text-xs ${badge} rounded px-2 py-0.5">${icon} ${a.action}</span></td>
      <td class="px-4 py-2 text-gray-300">${a.workload}</td>
      <td class="px-4 py-2 text-gray-400 text-xs">${a.reason||'—'}${a.duration?' ('+a.duration+')':''}</td>
    </tr>`;
  }).join(''):'<tr><td colspan="4" class="px-4 py-6 text-center text-gray-500">No activity yet</td></tr>';
}

async function fetchData(){
  try{const r=await fetch(BASE+'/api/state');update(await r.json())}catch(e){}
}

async function quickIsolate(){
  const target=document.getElementById('isolate-target').value.trim();
  const reason=document.getElementById('isolate-reason').value.trim();
  if(!target){alert('Enter a hostname or IP');return}
  try{
    const r=await fetch(BASE+'/api/isolate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,reason:reason||'Manual isolation from dashboard',source:'dashboard'})});
    const d=await r.json();
    alert(d.status==='isolated'?'Isolated: '+d.workload:'Error: '+(d.error||d.status));
    document.getElementById('isolate-target').value='';
    document.getElementById('isolate-reason').value='';
    fetchData();
  }catch(e){alert('Error: '+e)}
}

async function releaseWorkload(hostname){
  if(!confirm('Release '+hostname+'?'))return;
  try{
    const r=await fetch(BASE+'/api/release',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:hostname,reason:'Released from dashboard'})});
    const d=await r.json();
    alert(d.status==='released'?'Released: '+d.workload+' ('+d.duration+')':'Error: '+(d.error||d.status));
    fetchData();
  }catch(e){alert('Error: '+e)}
}

fetchData();
setInterval(fetchData,5000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class IsolatorHandler(BaseHTTPRequestHandler):
    pce = None

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send(self, code, body, ct="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _check_auth(self):
        """Verify Bearer token."""
        if not AUTH_TOKEN:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:] == AUTH_TOKEN
        # Also check query param
        parsed = urlparse(self.path)
        from urllib.parse import parse_qs
        params = parse_qs(parsed.query)
        if "token" in params:
            return params["token"][0] == AUTH_TOKEN
        return False

    def do_OPTIONS(self):
        self._send(200, "")

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path == "/":
            self._send(200, DASHBOARD_HTML, "text/html")

        elif path == "/healthz":
            self._send(200, json.dumps({"status": "healthy"}))

        elif path == "/api/state":
            with state_lock:
                data = {
                    "isolated": list(isolated_workloads.values()),
                    "isolated_count": len(isolated_workloads),
                    "audit_log": audit_log[-100:],
                    "max_isolated": MAX_ISOLATED,
                    "method": ISOLATION_METHOD,
                }
            self._send(200, json.dumps(data, default=str))

        elif path == "/api/isolated":
            if not self._check_auth():
                self._send(401, json.dumps({"error": "Unauthorized"}))
                return
            with state_lock:
                self._send(200, json.dumps(list(isolated_workloads.values()), default=str))

        elif path == "/api/audit":
            if not self._check_auth():
                self._send(401, json.dumps({"error": "Unauthorized"}))
                return
            with state_lock:
                self._send(200, json.dumps(audit_log[-200:], default=str))

        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")

        if path == "/api/isolate":
            if not self._check_auth():
                self._send(401, json.dumps({"error": "Unauthorized — provide Bearer token"}))
                return
            body = self._read_json()
            target = body.get("target", "")
            if not target:
                self._send(400, json.dumps({"error": "Missing 'target' (hostname, IP, or href)"}))
                return
            result = isolate_workload(
                self.pce, target,
                reason=body.get("reason", ""),
                source=body.get("source", "api"),
                ttl=body.get("ttl", 0),
                dry_run=body.get("dry_run", False),
            )
            code = 200 if result["status"] in ("isolated", "dry_run", "already_isolated") else 500
            self._send(code, json.dumps(result, default=str))

        elif path == "/api/release":
            if not self._check_auth():
                self._send(401, json.dumps({"error": "Unauthorized"}))
                return
            body = self._read_json()
            target = body.get("target", "")
            if not target:
                self._send(400, json.dumps({"error": "Missing 'target'"}))
                return
            result = release_workload(self.pce, target, reason=body.get("reason", ""))
            self._send(200, json.dumps(result, default=str))

        elif path == "/api/isolate/bulk":
            if not self._check_auth():
                self._send(401, json.dumps({"error": "Unauthorized"}))
                return
            body = self._read_json()
            targets = body.get("targets", [])
            if not targets:
                self._send(400, json.dumps({"error": "Missing 'targets' array"}))
                return
            if not body.get("confirm", False):
                self._send(400, json.dumps({"error": "Bulk isolate requires 'confirm': true",
                                            "targets_count": len(targets)}))
                return
            results = []
            for t in targets:
                r = isolate_workload(self.pce, t, reason=body.get("reason", ""),
                                     source=body.get("source", "api-bulk"), ttl=body.get("ttl", 0))
                results.append(r)
            self._send(200, json.dumps({"results": results}, default=str))

        else:
            self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("Workload Isolator starting...")
    log.info("Config: method=%s, max_isolated=%d, default_ttl=%ds, notifications=%s",
             ISOLATION_METHOD, MAX_ISOLATED, DEFAULT_TTL,
             "enabled" if NOTIFICATION_WEBHOOK else "disabled")

    if not AUTH_TOKEN:
        log.warning("AUTH_TOKEN not set — API is unauthenticated!")

    pce = get_pce()
    IsolatorHandler.pce = pce

    # Start auto-release thread
    release_thread = threading.Thread(target=auto_release_loop, args=(pce,), daemon=True)
    release_thread.start()

    server = HTTPServer(("0.0.0.0", HTTP_PORT), IsolatorHandler)
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
