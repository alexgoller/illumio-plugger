#!/usr/bin/env python3
"""
palo-alto-dag-sync — Sync Illumio workload labels to Palo Alto Dynamic Address Groups.

Polls PCE workloads, maps labels to PAN-OS tags, and registers IP-to-tag
mappings via the PAN-OS XML API. Palo Alto DAGs then dynamically include
workloads based on these tags.

Flow: PCE workloads → extract IPs + labels → build tags → push to PAN-OS
"""

import json
import logging
import os
import signal
import ssl
import threading
import time
import urllib.request
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from xml.etree import ElementTree as ET

from illumio import PolicyComputeEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("palo_alto_dag_sync")

state_lock = threading.Lock()
sync_state = {
    "last_sync": None,
    "sync_count": 0,
    "error": None,
    "workloads_synced": 0,
    "tags_registered": 0,
    "ips_registered": 0,
    "tag_summary": {},      # tag -> count of IPs
    "sync_history": [],     # last 20 syncs
    "palo_status": "unknown",
}

label_cache = {}


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
    pce.set_tls_settings(verify=False)
    return pce


def fetch_labels(pce):
    global label_cache
    try:
        resp = pce.get("/labels")
        if resp.status_code == 200:
            for lbl in resp.json():
                href = lbl.get("href", "")
                if href:
                    label_cache[href] = {"key": lbl.get("key", ""), "value": lbl.get("value", "")}
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


def build_tags(labels):
    """Build Palo Alto tags from Illumio labels.

    Tag format is configurable via TAG_PREFIX and TAG_FORMAT env vars.
    Default: illumio-{key}-{value} (e.g., illumio-app-ordering, illumio-env-prod)
    """
    prefix = os.environ.get("TAG_PREFIX", "illumio")
    fmt = os.environ.get("TAG_FORMAT", "{prefix}-{key}-{value}")
    label_keys = os.environ.get("SYNC_LABELS", "role,app,env,loc").split(",")

    tags = []
    for key in label_keys:
        key = key.strip()
        value = labels.get(key, "")
        if value:
            tag = fmt.format(prefix=prefix, key=key, value=value)
            # PAN-OS tag restrictions: max 127 chars, no spaces
            tag = tag.replace(" ", "-").replace("/", "-")[:127]
            tags.append(tag)
    return tags


# ============================================================
# PAN-OS XML API
# ============================================================

def panos_api_call(action, cmd=None, extra_params=None):
    """Make a PAN-OS XML API call."""
    host = os.environ.get("PALO_HOST", "")
    api_key = os.environ.get("PALO_API_KEY", "")

    if not host or not api_key:
        return None, "PALO_HOST and PALO_API_KEY not configured"

    params = {
        "type": action,
        "key": api_key,
    }
    if cmd:
        params["cmd"] = cmd
    if extra_params:
        params.update(extra_params)

    url = f"https://{host}/api/?{urllib.parse.urlencode(params)}"

    ctx = ssl.create_default_context()
    skip_tls = os.environ.get("PALO_TLS_SKIP_VERIFY", "true").lower() in ("true", "1")
    if skip_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        body = resp.read().decode()
        root = ET.fromstring(body)
        status = root.attrib.get("status", "")
        return root, None if status == "success" else f"PAN-OS error: {status}"
    except Exception as e:
        return None, str(e)


def panos_register_ips(ip_tag_map):
    """Register IP-to-tag mappings via PAN-OS User-ID XML API.

    ip_tag_map: {ip: [tag1, tag2, ...]}
    """
    if not ip_tag_map:
        return 0, None

    # Build the XML payload for User-ID tag registration
    uid_entries = []
    for ip, tags in ip_tag_map.items():
        for tag in tags:
            uid_entries.append(f'<entry ip="{ip}" persistent="1"><tag><member>{tag}</member></tag></entry>')

    # PAN-OS has a limit per request, batch in chunks of 500
    total_registered = 0
    batch_size = 500
    for i in range(0, len(uid_entries), batch_size):
        batch = uid_entries[i:i + batch_size]
        payload = f'<uid-message><type>update</type><payload><register>{"".join(batch)}</register></payload></uid-message>'

        root, err = panos_api_call("user-id", extra_params={"cmd": payload})
        if err:
            return total_registered, err
        total_registered += len(batch)

    return total_registered, None


def panos_unregister_ips(ip_tag_map):
    """Unregister IP-to-tag mappings."""
    if not ip_tag_map:
        return 0, None

    uid_entries = []
    for ip, tags in ip_tag_map.items():
        for tag in tags:
            uid_entries.append(f'<entry ip="{ip}"><tag><member>{tag}</member></tag></entry>')

    payload = f'<uid-message><type>update</type><payload><unregister>{"".join(uid_entries)}</unregister></payload></uid-message>'
    root, err = panos_api_call("user-id", extra_params={"cmd": payload})
    if err:
        return 0, err
    return len(uid_entries), None


def panos_check_health():
    """Check PAN-OS API connectivity."""
    root, err = panos_api_call("op", cmd="<show><system><info></info></system></show>")
    if err:
        return False, err
    return True, None


# ============================================================
# Sync Logic
# ============================================================

def run_sync(pce):
    """Full sync cycle: fetch PCE workloads, build tags, push to PAN-OS."""
    if not label_cache:
        fetch_labels(pce)

    palo_host = os.environ.get("PALO_HOST", "")
    dry_run = not palo_host

    log.info("Starting sync%s...", " (dry-run, no PALO_HOST)" if dry_run else "")

    if not dry_run:
        healthy, err = panos_check_health()
        with state_lock:
            sync_state["palo_status"] = "connected" if healthy else f"error: {err}"
        if not healthy:
            log.error("PAN-OS not reachable: %s", err)
            with state_lock:
                sync_state["error"] = f"PAN-OS: {err}"
            return
    else:
        with state_lock:
            sync_state["palo_status"] = "dry-run (no PALO_HOST)"

    # Fetch workloads
    try:
        resp = pce.get("/workloads", params={"max_results": 10000})
        workloads = resp.json() if resp.status_code == 200 else []
    except Exception as e:
        log.error("Failed to fetch workloads: %s", e)
        with state_lock:
            sync_state["error"] = str(e)
        return

    if not isinstance(workloads, list):
        workloads = []

    # Build IP-to-tag map
    ip_tag_map = {}
    tag_counts = defaultdict(int)
    synced = 0

    for wl in workloads:
        if not wl.get("online", False):
            continue

        labels = resolve_labels(wl)
        tags = build_tags(labels)
        if not tags:
            continue

        # Get IPs
        interfaces = wl.get("interfaces", [])
        for iface in interfaces:
            ip = iface.get("address", "")
            if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                ip_tag_map[ip] = tags
                for tag in tags:
                    tag_counts[tag] += 1
                synced += 1

    log.info("Built %d IP-to-tag mappings from %d workloads (%d unique tags)",
             len(ip_tag_map), synced, len(tag_counts))

    # Push to PAN-OS (skip in dry-run)
    registered = 0
    if not dry_run:
        registered, err = panos_register_ips(ip_tag_map)
        if err:
            log.error("Registration failed: %s", err)
            with state_lock:
                sync_state["error"] = err
            return
        log.info("Registered %d IP-tag entries on PAN-OS", registered)
    else:
        registered = len(ip_tag_map)
        log.info("Dry-run: would register %d IP-tag entries", registered)

    now = datetime.now(timezone.utc).isoformat()
    sync_entry = {
        "timestamp": now,
        "workloads": synced,
        "ips": len(ip_tag_map),
        "tags": len(tag_counts),
        "registered": registered,
        "error": None,
    }

    with state_lock:
        sync_state["last_sync"] = now
        sync_state["sync_count"] += 1
        sync_state["workloads_synced"] = synced
        sync_state["tags_registered"] = len(tag_counts)
        sync_state["ips_registered"] = len(ip_tag_map)
        sync_state["tag_summary"] = dict(tag_counts.most_common(50)) if hasattr(tag_counts, 'most_common') else dict(sorted(tag_counts.items(), key=lambda x: -x[1])[:50])
        sync_state["error"] = None
        sync_state["sync_history"] = (sync_state["sync_history"] + [sync_entry])[-20:]


def poller_loop(pce):
    interval = int(os.environ.get("SYNC_INTERVAL", "300"))
    while True:
        try:
            run_sync(pce)
        except Exception:
            log.exception("Sync failed")
        time.sleep(interval)


# ============================================================
# Dashboard
# ============================================================

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Palo Alto DAG Sync</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}.fade-in{animation:fadeIn .3s ease-out}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#1e1e2e}::-webkit-scrollbar-thumb{background:#585b70;border-radius:3px}
</style>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen dark">
<div class="max-w-[1200px] mx-auto px-6 py-8">
    <div class="flex items-center justify-between mb-8 fade-in">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <svg class="w-8 h-8 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/></svg>
                Palo Alto DAG Sync
            </h1>
            <p class="text-gray-500 mt-1">Illumio labels → PAN-OS Dynamic Address Groups</p>
        </div>
        <div class="flex items-center gap-3">
            <div id="palo-status" class="text-sm"></div>
            <button onclick="triggerSync()" class="px-3 py-1.5 text-xs rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors">Sync Now</button>
        </div>
    </div>

    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8" id="stats"></div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
            <h2 class="text-lg font-semibold text-white mb-4">Tags by IP Count</h2>
            <div style="height:300px"><canvas id="chart-tags"></canvas></div>
        </div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
            <h2 class="text-lg font-semibold text-white mb-4">Sync History</h2>
            <div style="height:300px"><canvas id="chart-history"></canvas></div>
        </div>
    </div>

    <div class="bg-dark-800 rounded-xl border border-gray-700 p-6 mb-8">
        <h2 class="text-lg font-semibold text-white mb-4">Tag Registry</h2>
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2" id="tag-list"></div>
    </div>

    <div class="text-center text-xs text-gray-600" id="footer"></div>
</div>

<script>
let chartTags, chartHistory;

function initCharts() {
    chartTags = new Chart(document.getElementById('chart-tags'), {
        type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#f9731644',borderColor:'#f97316',borderWidth:1,borderRadius:4}]},
        options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280'}},y:{grid:{display:false},ticks:{color:'#a6adc8',font:{size:10,family:'monospace'}}}}}
    });
    chartHistory = new Chart(document.getElementById('chart-history'), {
        type:'line',data:{labels:[],datasets:[
            {label:'IPs',data:[],borderColor:'#f97316',backgroundColor:'#f9731622',fill:true,tension:0.3,pointRadius:3},
            {label:'Tags',data:[],borderColor:'#3b82f6',backgroundColor:'#3b82f622',fill:true,tension:0.3,pointRadius:3},
        ]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#9ca3af',usePointStyle:true}}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280',font:{size:10}}},y:{grid:{color:'#31324422'},ticks:{color:'#6b7280'},beginAtZero:true}}}
    });
}

function update(data) {
    const statusColor = data.palo_status === 'connected' ? 'green' : data.palo_status === 'not configured' ? 'gray' : 'red';
    document.getElementById('palo-status').innerHTML = `<span class="px-2 py-0.5 rounded text-xs bg-${statusColor}-900/50 text-${statusColor}-400">${data.palo_status}</span>`;

    document.getElementById('stats').innerHTML = `
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-orange-400">${data.workloads_synced}</div><div class="text-xs text-gray-500 mt-1">Workloads Synced</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-blue-400">${data.ips_registered}</div><div class="text-xs text-gray-500 mt-1">IPs Registered</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-purple-400">${data.tags_registered}</div><div class="text-xs text-gray-500 mt-1">Unique Tags</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-green-400">${data.sync_count}</div><div class="text-xs text-gray-500 mt-1">Total Syncs</div></div>
    `;

    // Tags chart
    const tags = Object.entries(data.tag_summary || {}).sort((a,b)=>b[1]-a[1]).slice(0,15);
    chartTags.data.labels = tags.map(t=>t[0].replace('illumio-',''));
    chartTags.data.datasets[0].data = tags.map(t=>t[1]);
    chartTags.update('none');

    // History chart
    const history = data.sync_history || [];
    chartHistory.data.labels = history.map(h => new Date(h.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}));
    chartHistory.data.datasets[0].data = history.map(h=>h.ips);
    chartHistory.data.datasets[1].data = history.map(h=>h.tags);
    chartHistory.update('none');

    // Tag list
    document.getElementById('tag-list').innerHTML = tags.map(([tag,count]) =>
        `<div class="bg-dark-700/50 rounded px-3 py-2 flex items-center justify-between">
            <code class="text-xs text-orange-300 truncate">${tag}</code>
            <span class="text-xs text-gray-500 ml-2 shrink-0">${count}</span>
        </div>`
    ).join('');

    document.getElementById('footer').textContent = `Sync #${data.sync_count} · Last: ${data.last_sync ? new Date(data.last_sync).toLocaleString() : 'never'}${data.error ? ' · Error: '+data.error : ''}`;
}

async function fetchData() {
    try { update(await (await fetch('/api/sync')).json()); } catch(e) { console.error(e); }
}

async function triggerSync() {
    try { await fetch('/api/sync/trigger', {method:'POST'}); setTimeout(fetchData, 2000); } catch(e) { alert('Failed: '+e); }
}

initCharts(); fetchData(); setInterval(fetchData, 30000);
</script>
</body></html>"""


class SyncHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/sync":
            with state_lock:
                self.send_json(200, dict(sync_state))
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/sync/trigger":
            threading.Thread(target=run_sync, args=(pce_client,), daemon=True).start()
            self.send_json(200, {"triggered": True})
        else:
            self.send_error(404)

    def send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


pce_client = None


def main():
    global pce_client

    log.info("Starting palo-alto-dag-sync...")
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce_client = get_pce()
    log.info("Connected to PCE: %s", pce_client.base_url)

    palo_host = os.environ.get("PALO_HOST", "")
    if palo_host:
        log.info("Palo Alto: %s", palo_host)
    else:
        log.warning("PALO_HOST not configured — running in dry-run mode (PCE data only)")

    poller = threading.Thread(target=poller_loop, args=(pce_client,), daemon=True)
    poller.start()
    run_sync(pce_client)

    server = HTTPServer(("0.0.0.0", port), SyncHandler)
    log.info("Dashboard on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
