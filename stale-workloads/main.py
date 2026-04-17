#!/usr/bin/env python3
"""
stale-workloads — Discover workloads that haven't checked in, have no traffic,
or are offline. Dashboard shows stale workloads grouped by app|env with
unpair/cleanup recommendations.
"""

import json
import logging
import os
import signal
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

from illumio import PolicyComputeEngine
from illumio.explorer import TrafficQuery

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("stale_workloads")

state_lock = threading.Lock()
report_state = {
    "last_check": None,
    "check_count": 0,
    "error": None,
    "stale_workloads": [],
    "summary": {},
    "by_app_env": {},
    "by_reason": {},
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
            log.info("Loaded %d labels", len(label_cache))
    except Exception as e:
        log.warning("Failed to fetch labels: %s", e)


def resolve_labels(workload):
    """Resolve workload labels to key:value map."""
    result = {}
    for lbl in workload.get("labels", []):
        if isinstance(lbl, dict):
            href = lbl.get("href", "")
            if href in label_cache:
                cached = label_cache[href]
                result[cached["key"]] = cached["value"]
    return result


def get_app_env(labels):
    app = labels.get("app", "")
    env = labels.get("env", "")
    if app and env:
        return f"{app}|{env}"
    return app or env or "unlabeled"


def check_stale(pce):
    """Analyze all workloads for staleness."""
    if not label_cache:
        fetch_labels(pce)

    stale_days = int(os.environ.get("STALE_DAYS", "7"))
    offline_hours = int(os.environ.get("OFFLINE_HOURS", "24"))
    check_traffic = os.environ.get("CHECK_TRAFFIC", "true").lower() in ("true", "1")

    log.info("Checking for stale workloads (stale=%dd, offline=%dh, traffic_check=%s)...",
             stale_days, offline_hours, check_traffic)

    # Fetch all workloads
    try:
        resp = pce.get("/workloads", params={"max_results": 10000})
        workloads = resp.json() if resp.status_code == 200 else []
    except Exception as e:
        log.error("Failed to fetch workloads: %s", e)
        return

    if not isinstance(workloads, list):
        workloads = []

    log.info("Analyzing %d workloads...", len(workloads))

    now = datetime.now(timezone.utc)
    stale_threshold = now - timedelta(days=stale_days)
    offline_threshold = now - timedelta(hours=offline_hours)

    # Optionally query traffic to find workloads with zero traffic
    active_workload_hrefs = set()
    if check_traffic:
        try:
            lookback = int(os.environ.get("TRAFFIC_LOOKBACK_HOURS", "168"))  # 7 days default
            query = TrafficQuery.build(
                start_date=(now - timedelta(hours=lookback)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                end_date=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                policy_decisions=["allowed", "blocked", "potentially_blocked", "unknown"],
                max_results=50000,
            )
            flows = pce.get_traffic_flows_async(
                query_name="plugger-stale-workloads",
                traffic_query=query,
            )
            for f in flows:
                flow = f.to_json() if hasattr(f, 'to_json') else (f.__dict__ if hasattr(f, '__dict__') else f)
                if isinstance(flow, str):
                    flow = json.loads(flow)
                if isinstance(flow, dict):
                    for side in ("src", "dst"):
                        ep = flow.get(side, {})
                        if isinstance(ep, dict):
                            wl = ep.get("workload", {}) or {}
                            if isinstance(wl, dict) and wl.get("href"):
                                active_workload_hrefs.add(wl["href"])
            log.info("Found %d workloads with traffic in last %dh", len(active_workload_hrefs), lookback)
        except Exception as e:
            log.warning("Traffic check failed: %s", e)

    stale = []
    by_app_env = defaultdict(list)
    by_reason = defaultdict(int)
    total = len(workloads)
    managed = 0
    online = 0

    for wl in workloads:
        hostname = wl.get("hostname", "") or "(unnamed)"
        href = wl.get("href", "")
        labels = resolve_labels(wl)
        app_env = get_app_env(labels)
        is_online = wl.get("online", False)

        # Agent info
        agent = wl.get("agent", {}) or {}
        agent_href = agent.get("href", "")
        is_managed = bool(agent_href)
        last_heartbeat = None

        if is_managed:
            managed += 1
            # Parse last heartbeat
            hb = agent.get("status", {}) if isinstance(agent.get("status"), dict) else {}
            last_hb_str = hb.get("last_heartbeat_on", "") or agent.get("last_heartbeat_on", "")
            if last_hb_str:
                try:
                    last_heartbeat = datetime.fromisoformat(last_hb_str.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

        if is_online:
            online += 1

        # Determine staleness reasons
        reasons = []
        severity = "info"

        # 1. Offline for too long
        if not is_online:
            reasons.append("offline")
            severity = "warning"

        # 2. No heartbeat or stale heartbeat (managed only)
        if is_managed and last_heartbeat:
            if last_heartbeat < stale_threshold:
                days_ago = (now - last_heartbeat).days
                reasons.append(f"no heartbeat for {days_ago}d")
                severity = "high"
        elif is_managed and not last_heartbeat:
            reasons.append("no heartbeat data")
            severity = "warning"

        # 3. No traffic (if traffic check enabled)
        if check_traffic and href and href not in active_workload_hrefs:
            reasons.append("no traffic")
            if severity == "info":
                severity = "warning"

        # 4. Unmanaged (no agent)
        if not is_managed:
            reasons.append("unmanaged")

        if not reasons:
            continue

        interfaces = wl.get("interfaces", [])
        ip = interfaces[0].get("address", "") if interfaces else ""

        entry = {
            "hostname": hostname,
            "href": href,
            "ip": ip,
            "app_env": app_env,
            "labels": labels,
            "online": is_online,
            "managed": is_managed,
            "last_heartbeat": last_heartbeat.isoformat() if last_heartbeat else None,
            "reasons": reasons,
            "severity": severity,
            "enforcement_mode": wl.get("enforcement_mode", ""),
        }

        stale.append(entry)
        by_app_env[app_env].append(entry)
        for r in reasons:
            by_reason[r.split(" ")[0]] += 1  # group by first word

    # Sort by severity then hostname
    severity_order = {"high": 0, "warning": 1, "info": 2}
    stale.sort(key=lambda x: (severity_order.get(x["severity"], 3), x["hostname"]))

    summary = {
        "total_workloads": total,
        "managed": managed,
        "online": online,
        "offline": total - online,
        "stale_count": len(stale),
        "stale_days_threshold": stale_days,
        "offline_hours_threshold": offline_hours,
    }

    with state_lock:
        report_state["last_check"] = now.isoformat()
        report_state["check_count"] += 1
        report_state["stale_workloads"] = stale
        report_state["summary"] = summary
        report_state["by_app_env"] = {k: len(v) for k, v in by_app_env.items()}
        report_state["by_reason"] = dict(by_reason)
        report_state["error"] = None

    log.info("Check #%d: %d/%d stale (%d offline, %d managed, reasons: %s)",
             report_state["check_count"], len(stale), total,
             total - online, managed, dict(by_reason))


def poller_loop(pce):
    interval = int(os.environ.get("POLL_INTERVAL", "600"))
    while True:
        try:
            check_stale(pce)
        except Exception:
            log.exception("Stale check failed")
        time.sleep(interval)


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Stale Workloads</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}.fade-in{animation:fadeIn .3s ease-out}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#1e1e2e}::-webkit-scrollbar-thumb{background:#585b70;border-radius:3px}
</style>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen dark">
<div class="max-w-[1400px] mx-auto px-6 py-8">
    <div class="flex items-center justify-between mb-8 fade-in">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <svg class="w-8 h-8 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                Stale Workloads
            </h1>
            <p class="text-gray-500 mt-1">Discover offline, unresponsive, and trafficless workloads</p>
        </div>
        <div id="status" class="text-sm text-gray-400"></div>
    </div>

    <div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8" id="stats"></div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6"><h2 class="text-lg font-semibold text-white mb-4">By Reason</h2><div style="height:250px"><canvas id="chart-reasons"></canvas></div></div>
        <div class="lg:col-span-2 bg-dark-800 rounded-xl border border-gray-700 p-6"><h2 class="text-lg font-semibold text-white mb-4">By Application</h2><div style="height:250px"><canvas id="chart-apps"></canvas></div></div>
    </div>

    <div class="bg-dark-800 rounded-xl border border-gray-700 overflow-hidden mb-8">
        <div class="px-5 py-3 border-b border-gray-700 flex items-center justify-between">
            <h2 class="text-lg font-semibold text-white">Stale Workloads</h2>
            <input type="text" id="search" placeholder="Filter..." oninput="renderTable()" class="bg-dark-700 border border-gray-600 rounded px-3 py-1 text-sm text-white placeholder-gray-500 focus:outline-none w-40">
        </div>
        <div class="overflow-x-auto max-h-[500px] overflow-y-auto">
            <table class="w-full text-sm">
                <thead class="sticky top-0 bg-dark-800"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
                    <th class="px-4 py-3">Hostname</th><th class="px-4 py-3">App|Env</th><th class="px-4 py-3">IP</th>
                    <th class="px-4 py-3">Severity</th><th class="px-4 py-3">Reasons</th><th class="px-4 py-3">Heartbeat</th>
                    <th class="px-4 py-3">Mode</th>
                </tr></thead>
                <tbody id="table-body"></tbody>
            </table>
        </div>
    </div>

    <div class="text-center text-xs text-gray-600" id="footer"></div>
</div>

<script>
const BASE = (() => { const m = window.location.pathname.match(/^(\/plugins\/[^/]+\/ui)/); return m ? m[1] : ''; })();
let chartReasons, chartApps, lastData;

function formatNum(n) { return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':n.toLocaleString(); }
function timeAgo(ts) {
    if (!ts) return '—';
    const d = (Date.now()-new Date(ts).getTime())/1000;
    if (d<3600) return Math.floor(d/60)+'m ago';
    if (d<86400) return Math.floor(d/3600)+'h ago';
    return Math.floor(d/86400)+'d ago';
}

function initCharts() {
    chartReasons = new Chart(document.getElementById('chart-reasons'), {
        type: 'doughnut', data: {labels:[],datasets:[{data:[],backgroundColor:['#ef4444','#f97316','#eab308','#6b7280','#3b82f6'],borderWidth:0}]},
        options: {responsive:true,maintainAspectRatio:false,cutout:'60%',plugins:{legend:{position:'bottom',labels:{color:'#9ca3af',usePointStyle:true}}}}
    });
    chartApps = new Chart(document.getElementById('chart-apps'), {
        type: 'bar', data: {labels:[],datasets:[{data:[],backgroundColor:'#f9731644',borderColor:'#f97316',borderWidth:1,borderRadius:4}]},
        options: {responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280'}},y:{grid:{display:false},ticks:{color:'#a6adc8',font:{size:11,family:'monospace'}}}}}
    });
}

function update(data) {
    lastData = data;
    const s = data.summary || {};
    const stale = data.stale_workloads || [];

    document.getElementById('stats').innerHTML = `
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-white">${s.total_workloads||0}</div><div class="text-xs text-gray-500 mt-1">Total Workloads</div></div>
        <div class="bg-dark-800 rounded-xl border border-orange-900/30 p-5"><div class="text-3xl font-bold text-orange-400">${s.stale_count||0}</div><div class="text-xs text-gray-500 mt-1">Stale</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-red-400">${s.offline||0}</div><div class="text-xs text-gray-500 mt-1">Offline</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-green-400">${s.online||0}</div><div class="text-xs text-gray-500 mt-1">Online</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-blue-400">${s.managed||0}</div><div class="text-xs text-gray-500 mt-1">Managed</div></div>
    `;

    // Reasons chart
    const reasons = data.by_reason || {};
    chartReasons.data.labels = Object.keys(reasons);
    chartReasons.data.datasets[0].data = Object.values(reasons);
    chartReasons.update('none');

    // Apps chart
    const apps = Object.entries(data.by_app_env || {}).sort((a,b)=>b[1]-a[1]).slice(0,10);
    chartApps.data.labels = apps.map(a=>a[0]);
    chartApps.data.datasets[0].data = apps.map(a=>a[1]);
    chartApps.update('none');

    renderTable();

    document.getElementById('status').textContent = data.error ? 'Error: '+data.error : 'Check #'+(data.check_count||0)+' · '+timeAgo(data.last_check);
    document.getElementById('footer').textContent = 'Threshold: '+s.stale_days_threshold+'d heartbeat, '+s.offline_hours_threshold+'h offline';
}

function renderTable() {
    const stale = (lastData||{}).stale_workloads || [];
    const q = (document.getElementById('search').value||'').toLowerCase();
    const filtered = q ? stale.filter(w => w.hostname.toLowerCase().includes(q) || w.app_env.toLowerCase().includes(q) || w.ip.includes(q)) : stale;

    const sevColor = {high:'red',warning:'yellow',info:'gray'};
    document.getElementById('table-body').innerHTML = filtered.map(w => `
        <tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
            <td class="px-4 py-2"><code class="text-xs">${w.hostname}</code></td>
            <td class="px-4 py-2 text-xs text-gray-400">${w.app_env}</td>
            <td class="px-4 py-2 text-xs text-gray-500 font-mono">${w.ip}</td>
            <td class="px-4 py-2"><span class="px-1.5 py-0.5 rounded text-[10px] bg-${sevColor[w.severity]||'gray'}-900/50 text-${sevColor[w.severity]||'gray'}-400">${w.severity}</span></td>
            <td class="px-4 py-2"><div class="flex flex-wrap gap-1">${w.reasons.map(r=>'<span class="text-[10px] px-1.5 py-0.5 rounded bg-dark-700 text-gray-400">'+r+'</span>').join('')}</div></td>
            <td class="px-4 py-2 text-xs text-gray-500">${w.last_heartbeat ? timeAgo(w.last_heartbeat) : '—'}</td>
            <td class="px-4 py-2 text-xs text-gray-500">${w.enforcement_mode||'—'}</td>
        </tr>
    `).join('');
}

async function fetchData() {
    try { const d = await (await fetch('/api/stale')).json(); update(d); } catch(e) { console.error(e); }
}

initCharts(); fetchData(); setInterval(fetchData, 30000);
</script>
</body></html>"""


class StaleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/stale":
            with state_lock:
                self.send_json(200, dict(report_state))
        elif self.path == "/":
            body = DASHBOARD_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
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


def main():
    log.info("Starting stale-workloads...")
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce = get_pce()
    log.info("Connected to PCE: %s", pce.base_url)

    poller = threading.Thread(target=poller_loop, args=(pce,), daemon=True)
    poller.start()
    check_stale(pce)

    server = HTTPServer(("0.0.0.0", port), StaleHandler)
    log.info("Dashboard on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
