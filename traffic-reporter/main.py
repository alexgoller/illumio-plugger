#!/usr/bin/env python3
"""
traffic-reporter — Poll PCE traffic flows and serve an interactive dashboard.

Uses Chart.js for interactive graphs showing policy decisions, top talkers,
services, and blocked flow analysis.
"""

import json
import logging
import os
import signal
import threading
import time
from collections import Counter
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

from illumio import PolicyComputeEngine
from illumio.explorer import TrafficQuery

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("traffic_reporter")

state_lock = threading.Lock()
traffic_state = {
    "last_poll": None,
    "poll_count": 0,
    "total_flows": 0,
    "top_sources": [],
    "top_destinations": [],
    "top_services": [],
    "blocked_flows": [],
    "policy_decisions": {},
    "error": None,
}


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


def poll_traffic(pce):
    """Poll traffic analysis from PCE and update state."""
    lookback_hours = int(os.environ.get("LOOKBACK_HOURS", "24"))
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback_hours)

    log.info("Querying traffic flows (last %dh)...", lookback_hours)

    try:
        traffic_query = TrafficQuery.build(
            start_date=start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_date=end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            policy_decisions=["allowed", "blocked", "potentially_blocked", "unknown"],
            max_results=int(os.environ.get("MAX_RESULTS", "10000")),
        )

        raw_flows = pce.get_traffic_flows_async(
            query_name="plugger-traffic-reporter",
            traffic_query=traffic_query,
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

        src_counter = Counter()
        dst_counter = Counter()
        svc_counter = Counter()
        decisions = Counter()
        blocked = []

        for flow in flows:
            src = flow.get("src", {})
            dst = flow.get("dst", {})
            service = flow.get("service", {})

            src_name = ""
            if isinstance(src, dict):
                src_name = (src.get("workload", {}) or {}).get("hostname", "") or src.get("ip", "unknown")
            dst_name = ""
            if isinstance(dst, dict):
                dst_name = (dst.get("workload", {}) or {}).get("hostname", "") or dst.get("ip", "unknown")

            port = service.get("port", "?") if isinstance(service, dict) else "?"
            proto = service.get("proto", "?") if isinstance(service, dict) else "?"
            svc_name = f"{port}/{proto}"

            num_connections = flow.get("num_connections", 1)

            src_counter[src_name] += num_connections
            dst_counter[dst_name] += num_connections
            svc_counter[svc_name] += num_connections

            decision = flow.get("policy_decision", "unknown")
            decisions[decision] += num_connections

            if decision in ("blocked", "potentially_blocked"):
                blocked.append({
                    "src": src_name,
                    "dst": dst_name,
                    "service": svc_name,
                    "decision": decision,
                    "connections": num_connections,
                })

        with state_lock:
            traffic_state["last_poll"] = datetime.now(timezone.utc).isoformat()
            traffic_state["poll_count"] += 1
            traffic_state["total_flows"] = len(flows)
            traffic_state["top_sources"] = src_counter.most_common(20)
            traffic_state["top_destinations"] = dst_counter.most_common(20)
            traffic_state["top_services"] = svc_counter.most_common(20)
            traffic_state["blocked_flows"] = sorted(blocked, key=lambda x: x["connections"], reverse=True)[:50]
            traffic_state["policy_decisions"] = dict(decisions)
            traffic_state["error"] = None

        log.info("Poll #%d: %d flows, %d blocked",
                 traffic_state["poll_count"], len(flows), len(blocked))

    except Exception as e:
        log.exception("Traffic poll failed")
        with state_lock:
            traffic_state["error"] = str(e)


def poller_loop(pce):
    interval = int(os.environ.get("POLL_INTERVAL", "300"))
    while True:
        poll_traffic(pce)
        time.sleep(interval)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Traffic Reporter</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>
tailwind.config = {
    darkMode: 'class',
    theme: { extend: { colors: { dark: { 700: '#313244', 800: '#1e1e2e', 900: '#11111b' } } } }
}
</script>
<style>
    @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
    .fade-in { animation: fadeIn 0.4s ease-out; }
    .stat-card { transition: all 0.2s; }
    .stat-card:hover { transform: translateY(-2px); border-color: #585b70; }
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #1e1e2e; }
    ::-webkit-scrollbar-thumb { background: #585b70; border-radius: 3px; }
    .glow-green { box-shadow: 0 0 20px rgba(34,197,94,0.1); }
    .glow-red { box-shadow: 0 0 20px rgba(239,68,68,0.1); }
</style>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen dark">
<div class="max-w-[1400px] mx-auto px-6 py-8">

    <!-- Header -->
    <div class="flex items-center justify-between mb-8 fade-in">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <svg class="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
                </svg>
                Traffic Reporter
            </h1>
            <p class="text-gray-500 mt-1" id="subtitle">Loading...</p>
        </div>
        <div class="flex items-center gap-3">
            <div id="status-dot" class="w-3 h-3 rounded-full bg-gray-600 animate-pulse"></div>
            <span id="status-text" class="text-sm text-gray-400">Connecting...</span>
        </div>
    </div>

    <!-- Stat Cards -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <div class="stat-card bg-dark-800 rounded-xl border border-gray-700 p-6 fade-in">
            <div class="text-4xl font-bold text-blue-400" id="stat-flows">—</div>
            <div class="text-sm text-gray-500 mt-2">Unique Flows</div>
        </div>
        <div class="stat-card bg-dark-800 rounded-xl border border-gray-700 p-6 fade-in glow-green">
            <div class="text-4xl font-bold text-green-400" id="stat-allowed">—</div>
            <div class="text-sm text-gray-500 mt-2">Allowed Connections</div>
        </div>
        <div class="stat-card bg-dark-800 rounded-xl border border-gray-700 p-6 fade-in glow-red">
            <div class="text-4xl font-bold text-red-400" id="stat-blocked">—</div>
            <div class="text-sm text-gray-500 mt-2">Blocked / Pot. Blocked</div>
        </div>
        <div class="stat-card bg-dark-800 rounded-xl border border-gray-700 p-6 fade-in">
            <div class="text-4xl font-bold text-yellow-400" id="stat-unknown">—</div>
            <div class="text-sm text-gray-500 mt-2">Unknown Decision</div>
        </div>
    </div>

    <!-- Charts Row 1: Policy Decisions + Top Services -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6 fade-in">
            <h2 class="text-lg font-semibold text-white mb-4">Policy Decisions</h2>
            <div class="flex items-center justify-center" style="height:280px;">
                <canvas id="chart-decisions"></canvas>
            </div>
        </div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6 fade-in">
            <h2 class="text-lg font-semibold text-white mb-4">Top Services</h2>
            <div style="height:280px;">
                <canvas id="chart-services"></canvas>
            </div>
        </div>
    </div>

    <!-- Charts Row 2: Sources + Destinations -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6 fade-in">
            <h2 class="text-lg font-semibold text-white mb-4">Top Sources</h2>
            <div style="height:350px;">
                <canvas id="chart-sources"></canvas>
            </div>
        </div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6 fade-in">
            <h2 class="text-lg font-semibold text-white mb-4">Top Destinations</h2>
            <div style="height:350px;">
                <canvas id="chart-destinations"></canvas>
            </div>
        </div>
    </div>

    <!-- Blocked Flows Table -->
    <div class="bg-dark-800 rounded-xl border border-red-900/30 p-6 mb-8 fade-in" id="blocked-section" style="display:none;">
        <div class="flex items-center gap-2 mb-4">
            <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/>
            </svg>
            <h2 class="text-lg font-semibold text-red-400">Blocked Flows</h2>
            <span class="text-xs text-gray-500 ml-2" id="blocked-count"></span>
        </div>
        <div class="overflow-x-auto">
            <table class="w-full">
                <thead>
                    <tr class="text-left text-xs text-gray-500 uppercase tracking-wider">
                        <th class="pb-3 pr-4">Source</th>
                        <th class="pb-3 pr-4">Destination</th>
                        <th class="pb-3 pr-4">Service</th>
                        <th class="pb-3 pr-4">Decision</th>
                        <th class="pb-3 text-right">Connections</th>
                    </tr>
                </thead>
                <tbody id="blocked-table" class="text-sm"></tbody>
            </table>
        </div>
    </div>

    <!-- Footer -->
    <div class="text-center text-xs text-gray-600 fade-in" id="footer">
        <span id="poll-info"></span>
        &middot; <a href="/api/traffic" class="text-blue-500 hover:text-blue-400">JSON API</a>
    </div>
</div>

<script>
const COLORS = {
    allowed: '#22c55e',
    blocked: '#ef4444',
    potentially_blocked: '#f97316',
    unknown: '#eab308',
};

const CHART_DEFAULTS = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: { labels: { color: '#9ca3af', font: { size: 12 } } },
        tooltip: {
            backgroundColor: '#1e1e2e',
            borderColor: '#313244',
            borderWidth: 1,
            titleColor: '#cdd6f4',
            bodyColor: '#a6adc8',
            padding: 12,
            cornerRadius: 8,
            callbacks: {
                label: ctx => {
                    const v = ctx.parsed.y !== undefined ? ctx.parsed.y : ctx.parsed;
                    return ctx.label + ': ' + formatNum(v);
                }
            }
        }
    }
};

let chartDecisions, chartServices, chartSources, chartDestinations;

function formatNum(n) {
    if (n >= 1e9) return (n/1e9).toFixed(1) + 'B';
    if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
    return n.toLocaleString();
}

function truncate(s, n) {
    return s.length > n ? s.substring(0, n) + '...' : s;
}

function initCharts() {
    chartDecisions = new Chart(document.getElementById('chart-decisions'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0, hoverOffset: 8 }] },
        options: {
            ...CHART_DEFAULTS,
            cutout: '65%',
            plugins: {
                ...CHART_DEFAULTS.plugins,
                legend: { position: 'bottom', labels: { color: '#9ca3af', padding: 16, usePointStyle: true, pointStyle: 'circle' } },
                tooltip: {
                    ...CHART_DEFAULTS.plugins.tooltip,
                    callbacks: { label: ctx => ctx.label + ': ' + formatNum(ctx.parsed) }
                }
            }
        }
    });

    const barOpts = {
        ...CHART_DEFAULTS,
        indexAxis: 'y',
        plugins: {
            ...CHART_DEFAULTS.plugins,
            legend: { display: false },
        },
        scales: {
            x: {
                grid: { color: '#31324422' },
                ticks: { color: '#6b7280', font: { size: 11 }, callback: v => formatNum(v) }
            },
            y: {
                grid: { display: false },
                ticks: { color: '#a6adc8', font: { size: 11, family: 'monospace' } }
            }
        }
    };

    chartServices = new Chart(document.getElementById('chart-services'), {
        type: 'bar',
        data: { labels: [], datasets: [{ data: [], backgroundColor: '#93c5fd44', borderColor: '#93c5fd', borderWidth: 1, borderRadius: 4 }] },
        options: barOpts
    });

    chartSources = new Chart(document.getElementById('chart-sources'), {
        type: 'bar',
        data: { labels: [], datasets: [{ data: [], backgroundColor: '#a78bfa33', borderColor: '#a78bfa', borderWidth: 1, borderRadius: 4 }] },
        options: barOpts
    });

    chartDestinations = new Chart(document.getElementById('chart-destinations'), {
        type: 'bar',
        data: { labels: [], datasets: [{ data: [], backgroundColor: '#f9a8d433', borderColor: '#f9a8d4', borderWidth: 1, borderRadius: 4 }] },
        options: barOpts
    });
}

function updateDashboard(data) {
    const d = data.policy_decisions || {};
    const allowed = d.allowed || 0;
    const blocked = (d.blocked || 0) + (d.potentially_blocked || 0);
    const unknown = d.unknown || 0;

    // Stats
    document.getElementById('stat-flows').textContent = formatNum(data.total_flows);
    document.getElementById('stat-allowed').textContent = formatNum(allowed);
    document.getElementById('stat-blocked').textContent = formatNum(blocked);
    document.getElementById('stat-unknown').textContent = formatNum(unknown);

    // Subtitle
    const lookback = document.location.search ? new URLSearchParams(document.location.search).get('hours') : null;
    document.getElementById('subtitle').textContent =
        `${data.total_flows.toLocaleString()} flows analyzed · Last ${lookback || 'LOOKBACK_HOURS'}h`;

    // Status
    if (data.error) {
        document.getElementById('status-dot').className = 'w-3 h-3 rounded-full bg-red-500';
        document.getElementById('status-text').textContent = 'Error';
        document.getElementById('status-text').className = 'text-sm text-red-400';
    } else {
        document.getElementById('status-dot').className = 'w-3 h-3 rounded-full bg-green-500 animate-pulse';
        document.getElementById('status-text').textContent = 'Live';
        document.getElementById('status-text').className = 'text-sm text-green-400';
    }

    // Decisions donut
    const decisionLabels = [];
    const decisionData = [];
    const decisionColors = [];
    for (const [k, v] of Object.entries(d)) {
        decisionLabels.push(k.replace('_', ' '));
        decisionData.push(v);
        decisionColors.push(COLORS[k] || '#6b7280');
    }
    chartDecisions.data.labels = decisionLabels;
    chartDecisions.data.datasets[0].data = decisionData;
    chartDecisions.data.datasets[0].backgroundColor = decisionColors;
    chartDecisions.update('none');

    // Services bar
    const svc = (data.top_services || []).slice(0, 10);
    chartServices.data.labels = svc.map(s => s[0]);
    chartServices.data.datasets[0].data = svc.map(s => s[1]);
    chartServices.update('none');

    // Sources bar
    const src = (data.top_sources || []).slice(0, 10);
    chartSources.data.labels = src.map(s => truncate(s[0], 30));
    chartSources.data.datasets[0].data = src.map(s => s[1]);
    chartSources.update('none');

    // Destinations bar
    const dst = (data.top_destinations || []).slice(0, 10);
    chartDestinations.data.labels = dst.map(s => truncate(s[0], 30));
    chartDestinations.data.datasets[0].data = dst.map(s => s[1]);
    chartDestinations.update('none');

    // Blocked table
    const blockedFlows = data.blocked_flows || [];
    const blockedSection = document.getElementById('blocked-section');
    if (blockedFlows.length > 0) {
        blockedSection.style.display = 'block';
        document.getElementById('blocked-count').textContent = blockedFlows.length + ' flows';
        const tbody = document.getElementById('blocked-table');
        tbody.innerHTML = blockedFlows.slice(0, 25).map(b => `
            <tr class="border-b border-gray-800/50 hover:bg-dark-700/30 transition-colors">
                <td class="py-2.5 pr-4"><code class="text-xs bg-dark-700 px-1.5 py-0.5 rounded">${b.src}</code></td>
                <td class="py-2.5 pr-4"><code class="text-xs bg-dark-700 px-1.5 py-0.5 rounded">${b.dst}</code></td>
                <td class="py-2.5 pr-4"><span class="text-blue-300">${b.service}</span></td>
                <td class="py-2.5 pr-4"><span class="px-2 py-0.5 rounded text-xs font-medium ${b.decision === 'blocked' ? 'bg-red-900/50 text-red-400' : 'bg-orange-900/50 text-orange-400'}">${b.decision}</span></td>
                <td class="py-2.5 text-right font-mono text-gray-400">${formatNum(b.connections)}</td>
            </tr>
        `).join('');
    } else {
        blockedSection.style.display = 'none';
    }

    // Footer
    document.getElementById('poll-info').textContent =
        `Poll #${data.poll_count} · Updated ${data.last_poll ? new Date(data.last_poll).toLocaleTimeString() : 'never'}`;
}

async function fetchData() {
    try {
        const resp = await fetch('/api/traffic');
        const data = await resp.json();
        updateDashboard(data);
    } catch (e) {
        console.error('Fetch failed:', e);
    }
}

// Init
initCharts();
fetchData();
// Auto-refresh every 30s
setInterval(fetchData, 30000);
</script>
</body>
</html>"""


class TrafficHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/traffic":
            with state_lock:
                self.send_json(200, dict(traffic_state))
        elif self.path == "/":
            self.send_html(DASHBOARD_HTML.replace("LOOKBACK_HOURS", os.environ.get("LOOKBACK_HOURS", "24")))
        else:
            self.send_error(404)

    def send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    log.info("Starting traffic-reporter...")
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce = get_pce()
    log.info("Connected to PCE: %s", pce.base_url)

    poller = threading.Thread(target=poller_loop, args=(pce,), daemon=True)
    poller.start()
    poll_traffic(pce)

    server = HTTPServer(("0.0.0.0", port), TrafficHandler)
    log.info("Dashboard on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
