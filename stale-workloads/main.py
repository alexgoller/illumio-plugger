#!/usr/bin/env python3
"""
stale-workloads — Discover workloads that haven't checked in, have no traffic,
or are offline. Dashboard shows stale workloads grouped by app|env with
unpair/cleanup recommendations.
"""

import json
import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from illumio.explorer import TrafficQuery
from plugger_sdk import Plugin

app = Plugin("stale-workloads")

STALE_DAYS = int(app.env("STALE_DAYS", "7"))
OFFLINE_HOURS = int(app.env("OFFLINE_HOURS", "24"))
CHECK_TRAFFIC = app.env("CHECK_TRAFFIC", "true").lower() in ("true", "1")
CLEANUP_ENABLED = app.env("ENABLE_CLEANUP", "false").lower() in ("true", "1")

if CLEANUP_ENABLED:
    app.log.info("Cleanup ENABLED — unpair/delete actions available")


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

@app.poll(interval_env="POLL_INTERVAL", default=3600)
def check_stale(pce):
    app.log.info("Checking for stale workloads (stale=%dd, offline=%dh, traffic_check=%s)...",
                 STALE_DAYS, OFFLINE_HOURS, CHECK_TRAFFIC)

    try:
        resp = pce.get("/workloads", params={"max_results": 10000})
        workloads = resp.json() if resp.status_code == 200 else []
    except Exception as e:
        app.log.error("Failed to fetch workloads: %s", e)
        return

    if not isinstance(workloads, list):
        workloads = []

    app.log.info("Analyzing %d workloads...", len(workloads))

    now = datetime.now(timezone.utc)
    stale_threshold = now - timedelta(days=STALE_DAYS)
    offline_threshold = now - timedelta(hours=OFFLINE_HOURS)

    active_workload_hrefs = set()
    if CHECK_TRAFFIC:
        try:
            lookback = int(app.env("TRAFFIC_LOOKBACK_HOURS", "168"))
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
            app.log.info("Found %d workloads with traffic in last %dh", len(active_workload_hrefs), lookback)
        except Exception as e:
            app.log.warning("Traffic check failed: %s", e)

    stale = []
    by_app_env = defaultdict(list)
    by_reason = defaultdict(int)
    total = len(workloads)
    managed = 0
    online = 0

    for wl in workloads:
        hostname = wl.get("hostname", "") or "(unnamed)"
        href = wl.get("href", "")
        labels = app.resolve_workload_labels(wl)
        a = labels.get("app", "")
        e = labels.get("env", "")
        app_env = f"{a}|{e}" if a and e else (a or e or "unlabeled")
        is_online = wl.get("online", False)

        agent = wl.get("agent", {}) or {}
        agent_href = agent.get("href", "")
        is_managed = bool(agent_href)
        last_heartbeat = None

        if is_managed:
            managed += 1
            hb = agent.get("status", {}) if isinstance(agent.get("status"), dict) else {}
            last_hb_str = hb.get("last_heartbeat_on", "") or agent.get("last_heartbeat_on", "")
            if last_hb_str:
                try:
                    last_heartbeat = datetime.fromisoformat(last_hb_str.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

        if is_online:
            online += 1

        reasons = []
        severity = "info"

        if not is_online:
            reasons.append("offline")
            severity = "warning"

        if is_managed and last_heartbeat:
            if last_heartbeat < stale_threshold:
                days_ago = (now - last_heartbeat).days
                reasons.append(f"no heartbeat for {days_ago}d")
                severity = "high"
        elif is_managed and not last_heartbeat:
            reasons.append("no heartbeat data")
            severity = "warning"

        if CHECK_TRAFFIC and href and href not in active_workload_hrefs:
            reasons.append("no traffic")
            if severity == "info":
                severity = "warning"

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
            by_reason[r.split(" ")[0]] += 1

    severity_order = {"high": 0, "warning": 1, "info": 2}
    stale.sort(key=lambda x: (severity_order.get(x["severity"], 3), x["hostname"]))

    app.update_state({
        "last_check": now.isoformat(),
        "check_count": app.state.get("check_count", 0) + 1,
        "stale_workloads": stale,
        "summary": {
            "total_workloads": total,
            "managed": managed,
            "online": online,
            "offline": total - online,
            "stale_count": len(stale),
            "stale_days_threshold": STALE_DAYS,
            "offline_hours_threshold": OFFLINE_HOURS,
        },
        "by_app_env": {k: len(v) for k, v in by_app_env.items()},
        "by_reason": dict(by_reason),
        "error": None,
    })

    app.log.info("Check #%d: %d/%d stale (%d offline, %d managed, reasons: %s)",
                 app.state["check_count"], len(stale), total,
                 total - online, managed, dict(by_reason))

    if stale:
        sev = "info" if len(stale) < 10 else "warning" if len(stale) < 50 else "critical"
        lines = [
            f"**{len(stale)} stale workloads** found out of {total} total",
            f"- Offline: {total - online}",
            f"- Managed: {managed}",
        ]
        for reason, count in sorted(by_reason.items(), key=lambda x: -x[1]):
            lines.append(f"- {reason}: {count}")
        if by_app_env:
            top_apps = sorted(by_app_env.items(), key=lambda x: -len(x[1]))[:5]
            lines.append("\n**Top affected apps:**")
            for a, wls in top_apps:
                lines.append(f"- {a}: {len(wls)} stale")
        app.report(
            f"{len(stale)} stale workloads detected",
            body="\n".join(lines),
            severity=sev,
            tags=["stale", "workloads", "cleanup"],
            data={"stale": len(stale), "total": total, "reasons": dict(by_reason)},
        )


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.api("GET", "/api/stale")
def get_stale(request):
    data = dict(app.state)
    data["cleanup_enabled"] = CLEANUP_ENABLED
    return data


@app.api("POST", "/api/cleanup/unpair")
def cleanup_unpair(request):
    if not CLEANUP_ENABLED:
        return {"error": "Cleanup disabled. Set ENABLE_CLEANUP=true."}, 403
    href = request.json.get("href", "")
    if not href:
        return {"error": "workload href is required"}, 400
    try:
        resp = app.pce.put(href, json={"agent": {"config": {"mode": "idle"}}})
        if resp.status_code in (200, 204):
            app.log.info("Unpaired workload: %s", href)
            return {"success": True, "action": "unpaired"}
        return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.api("POST", "/api/cleanup/delete")
def cleanup_delete(request):
    if not CLEANUP_ENABLED:
        return {"error": "Cleanup disabled. Set ENABLE_CLEANUP=true."}, 403
    href = request.json.get("href", "")
    if not href:
        return {"error": "workload href is required"}, 400
    try:
        resp = app.pce.delete(href)
        if resp.status_code in (200, 204):
            app.log.info("Deleted workload: %s", href)
            return {"success": True, "action": "deleted"}
        return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

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
                    <th class="px-4 py-3">Mode</th><th class="px-4 py-3 text-right">Actions</th>
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
    document.getElementById('stats').innerHTML = `
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-white">${s.total_workloads||0}</div><div class="text-xs text-gray-500 mt-1">Total Workloads</div></div>
        <div class="bg-dark-800 rounded-xl border border-orange-900/30 p-5"><div class="text-3xl font-bold text-orange-400">${s.stale_count||0}</div><div class="text-xs text-gray-500 mt-1">Stale</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-red-400">${s.offline||0}</div><div class="text-xs text-gray-500 mt-1">Offline</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-green-400">${s.online||0}</div><div class="text-xs text-gray-500 mt-1">Online</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-blue-400">${s.managed||0}</div><div class="text-xs text-gray-500 mt-1">Managed</div></div>
    `;
    const reasons = data.by_reason || {};
    chartReasons.data.labels = Object.keys(reasons);
    chartReasons.data.datasets[0].data = Object.values(reasons);
    chartReasons.update('none');
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
    const canCleanup = (lastData||{}).cleanup_enabled;
    document.getElementById('table-body').innerHTML = filtered.map(w => `
        <tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
            <td class="px-4 py-2"><code class="text-xs">${w.hostname}</code></td>
            <td class="px-4 py-2 text-xs text-gray-400">${w.app_env}</td>
            <td class="px-4 py-2 text-xs text-gray-500 font-mono">${w.ip}</td>
            <td class="px-4 py-2"><span class="px-1.5 py-0.5 rounded text-[10px] bg-${sevColor[w.severity]||'gray'}-900/50 text-${sevColor[w.severity]||'gray'}-400">${w.severity}</span></td>
            <td class="px-4 py-2"><div class="flex flex-wrap gap-1">${w.reasons.map(r=>'<span class="text-[10px] px-1.5 py-0.5 rounded bg-dark-700 text-gray-400">'+r+'</span>').join('')}</div></td>
            <td class="px-4 py-2 text-xs text-gray-500">${w.last_heartbeat ? timeAgo(w.last_heartbeat) : '—'}</td>
            <td class="px-4 py-2 text-xs text-gray-500">${w.enforcement_mode||'—'}</td>
            <td class="px-4 py-2 text-right">
                ${canCleanup ? `<div class="flex gap-1 justify-end">
                    ${w.managed ? `<button onclick="cleanupWorkload('${w.href}','unpair','${w.hostname}')" class="px-1.5 py-0.5 text-[10px] rounded bg-yellow-800 hover:bg-yellow-700 text-yellow-200">Unpair</button>` : ''}
                    ${!w.managed ? `<button onclick="cleanupWorkload('${w.href}','delete','${w.hostname}')" class="px-1.5 py-0.5 text-[10px] rounded bg-red-800 hover:bg-red-700 text-red-200">Delete</button>` : ''}
                </div>` : '<span class="text-[10px] text-gray-600">disabled</span>'}
            </td>
        </tr>
    `).join('');
}

async function cleanupWorkload(href, action, hostname) {
    const msg = action === 'unpair'
        ? 'Unpair workload "' + hostname + '"? This will remove the VEN agent.'
        : 'Delete workload "' + hostname + '" from PCE? This cannot be undone.';
    if (!confirm(msg)) return;
    try {
        const resp = await fetch(BASE+'/api/cleanup/' + action, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({href: href})
        });
        const result = await resp.json();
        if (result.success) {
            alert((action === 'unpair' ? 'Unpaired' : 'Deleted') + ': ' + hostname);
            await fetchData();
        } else {
            alert('Failed: ' + result.error);
        }
    } catch(e) { alert('Failed: ' + e); }
}

async function fetchData() {
    try { const d = await (await fetch(BASE+'/api/stale')).json(); update(d); } catch(e) { console.error(e); }
}

initCharts(); fetchData(); setInterval(fetchData, 30000);
</script>
</body></html>"""


@app.dashboard
def render():
    return DASHBOARD_HTML


app.run()
