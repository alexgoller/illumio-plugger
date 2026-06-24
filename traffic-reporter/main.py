#!/usr/bin/env python3
"""
traffic-reporter — Poll PCE traffic flows and serve an interactive dashboard.

Uses Chart.js for interactive graphs showing policy decisions, top talkers,
services, and blocked flow analysis.
"""

import ipaddress
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone, timedelta

from illumio.explorer import TrafficQuery
from plugger_sdk import Plugin

app = Plugin("traffic-reporter")

LOOKBACK_HOURS = int(app.env("LOOKBACK_HOURS", "24"))
MAX_RESULTS = int(app.env("MAX_RESULTS", "10000"))

# ---------------------------------------------------------------------------
# Squelch / mute rules
# ---------------------------------------------------------------------------

SQUELCH_RULES = []
_squelch_raw = app.env("SQUELCH_RULES", "").strip()
if _squelch_raw:
    try:
        for rule in json.loads(_squelch_raw):
            r = {"type": rule.get("type", ""), "label": rule.get("label", ""), "enabled": True}
            if r["type"] == "service":
                r["port"] = rule.get("port")
                r["proto"] = rule.get("proto", "").lower()
            elif r["type"] == "ip":
                r["pattern"] = rule.get("pattern", "")
            elif r["type"] == "subnet":
                r["network"] = ipaddress.ip_network(rule.get("cidr", "0.0.0.0/0"), strict=False)
            elif r["type"] == "hostname":
                r["regex"] = re.compile(rule.get("pattern", ""), re.IGNORECASE)
            elif r["type"] == "decision":
                r["value"] = rule.get("value", "")
            SQUELCH_RULES.append(r)
        app.log.info("Loaded %d squelch rules", len(SQUELCH_RULES))
    except Exception as e:
        app.log.warning("Failed to parse SQUELCH_RULES: %s", e)

# Runtime-managed squelch (toggleable via API)
squelch_state = {"rules": list(SQUELCH_RULES), "squelched_count": 0}


def is_squelched(flow, src_name, dst_name, svc_port, svc_proto, decision):
    for rule in squelch_state["rules"]:
        if not rule.get("enabled", True):
            continue
        t = rule["type"]
        if t == "service":
            if rule.get("port") is not None and svc_port == rule["port"]:
                proto_match = not rule.get("proto") or svc_proto == rule["proto"]
                if proto_match:
                    return True
        elif t == "ip":
            pat = rule.get("pattern", "")
            if pat and (pat == src_name or pat == dst_name):
                return True
            src_ip = flow.get("src", {}).get("ip", "")
            dst_ip = flow.get("dst", {}).get("ip", "")
            if pat and (pat == src_ip or pat == dst_ip):
                return True
        elif t == "subnet":
            net = rule.get("network")
            if net:
                for side in ("src", "dst"):
                    ip = flow.get(side, {}).get("ip", "")
                    if ip:
                        try:
                            if ipaddress.ip_address(ip) in net:
                                return True
                        except ValueError:
                            pass
        elif t == "hostname":
            rx = rule.get("regex")
            if rx and (rx.search(src_name) or rx.search(dst_name)):
                return True
        elif t == "decision":
            if rule.get("value") and decision == rule["value"]:
                return True
    return False


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

@app.poll(interval_env="POLL_INTERVAL", default=3600)
def poll_traffic(pce):
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

    app.log.info("Querying traffic flows (last %dh)...", LOOKBACK_HOURS)

    traffic_query = TrafficQuery.build(
        start_date=start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_date=end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        policy_decisions=["allowed", "blocked", "potentially_blocked", "unknown"],
        max_results=MAX_RESULTS,
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
    src_svc_links = Counter()
    svc_dst_links = Counter()

    def extract_label_group(endpoint):
        lm = {}
        if not isinstance(endpoint, dict):
            return None
        labels_list = endpoint.get("labels", [])
        if not labels_list:
            wl = endpoint.get("workload", {}) or {}
            labels_list = wl.get("labels", [])
        for lbl in (labels_list or []):
            if isinstance(lbl, dict):
                href = lbl.get("href", "")
                if href:
                    key, val = app.resolve_label(href)
                    if key:
                        lm[key] = val
                elif lbl.get("key") and lbl.get("value"):
                    lm[lbl["key"]] = lbl["value"]
        a = lm.get("app", "")
        e = lm.get("env", "")
        if a or e:
            return f"{a}|{e}" if a and e else (a or e)
        return None

    squelched = 0
    for flow in flows:
        src = flow.get("src", {})
        dst = flow.get("dst", {})
        service = flow.get("service", {})

        src_name = (src.get("workload", {}) or {}).get("hostname", "") or src.get("ip", "unknown") if isinstance(src, dict) else "unknown"
        dst_name = (dst.get("workload", {}) or {}).get("hostname", "") or dst.get("ip", "unknown") if isinstance(dst, dict) else "unknown"

        port = service.get("port", "?") if isinstance(service, dict) else "?"
        proto = service.get("proto", "?") if isinstance(service, dict) else "?"
        svc_name = f"{port}/{proto}"
        decision = flow.get("policy_decision", "unknown")

        # Apply squelch rules
        proto_name = {6: "tcp", 17: "udp"}.get(proto, str(proto)) if isinstance(proto, int) else str(proto)
        port_int = int(port) if isinstance(port, int) or (isinstance(port, str) and port.isdigit()) else None
        if is_squelched(flow, src_name, dst_name, port_int, proto_name, decision):
            squelched += 1
            continue

        src_group = extract_label_group(src) or src_name
        dst_group = extract_label_group(dst) or dst_name

        num_connections = flow.get("num_connections", 1)

        src_counter[src_name] += num_connections
        dst_counter[dst_name] += num_connections
        svc_counter[svc_name] += num_connections
        src_svc_links[(src_group, svc_name)] += num_connections
        svc_dst_links[(svc_name, dst_group)] += num_connections

        decisions[decision] += num_connections

        if decision in ("blocked", "potentially_blocked"):
            blocked.append({
                "src": src_name,
                "dst": dst_name,
                "service": svc_name,
                "decision": decision,
                "connections": num_connections,
            })

    sankey = []
    for (src, svc), count in src_svc_links.most_common(30):
        sankey.append({"from": src, "to": svc, "flow": count})
    for (svc, dst), count in svc_dst_links.most_common(30):
        sankey.append({"from": svc, "to": dst + " ", "flow": count})

    squelch_state["squelched_count"] = squelched

    app.update_state({
        "last_poll": datetime.now(timezone.utc).isoformat(),
        "poll_count": app.state.get("poll_count", 0) + 1,
        "total_flows": len(flows),
        "squelched": squelched,
        "visible_flows": len(flows) - squelched,
        "top_sources": src_counter.most_common(20),
        "top_destinations": dst_counter.most_common(20),
        "top_services": svc_counter.most_common(20),
        "blocked_flows": sorted(blocked, key=lambda x: x["connections"], reverse=True)[:50],
        "policy_decisions": dict(decisions),
        "sankey_links": sankey,
        "squelch_rules": [{"type": r["type"], "label": r.get("label", ""), "enabled": r.get("enabled", True)} for r in squelch_state["rules"]],
        "error": None,
    })

    app.log.info("Poll #%d: %d flows (%d squelched), %d blocked",
                 app.state["poll_count"], len(flows), squelched, len(blocked))


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.api("GET", "/api/traffic")
def get_traffic(request):
    return app.state


@app.api("GET", "/api/squelch")
def get_squelch(request):
    return {"rules": squelch_state["rules"], "squelched_count": squelch_state["squelched_count"]}


@app.api("POST", "/api/squelch/add")
def add_squelch(request):
    rule = request.json
    if not rule.get("type"):
        return {"error": "type is required"}, 400
    r = {"type": rule["type"], "label": rule.get("label", ""), "enabled": True}
    if r["type"] == "service":
        r["port"] = rule.get("port")
        r["proto"] = rule.get("proto", "").lower()
    elif r["type"] == "ip":
        r["pattern"] = rule.get("pattern", "")
    elif r["type"] == "subnet":
        try:
            r["network"] = ipaddress.ip_network(rule.get("cidr", ""), strict=False)
        except ValueError:
            return {"error": "invalid CIDR"}, 400
    elif r["type"] == "hostname":
        try:
            r["regex"] = re.compile(rule.get("pattern", ""), re.IGNORECASE)
        except re.error:
            return {"error": "invalid regex"}, 400
    elif r["type"] == "decision":
        r["value"] = rule.get("value", "")
    squelch_state["rules"].append(r)
    app.log.info("Added squelch rule: %s (%s)", r["type"], r.get("label", ""))
    return {"status": "added", "total_rules": len(squelch_state["rules"])}


@app.api("POST", "/api/squelch/toggle")
def toggle_squelch(request):
    idx = request.json.get("index")
    if idx is None or idx < 0 or idx >= len(squelch_state["rules"]):
        return {"error": "invalid index"}, 400
    squelch_state["rules"][idx]["enabled"] = not squelch_state["rules"][idx].get("enabled", True)
    return {"index": idx, "enabled": squelch_state["rules"][idx]["enabled"]}


@app.api("POST", "/api/squelch/remove")
def remove_squelch(request):
    idx = request.json.get("index")
    if idx is None or idx < 0 or idx >= len(squelch_state["rules"]):
        return {"error": "invalid index"}, 400
    removed = squelch_state["rules"].pop(idx)
    app.log.info("Removed squelch rule: %s", removed.get("label", removed["type"]))
    return {"status": "removed", "total_rules": len(squelch_state["rules"])}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Traffic Reporter</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#1e1e2e}::-webkit-scrollbar-thumb{background:#585b70;border-radius:3px}
</style>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen dark">
<div class="max-w-[1400px] mx-auto px-6 py-8">
    <div class="flex items-center justify-between mb-8">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <svg class="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                Traffic Reporter
            </h1>
            <p class="text-gray-500 mt-1">Last """ + str(LOOKBACK_HOURS) + """h of traffic flow analysis</p>
        </div>
        <div id="status" class="text-sm text-gray-400"></div>
    </div>

    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8" id="stats"></div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
            <h2 class="text-lg font-semibold text-white mb-4">Policy Decisions</h2>
            <div style="height:280px"><canvas id="chart-decisions"></canvas></div>
        </div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
            <h2 class="text-lg font-semibold text-white mb-4">Top Services</h2>
            <div style="height:280px"><canvas id="chart-services"></canvas></div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
            <h2 class="text-lg font-semibold text-white mb-4">Top Sources</h2>
            <div style="height:300px"><canvas id="chart-sources"></canvas></div>
        </div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
            <h2 class="text-lg font-semibold text-white mb-4">Top Destinations</h2>
            <div style="height:300px"><canvas id="chart-destinations"></canvas></div>
        </div>
    </div>

    <div class="bg-dark-800 rounded-xl border border-gray-700 overflow-hidden mb-8">
        <div class="px-5 py-3 border-b border-gray-700">
            <h2 class="text-lg font-semibold text-white">Blocked / Potentially Blocked Flows</h2>
        </div>
        <div class="overflow-x-auto max-h-[400px] overflow-y-auto">
            <table class="w-full text-sm">
                <thead class="sticky top-0 bg-dark-800"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
                    <th class="px-4 py-3">Source</th><th class="px-4 py-3">Destination</th>
                    <th class="px-4 py-3">Service</th><th class="px-4 py-3">Decision</th>
                    <th class="px-4 py-3 text-right">Connections</th>
                </tr></thead>
                <tbody id="blocked-table"></tbody>
            </table>
        </div>
    </div>

    <div class="text-center text-xs text-gray-600" id="footer"></div>
</div>

<script>
const BASE = (() => { const m = window.location.pathname.match(/^\\/plugins\\/[^/]+\\/ui/); return m ? m[0] : ''; })();
let chartDecisions, chartServices, chartSources, chartDest;

function formatNum(n) { return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':n.toLocaleString(); }

function initCharts() {
    chartDecisions = new Chart(document.getElementById('chart-decisions'), {
        type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#a6e3a1','#f38ba8','#f9e2af','#6c7086'],borderWidth:0}]},
        options:{responsive:true,maintainAspectRatio:false,cutout:'55%',plugins:{legend:{position:'bottom',labels:{color:'#9ca3af',usePointStyle:true}}}}
    });
    chartServices = new Chart(document.getElementById('chart-services'), {
        type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#89b4fa44',borderColor:'#89b4fa',borderWidth:1,borderRadius:4}]},
        options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280'}},y:{grid:{display:false},ticks:{color:'#a6adc8',font:{size:11,family:'monospace'}}}}}
    });
    chartSources = new Chart(document.getElementById('chart-sources'), {
        type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#cba6f744',borderColor:'#cba6f7',borderWidth:1,borderRadius:4}]},
        options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280'}},y:{grid:{display:false},ticks:{color:'#a6adc8',font:{size:10}}}}}
    });
    chartDest = new Chart(document.getElementById('chart-destinations'), {
        type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#94e2d544',borderColor:'#94e2d5',borderWidth:1,borderRadius:4}]},
        options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280'}},y:{grid:{display:false},ticks:{color:'#a6adc8',font:{size:10}}}}}
    });
}

function update(data) {
    const d = data.policy_decisions || {};
    const totalConn = Object.values(d).reduce((s,v)=>s+v,0);
    const blockedConn = (d.blocked||0)+(d.potentially_blocked||0);

    document.getElementById('stats').innerHTML = `
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-white">${formatNum(data.total_flows||0)}</div><div class="text-xs text-gray-500 mt-1">Total Flows</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-green-400">${formatNum(d.allowed||0)}</div><div class="text-xs text-gray-500 mt-1">Allowed</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-red-400">${formatNum(blockedConn)}</div><div class="text-xs text-gray-500 mt-1">Blocked</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-yellow-400">${totalConn?Math.round(blockedConn/totalConn*100):0}%</div><div class="text-xs text-gray-500 mt-1">Block Rate</div></div>
    `;

    const decLabels = Object.keys(d);
    chartDecisions.data.labels = decLabels;
    chartDecisions.data.datasets[0].data = decLabels.map(k=>d[k]);
    chartDecisions.update('none');

    const svcs = (data.top_services||[]).slice(0,10);
    chartServices.data.labels = svcs.map(s=>s[0]);
    chartServices.data.datasets[0].data = svcs.map(s=>s[1]);
    chartServices.update('none');

    const srcs = (data.top_sources||[]).slice(0,10);
    chartSources.data.labels = srcs.map(s=>s[0].length>30?s[0].substring(0,27)+'...':s[0]);
    chartSources.data.datasets[0].data = srcs.map(s=>s[1]);
    chartSources.update('none');

    const dsts = (data.top_destinations||[]).slice(0,10);
    chartDest.data.labels = dsts.map(s=>s[0].length>30?s[0].substring(0,27)+'...':s[0]);
    chartDest.data.datasets[0].data = dsts.map(s=>s[1]);
    chartDest.update('none');

    const blocked = (data.blocked_flows||[]).slice(0,30);
    const decColor = {blocked:'red',potentially_blocked:'yellow'};
    document.getElementById('blocked-table').innerHTML = blocked.map(b=>`
        <tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
            <td class="px-4 py-2 text-xs"><code>${b.src}</code></td>
            <td class="px-4 py-2 text-xs"><code>${b.dst}</code></td>
            <td class="px-4 py-2 text-xs text-gray-400 font-mono">${b.service}</td>
            <td class="px-4 py-2"><span class="px-1.5 py-0.5 rounded text-[10px] bg-${decColor[b.decision]||'gray'}-900/50 text-${decColor[b.decision]||'gray'}-400">${b.decision}</span></td>
            <td class="px-4 py-2 text-right text-xs text-gray-400 font-mono">${formatNum(b.connections)}</td>
        </tr>
    `).join('');

    document.getElementById('status').textContent = 'Poll #'+(data.poll_count||0)+' · '+(data.last_poll?new Date(data.last_poll).toLocaleTimeString():'never');
    document.getElementById('footer').textContent = data.total_flows+' flows · '+(data.top_sources||[]).length+' sources · '+(data.top_destinations||[]).length+' destinations';
}

async function fetchData() {
    try { const d = await (await fetch(BASE+'/api/traffic')).json(); update(d); } catch(e) { console.error(e); }
}

initCharts(); fetchData(); setInterval(fetchData, 30000);
</script>
</body></html>"""


@app.dashboard
def render():
    return DASHBOARD_HTML


app.run()
