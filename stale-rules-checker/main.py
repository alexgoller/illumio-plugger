#!/usr/bin/env python3
"""
stale-rules-checker — Find blocked traffic and unused rules.

Queries PCE for:
1. Traffic that was blocked/potentially blocked in the last 24h
2. Active rules that had zero matching traffic in the last 24h
3. Groups everything by app|env tuples for segmentation visibility

Serves a web dashboard and writes JSON reports.
"""

import json
import logging
import os
import signal
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

from illumio import PolicyComputeEngine
from illumio.explorer import TrafficQuery

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("stale_rules_checker")

state_lock = threading.Lock()
report_state = {
    "last_check": None,
    "check_count": 0,
    "error": None,
    # Blocked traffic grouped by app|env
    "blocked_pairs": [],       # [{src_group, dst_group, services, total_connections, flows}]
    "blocked_summary": {},     # total blocked connections, unique pairs, etc.
    # Stale rules (active rules with no traffic)
    "stale_rules": [],         # [{ruleset, rule, scopes, services, reason}]
    "suggested_rules": [],     # high-volume blocked pairs
    "auto_rules": [],          # PCE-ready rule JSON for intra-app|env
    "stale_summary": {},
    # Label cache
    "label_count": 0,
}

label_cache = {}  # href -> {"key": "...", "value": "..."}


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


def resolve_label(href):
    """Resolve a label href to key=value."""
    if href in label_cache:
        c = label_cache[href]
        return c["key"], c["value"]
    return None, None


def endpoint_to_group(endpoint):
    """Extract app|env from a flow endpoint."""
    if not isinstance(endpoint, dict):
        return None

    labels = endpoint.get("labels", [])
    if not labels:
        wl = endpoint.get("workload", {}) or {}
        labels = wl.get("labels", [])

    if not labels:
        return None

    label_map = {}
    for lbl in labels if isinstance(labels, list) else []:
        if isinstance(lbl, dict):
            href = lbl.get("href", "")
            if href:
                key, val = resolve_label(href)
                if key:
                    label_map[key] = val
            elif lbl.get("key") and lbl.get("value"):
                label_map[lbl["key"]] = lbl["value"]

    app = label_map.get("app", "")
    env = label_map.get("env", "")
    if app or env:
        return f"{app}|{env}" if app and env else (app or env)
    return None


def endpoint_name(endpoint):
    """Get hostname or IP from endpoint."""
    if not isinstance(endpoint, dict):
        return "unknown"
    return (endpoint.get("workload", {}) or {}).get("hostname", "") or endpoint.get("ip", "unknown")


def analyze_traffic(pce):
    """Query blocked traffic and build analysis."""
    lookback = int(os.environ.get("LOOKBACK_HOURS", "24"))
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback)

    log.info("Querying blocked traffic (last %dh)...", lookback)

    # Query blocked/potentially blocked traffic
    query = TrafficQuery.build(
        start_date=start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_date=end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        policy_decisions=["blocked", "potentially_blocked"],
        max_results=int(os.environ.get("MAX_RESULTS", "10000")),
    )

    raw_flows = pce.get_traffic_flows_async(
        query_name="plugger-stale-rules",
        traffic_query=query,
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

    log.info("Got %d blocked flows", len(flows))

    # Group blocked traffic by app|env pairs
    pair_data = defaultdict(lambda: {"connections": 0, "services": Counter(), "hosts": set(), "decision": Counter()})

    for flow in flows:
        src = flow.get("src", {})
        dst = flow.get("dst", {})
        service = flow.get("service", {})
        num = flow.get("num_connections", 1)
        decision = flow.get("policy_decision", "blocked")

        src_group = endpoint_to_group(src) or endpoint_name(src)
        dst_group = endpoint_to_group(dst) or endpoint_name(dst)

        port = service.get("port", "?") if isinstance(service, dict) else "?"
        proto = service.get("proto", "?") if isinstance(service, dict) else "?"
        svc = f"{port}/{proto}"

        key = (src_group, dst_group)
        pair_data[key]["connections"] += num
        pair_data[key]["services"][svc] += num
        pair_data[key]["decision"][decision] += num
        pair_data[key]["hosts"].add(endpoint_name(src))
        pair_data[key]["hosts"].add(endpoint_name(dst))

    # Sort by connections
    blocked_pairs = []
    for (src_g, dst_g), data in sorted(pair_data.items(), key=lambda x: -x[1]["connections"]):
        blocked_pairs.append({
            "src_group": src_g,
            "dst_group": dst_g,
            "total_connections": data["connections"],
            "services": data["services"].most_common(10),
            "decisions": dict(data["decision"]),
            "host_count": len(data["hosts"]),
        })

    total_blocked = sum(d["connections"] for d in pair_data.values())
    unique_pairs = len(pair_data)

    return blocked_pairs, {
        "total_blocked_connections": total_blocked,
        "unique_pairs": unique_pairs,
        "total_flows": len(flows),
        "lookback_hours": lookback,
    }


def find_stale_rules(pce, blocked_pairs):
    """Find active rules that might be stale or missing."""
    log.info("Checking active rulesets...")

    stale = []
    try:
        resp = pce.get("/sec_policy/active/rule_sets")
        rulesets = resp.json() if resp.status_code == 200 else []

        for rs in rulesets:
            if not isinstance(rs, dict):
                continue
            rs_name = rs.get("name", "")
            rules = rs.get("rules", [])
            enabled = rs.get("enabled", True)

            if not enabled:
                stale.append({
                    "ruleset": rs_name,
                    "rule_count": len(rules),
                    "enabled": False,
                    "reason": "Ruleset is disabled",
                    "severity": "info",
                })
                continue

            if not rules:
                stale.append({
                    "ruleset": rs_name,
                    "rule_count": 0,
                    "enabled": True,
                    "reason": "Ruleset has no rules",
                    "severity": "warning",
                })

            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                if not rule.get("enabled", True):
                    stale.append({
                        "ruleset": rs_name,
                        "rule": rule.get("href", ""),
                        "enabled": False,
                        "reason": "Rule is disabled within active ruleset",
                        "severity": "info",
                    })

    except Exception as e:
        log.warning("Failed to fetch rulesets: %s", e)

    # Check for blocked pairs that suggest missing rules
    suggested_rules = []
    for pair in blocked_pairs[:20]:  # top 20 blocked pairs
        if pair["total_connections"] > 100:
            suggested_rules.append({
                "src": pair["src_group"],
                "dst": pair["dst_group"],
                "services": [s[0] for s in pair["services"][:5]],
                "connections": pair["total_connections"],
                "reason": f"High-volume blocked traffic ({pair['total_connections']:,} connections) — may need a rule",
                "severity": "high",
            })

    # Build auto-suggest rules for intra-app|env blocked traffic
    auto_rules = build_auto_suggestions(pce, blocked_pairs)

    return stale, suggested_rules, auto_rules, {
        "stale_rulesets": len([s for s in stale if "Ruleset" in s.get("reason", "")]),
        "disabled_rules": len([s for s in stale if "disabled" in s.get("reason", "").lower()]),
        "suggested_rules": len(suggested_rules),
        "auto_rules": len(auto_rules),
    }


# Proto number to name mapping
PROTO_MAP = {"6": "tcp", "17": "udp"}


def build_auto_suggestions(pce, blocked_pairs):
    """Build PCE-ready rule suggestions for same app|env blocked pairs."""
    # Resolve label values to hrefs for rule building
    value_to_href = {}
    for href, info in label_cache.items():
        key_val = (info["key"], info["value"])
        value_to_href[key_val] = href

    # Fetch existing services to match port/proto
    svc_by_port = {}
    try:
        resp = pce.get("/sec_policy/active/services")
        if resp.status_code == 200:
            for svc in resp.json():
                if isinstance(svc, dict):
                    for sp in svc.get("service_ports", []):
                        if isinstance(sp, dict):
                            port = sp.get("port")
                            proto = sp.get("proto")
                            if port and proto:
                                svc_by_port[(port, proto)] = {
                                    "href": svc.get("href", ""),
                                    "name": svc.get("name", ""),
                                }
    except Exception:
        pass

    auto_rules = []

    for pair in blocked_pairs:
        src_g = pair["src_group"]
        dst_g = pair["dst_group"]

        # Only auto-suggest for same app|env (intra-scope)
        if src_g != dst_g:
            continue

        if pair["total_connections"] < 10:
            continue

        # Parse the app|env tuple
        parts = src_g.split("|")
        if len(parts) != 2:
            continue
        app_val, env_val = parts[0], parts[1]

        app_href = value_to_href.get(("app", app_val), "")
        env_href = value_to_href.get(("env", env_val), "")

        if not app_href or not env_href:
            continue

        # Build service list from blocked traffic
        rule_services = []
        for svc_str, count in pair["services"]:
            try:
                port_s, proto_s = svc_str.split("/")
                port = int(port_s)
                proto = int(proto_s)
                proto_name = PROTO_MAP.get(str(proto), str(proto))

                # Check if a named service exists
                existing = svc_by_port.get((port, proto))
                if existing:
                    rule_services.append({
                        "href": existing["href"],
                        "name": existing["name"],
                        "port": port,
                        "proto": proto_name,
                        "connections": count,
                    })
                else:
                    rule_services.append({
                        "port": port,
                        "proto": proto_name,
                        "connections": count,
                    })
            except (ValueError, IndexError):
                continue

        if not rule_services:
            continue

        # Build the PCE-compatible rule JSON
        scope_labels = [{"href": app_href}, {"href": env_href}]

        ingress_services = []
        for rs in rule_services:
            if "href" in rs and rs["href"]:
                ingress_services.append({"href": rs["href"]})
            else:
                proto_num = 6 if rs["proto"] == "tcp" else 17 if rs["proto"] == "udp" else int(rs["proto"])
                ingress_services.append({"port": rs["port"], "proto": proto_num})

        rule_json = {
            "enabled": True,
            "providers": [{"actors": "ams"}],    # all workloads in scope
            "consumers": [{"actors": "ams"}],    # all workloads in scope
            "ingress_services": ingress_services,
            "resolve_labels_as": {
                "providers": ["workloads"],
                "consumers": ["workloads"],
            },
        }

        ruleset_json = {
            "name": f"plugger-auto | {app_val} | {env_val}",
            "enabled": True,
            "scopes": [scope_labels],
            "rules": [rule_json],
        }

        auto_rules.append({
            "app_env": src_g,
            "app": app_val,
            "env": env_val,
            "app_href": app_href,
            "env_href": env_href,
            "services": rule_services,
            "total_connections": pair["total_connections"],
            "host_count": pair["host_count"],
            "ruleset_json": ruleset_json,
            "rule_json": rule_json,
        })

    # Sort by connections
    auto_rules.sort(key=lambda x: -x["total_connections"])
    return auto_rules


def run_check(pce):
    """Full analysis cycle."""
    if not label_cache:
        fetch_labels(pce)

    try:
        blocked_pairs, blocked_summary = analyze_traffic(pce)
        stale_rules, suggested_rules, auto_rules, stale_summary = find_stale_rules(pce, blocked_pairs)

        with state_lock:
            report_state["last_check"] = datetime.now(timezone.utc).isoformat()
            report_state["check_count"] += 1
            report_state["blocked_pairs"] = blocked_pairs
            report_state["blocked_summary"] = blocked_summary
            report_state["stale_rules"] = stale_rules
            report_state["suggested_rules"] = suggested_rules
            report_state["auto_rules"] = auto_rules
            report_state["stale_summary"] = stale_summary
            report_state["label_count"] = len(label_cache)
            report_state["error"] = None

        log.info("Check #%d: %d blocked pairs (%d connections), %d stale rules, %d suggestions, %d auto-rules",
                 report_state["check_count"], len(blocked_pairs),
                 blocked_summary["total_blocked_connections"],
                 len(stale_rules), len(suggested_rules), len(auto_rules))

    except Exception as e:
        log.exception("Analysis failed")
        with state_lock:
            report_state["error"] = str(e)


def poller_loop(pce):
    interval = int(os.environ.get("POLL_INTERVAL", "300"))
    while True:
        run_check(pce)
        time.sleep(interval)


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Stale Rules Checker</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>
tailwind.config = { darkMode: 'class', theme: { extend: { colors: { dark: { 700: '#313244', 800: '#1e1e2e', 900: '#11111b' } } } } }
</script>
<style>
@keyframes fadeIn { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:translateY(0); } }
.fade-in { animation: fadeIn 0.3s ease-out; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #1e1e2e; }
::-webkit-scrollbar-thumb { background: #585b70; border-radius: 3px; }
.tab-active { border-bottom: 2px solid #93c5fd; color: #93c5fd; }
.tab-inactive { border-bottom: 2px solid transparent; color: #6b7280; }
.tab-inactive:hover { color: #9ca3af; }
</style>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen dark">
<div class="max-w-[1400px] mx-auto px-6 py-8">

    <div class="flex items-center justify-between mb-8 fade-in">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <svg class="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/>
                </svg>
                Stale Rules Checker
            </h1>
            <p class="text-gray-500 mt-1">Blocked traffic analysis and rule gap detection</p>
        </div>
        <div class="flex items-center gap-3">
            <div id="status-dot" class="w-3 h-3 rounded-full bg-gray-600"></div>
            <span id="status-text" class="text-sm text-gray-400">Loading...</span>
        </div>
    </div>

    <!-- Stats -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8" id="stats"></div>

    <!-- Tabs -->
    <div class="flex gap-6 border-b border-gray-700 mb-6">
        <button onclick="showTab('blocked')" id="tab-blocked" class="pb-3 text-sm font-medium tab-active cursor-pointer">Blocked Traffic</button>
        <button onclick="showTab('suggested')" id="tab-suggested" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Suggested Rules</button>
        <button onclick="showTab('auto')" id="tab-auto" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Auto-Suggest Rules</button>
        <button onclick="showTab('stale')" id="tab-stale" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Stale Rules</button>
        <button onclick="showTab('chart')" id="tab-chart" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Charts</button>
    </div>

    <div id="panel-blocked"></div>
    <div id="panel-suggested" style="display:none;"></div>
    <div id="panel-auto" style="display:none;"></div>
    <div id="panel-stale" style="display:none;"></div>
    <div id="panel-chart" style="display:none;">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="bg-dark-800 rounded-xl border border-gray-700 p-6"><h2 class="text-lg font-semibold text-white mb-4">Top Blocked Pairs</h2><div style="height:350px;"><canvas id="chart-blocked"></canvas></div></div>
            <div class="bg-dark-800 rounded-xl border border-gray-700 p-6"><h2 class="text-lg font-semibold text-white mb-4">Blocked Services</h2><div style="height:350px;"><canvas id="chart-services"></canvas></div></div>
        </div>
    </div>

    <div class="text-center text-xs text-gray-600 mt-8">
        <span id="footer"></span> &middot; <a id="api-link" href="/api/report" class="text-blue-500 hover:text-blue-400">JSON API</a>
    </div>
</div>

<script>
const BASE = (() => { const m = window.location.pathname.match(/^(\/plugins\/[^/]+\/ui)/); return m ? m[1] : ''; })();
const tabs = ['blocked','suggested','auto','stale','chart'];
let chartBlocked, chartServices;

function showTab(name) {
    tabs.forEach(t => {
        document.getElementById('panel-'+t).style.display = t===name?'block':'none';
        document.getElementById('tab-'+t).className = 'pb-3 text-sm font-medium cursor-pointer '+(t===name?'tab-active':'tab-inactive');
    });
}

function formatNum(n) {
    if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
    if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
    return n.toLocaleString();
}

function initCharts() {
    const barOpts = {
        responsive:true, maintainAspectRatio:false, indexAxis:'y',
        plugins: { legend:{display:false}, tooltip:{backgroundColor:'#1e1e2e',borderColor:'#313244',borderWidth:1,titleColor:'#cdd6f4',bodyColor:'#a6adc8',padding:12,cornerRadius:8} },
        scales: { x:{grid:{color:'#31324422'},ticks:{color:'#6b7280',callback:v=>formatNum(v)}}, y:{grid:{display:false},ticks:{color:'#a6adc8',font:{size:11,family:'monospace'}}} }
    };
    chartBlocked = new Chart(document.getElementById('chart-blocked'), {
        type:'bar', data:{labels:[],datasets:[{data:[],backgroundColor:'#ef444444',borderColor:'#ef4444',borderWidth:1,borderRadius:4}]}, options:barOpts
    });
    chartServices = new Chart(document.getElementById('chart-services'), {
        type:'bar', data:{labels:[],datasets:[{data:[],backgroundColor:'#f9731644',borderColor:'#f97316',borderWidth:1,borderRadius:4}]}, options:barOpts
    });
}

function severityColor(s) { return s==='high'?'red':s==='warning'?'yellow':'blue'; }

function update(data) {
    const bs = data.blocked_summary || {};
    const ss = data.stale_summary || {};

    // Stats
    document.getElementById('stats').innerHTML = `
        <div class="bg-dark-800 rounded-xl border border-red-900/30 p-5 fade-in"><div class="text-3xl font-bold text-red-400">${formatNum(bs.total_blocked_connections||0)}</div><div class="text-xs text-gray-500 mt-1">Blocked Connections</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in"><div class="text-3xl font-bold text-orange-400">${bs.unique_pairs||0}</div><div class="text-xs text-gray-500 mt-1">Blocked App|Env Pairs</div></div>
        <div class="bg-dark-800 rounded-xl border border-emerald-900/30 p-5 fade-in"><div class="text-3xl font-bold text-emerald-400">${(data.auto_rules||[]).length}</div><div class="text-xs text-gray-500 mt-1">Auto-Suggest Rules</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in"><div class="text-3xl font-bold text-gray-400">${(data.stale_rules||[]).length}</div><div class="text-xs text-gray-500 mt-1">Stale/Disabled Rules</div></div>
    `;

    // Status
    if (data.error) {
        document.getElementById('status-dot').className='w-3 h-3 rounded-full bg-red-500';
        document.getElementById('status-text').textContent='Error';
    } else {
        document.getElementById('status-dot').className='w-3 h-3 rounded-full bg-green-500 animate-pulse';
        document.getElementById('status-text').textContent='Live';
    }

    // Blocked pairs table
    const pairs = data.blocked_pairs || [];
    document.getElementById('panel-blocked').innerHTML = pairs.length ? `
        <div class="bg-dark-800 rounded-xl border border-gray-700 overflow-hidden">
            <table class="w-full text-sm">
                <thead><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
                    <th class="px-4 py-3">Source (app|env)</th><th class="px-4 py-3">Destination (app|env)</th>
                    <th class="px-4 py-3">Services</th><th class="px-4 py-3 text-right">Connections</th><th class="px-4 py-3 text-right">Hosts</th>
                </tr></thead>
                <tbody>${pairs.map(p => `
                    <tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
                        <td class="px-4 py-2.5"><code class="text-xs bg-red-900/20 text-red-300 px-1.5 py-0.5 rounded">${p.src_group}</code></td>
                        <td class="px-4 py-2.5"><code class="text-xs bg-orange-900/20 text-orange-300 px-1.5 py-0.5 rounded">${p.dst_group}</code></td>
                        <td class="px-4 py-2.5"><span class="text-xs text-gray-400">${p.services.map(s=>s[0]).join(', ')}</span></td>
                        <td class="px-4 py-2.5 text-right font-mono text-red-400">${formatNum(p.total_connections)}</td>
                        <td class="px-4 py-2.5 text-right text-gray-500">${p.host_count}</td>
                    </tr>
                `).join('')}</tbody>
            </table>
        </div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">No Blocked Traffic</div><div class="text-gray-500 mt-2">No blocked or potentially blocked flows in the last '+bs.lookback_hours+'h.</div></div>';

    // Suggested rules
    const suggested = data.suggested_rules || [];
    document.getElementById('panel-suggested').innerHTML = suggested.length ? `
        <div class="space-y-3">${suggested.map(s => `
            <div class="bg-dark-800 rounded-xl border border-${severityColor(s.severity)}-900/30 p-4">
                <div class="flex items-center gap-3 mb-2">
                    <span class="px-2 py-0.5 rounded text-xs font-medium bg-${severityColor(s.severity)}-900/50 text-${severityColor(s.severity)}-400">${s.severity}</span>
                    <span class="text-white font-medium"><code>${s.src}</code> → <code>${s.dst}</code></span>
                    <span class="text-gray-500 text-xs ml-auto">${formatNum(s.connections)} connections</span>
                </div>
                <div class="text-sm text-gray-400">${s.reason}</div>
                <div class="flex gap-1 mt-2">${s.services.map(svc => `<span class="text-xs bg-dark-700 text-gray-400 px-1.5 py-0.5 rounded">${svc}</span>`).join('')}</div>
            </div>
        `).join('')}</div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">No Suggestions</div><div class="text-gray-500 mt-2">No high-volume blocked traffic patterns detected.</div></div>';

    // Auto-suggest rules (intra app|env)
    const autoRules = data.auto_rules || [];
    document.getElementById('panel-auto').innerHTML = autoRules.length ? `
        <div class="space-y-4">${autoRules.map((r, i) => `
            <div class="bg-dark-800 rounded-xl border border-emerald-900/30 p-5">
                <div class="flex items-center justify-between mb-3">
                    <div class="flex items-center gap-3">
                        <span class="px-2.5 py-1 rounded-lg text-sm font-semibold bg-emerald-900/40 text-emerald-400">${r.app_env}</span>
                        <span class="text-gray-400 text-sm">Intra-scope rule</span>
                    </div>
                    <div class="flex items-center gap-3 text-xs text-gray-500">
                        <span>${formatNum(r.total_connections)} blocked connections</span>
                        <span>${r.host_count} hosts</span>
                    </div>
                </div>
                <div class="flex flex-wrap gap-1.5 mb-3">
                    ${r.services.map(s => `<span class="text-xs px-2 py-0.5 rounded ${s.name ? 'bg-blue-900/30 text-blue-300' : 'bg-dark-700 text-gray-400'}">${s.name || s.port+'/'+s.proto} <span class="text-gray-500">(${formatNum(s.connections)})</span></span>`).join('')}
                </div>
                <details class="group">
                    <summary class="text-xs text-blue-400 cursor-pointer hover:text-blue-300">Show ruleset JSON (ready to provision)</summary>
                    <div class="mt-2 bg-dark-900 rounded-lg p-3 overflow-x-auto">
                        <pre class="text-xs text-gray-300 font-mono whitespace-pre">${JSON.stringify(r.ruleset_json, null, 2)}</pre>
                    </div>
                    <div class="mt-2 flex gap-2">
                        <button onclick="navigator.clipboard.writeText(JSON.stringify(autoRules[${i}].ruleset_json, null, 2));this.textContent='Copied!';setTimeout(()=>this.textContent='Copy JSON',2000)"
                            class="px-3 py-1 text-xs rounded bg-dark-700 text-gray-300 hover:bg-dark-700/80 transition-colors">Copy JSON</button>
                    </div>
                </details>
            </div>
        `).join('')}</div>
        <div class="mt-4 p-4 bg-dark-800 rounded-xl border border-gray-700">
            <p class="text-xs text-gray-500">These rules allow all workloads within the same app|env scope to communicate on the observed blocked ports. Review before provisioning — you may want to restrict to specific roles.</p>
        </div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">No Auto-Suggestions</div><div class="text-gray-500 mt-2">No intra-app|env blocked traffic detected.</div></div>';

    // Stale rules
    const stale = data.stale_rules || [];
    document.getElementById('panel-stale').innerHTML = stale.length ? `
        <div class="space-y-2">${stale.map(s => `
            <div class="bg-dark-800 rounded-xl border border-gray-700 p-4 flex items-center gap-3">
                <span class="px-2 py-0.5 rounded text-xs font-medium bg-${severityColor(s.severity)}-900/50 text-${severityColor(s.severity)}-400">${s.severity}</span>
                <span class="text-white font-medium">${s.ruleset}</span>
                <span class="text-sm text-gray-400">${s.reason}</span>
            </div>
        `).join('')}</div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">All Rules Active</div><div class="text-gray-500 mt-2">No disabled or empty rulesets found.</div></div>';

    // Charts
    const topPairs = pairs.slice(0, 10);
    chartBlocked.data.labels = topPairs.map(p => p.src_group + ' → ' + p.dst_group);
    chartBlocked.data.datasets[0].data = topPairs.map(p => p.total_connections);
    chartBlocked.update('none');

    const svcCounter = {};
    pairs.forEach(p => p.services.forEach(([svc, count]) => { svcCounter[svc] = (svcCounter[svc]||0) + count; }));
    const topSvcs = Object.entries(svcCounter).sort((a,b) => b[1]-a[1]).slice(0, 10);
    chartServices.data.labels = topSvcs.map(s => s[0]);
    chartServices.data.datasets[0].data = topSvcs.map(s => s[1]);
    chartServices.update('none');

    document.getElementById('footer').textContent = `Check #${data.check_count} · ${data.last_check ? new Date(data.last_check).toLocaleTimeString() : 'never'} · ${data.label_count} labels cached`;
}

async function fetchData() {
    try { update(await (await fetch(BASE + '/api/report')).json()); } catch(e) { console.error(e); }
}

initCharts();
document.getElementById('api-link').href = BASE + '/api/report';
fetchData();
setInterval(fetchData, 30000);
</script>
</body></html>"""


class ReportHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/report":
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
    log.info("Starting stale-rules-checker...")
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce = get_pce()
    log.info("Connected to PCE: %s", pce.base_url)

    poller = threading.Thread(target=poller_loop, args=(pce,), daemon=True)
    poller.start()
    run_check(pce)

    server = HTTPServer(("0.0.0.0", port), ReportHandler)
    log.info("Dashboard on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
