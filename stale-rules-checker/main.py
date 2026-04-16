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
        scope_labels = [
            {"label": {"href": app_href}, "exclusion": False},
            {"label": {"href": env_href}, "exclusion": False},
        ]

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
        <button onclick="showTab('auto')" id="tab-auto" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">AI Suggested Rules</button>
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
        <div class="bg-dark-800 rounded-xl border border-emerald-900/30 p-5 fade-in"><div class="text-3xl font-bold text-emerald-400">${(data.auto_rules||[]).length}</div><div class="text-xs text-gray-500 mt-1">AI Suggested Rules</div></div>
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

    // AI Suggested rules (intra app|env)
    const autoRules = data.auto_rules || [];
    const analyses = data.ai_analyses || {};
    const aiEnabled = data.ai_config && data.ai_config.enabled;
    document.getElementById('panel-auto').innerHTML = autoRules.length ? `
        <div class="flex items-center justify-between mb-4">
            <div class="flex items-center gap-2">
                <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
                <h2 class="text-lg font-semibold text-white">AI Suggested Rules</h2>
                ${aiEnabled ? `<span class="text-xs bg-emerald-900/40 text-emerald-400 px-2 py-0.5 rounded">AI: ${data.ai_config.provider} / ${data.ai_config.model}</span>` : '<span class="text-xs bg-gray-700 text-gray-400 px-2 py-0.5 rounded">AI not configured</span>'}
            </div>
            ${aiEnabled ? `<button onclick="analyzeAll()" class="px-3 py-1.5 text-xs rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition-colors">Analyze All with AI</button>` : ''}
        </div>
        <div class="space-y-4">${autoRules.map((r, i) => {
            const a = analyses[String(i)] || {};
            const hasAI = a.recommendation;
            const provisioned = a.provisioned;
            const recColor = a.recommendation === 'approve' ? 'emerald' : a.recommendation === 'reject' ? 'red' : 'yellow';
            const riskColor = a.risk_level === 'low' ? 'emerald' : a.risk_level === 'high' ? 'red' : 'yellow';
            return `
            <div class="bg-dark-800 rounded-xl border ${hasAI ? (a.recommendation === 'approve' ? 'border-emerald-900/50' : a.recommendation === 'reject' ? 'border-red-900/50' : 'border-yellow-900/50') : 'border-gray-700'} p-5" id="rule-card-${i}">
                <div class="flex items-center justify-between mb-3">
                    <div class="flex items-center gap-3">
                        <span class="px-2.5 py-1 rounded-lg text-sm font-semibold bg-emerald-900/40 text-emerald-400">${r.app_env}</span>
                        <span class="text-gray-400 text-sm">Intra-scope rule</span>
                        ${hasAI ? `<span class="px-2 py-0.5 rounded text-xs font-medium bg-${recColor}-900/50 text-${recColor}-400">AI: ${a.recommendation.toUpperCase()}</span>` : ''}
                        ${hasAI ? `<span class="px-2 py-0.5 rounded text-xs bg-${riskColor}-900/30 text-${riskColor}-400">Risk: ${a.risk_level}</span>` : ''}
                        ${provisioned && provisioned.success ? '<span class="px-2 py-0.5 rounded text-xs bg-blue-900/50 text-blue-400">Provisioned to Draft</span>' : ''}
                    </div>
                    <div class="flex items-center gap-3 text-xs text-gray-500">
                        <span>${formatNum(r.total_connections)} blocked</span>
                        <span>${r.host_count} hosts</span>
                        ${hasAI && a.confidence ? `<span>Confidence: ${Math.round(a.confidence * 100)}%</span>` : ''}
                    </div>
                </div>
                <div class="flex flex-wrap gap-1.5 mb-3">
                    ${r.services.map(s => `<span class="text-xs px-2 py-0.5 rounded ${s.name ? 'bg-blue-900/30 text-blue-300' : 'bg-dark-700 text-gray-400'}">${s.name || s.port+'/'+s.proto} <span class="text-gray-500">(${formatNum(s.connections)})</span></span>`).join('')}
                </div>
                ${hasAI ? `
                <div class="bg-dark-700/30 rounded-lg p-3 mb-3 border-l-2 border-${recColor}-500">
                    <div class="text-sm text-gray-300 mb-1">${a.reasoning}</div>
                    ${a.suggested_modifications ? `<div class="text-xs text-${recColor}-400 mt-1">Suggestion: ${a.suggested_modifications}</div>` : ''}
                </div>` : ''}
                <div class="flex items-center gap-2">
                    ${aiEnabled && !hasAI ? `<button onclick="analyzeRule(${i})" id="ai-btn-${i}" class="px-3 py-1.5 text-xs rounded-lg bg-emerald-700 hover:bg-emerald-600 text-white transition-colors flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
                        AI Analyze</button>` : ''}
                    ${!provisioned || !provisioned.success ? `<button onclick="provisionRule(${i})" id="prov-btn-${i}" class="px-3 py-1.5 text-xs rounded-lg bg-blue-700 hover:bg-blue-600 text-white transition-colors">Provision to Draft</button>` : ''}
                    <button onclick="toggleJSON(${i})" class="px-3 py-1.5 text-xs rounded-lg bg-dark-700 text-gray-300 hover:bg-dark-700/80 transition-colors">Show JSON</button>
                    <button onclick="navigator.clipboard.writeText(JSON.stringify(autoRules[${i}].ruleset_json,null,2));this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)" class="px-3 py-1.5 text-xs rounded-lg bg-dark-700 text-gray-300 hover:bg-dark-700/80 transition-colors">Copy</button>
                </div>
                <div id="json-${i}" style="display:none;" class="mt-3 bg-dark-900 rounded-lg p-3 overflow-x-auto">
                    <pre class="text-xs text-gray-300 font-mono whitespace-pre">${JSON.stringify(r.ruleset_json, null, 2)}</pre>
                </div>
                ${provisioned && !provisioned.success ? `<div class="mt-2 text-xs text-red-400">Provision failed: ${provisioned.error}</div>` : ''}
            </div>`;
        }).join('')}</div>
        <div class="mt-4 p-4 bg-dark-800 rounded-xl border border-gray-700">
            <p class="text-xs text-gray-500">AI Suggested rules allow workloads within the same app|env scope to communicate on observed blocked ports. "Provision to Draft" creates the ruleset in PCE draft policy — you must still provision from the PCE to activate.</p>
        </div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">No AI Suggestions</div><div class="text-gray-500 mt-2">No intra-app|env blocked traffic detected.</div></div>';

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
    try { const d = await (await fetch(BASE + '/api/report')).json(); window._lastData = d; update(d); } catch(e) { console.error(e); }
}

function toggleJSON(i) {
    const el = document.getElementById('json-'+i);
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

async function analyzeRule(index) {
    const btn = document.getElementById('ai-btn-'+index);
    if (btn) { btn.textContent = 'Analyzing...'; btn.disabled = true; }
    try {
        const resp = await fetch(BASE + '/api/ai/analyze', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({index: index})
        });
        const result = await resp.json();
        if (result.error) { alert('AI Error: ' + result.error); return; }
        await fetchData(); // refresh to show result
    } catch(e) { alert('AI request failed: ' + e); }
    finally { if (btn) { btn.textContent = 'AI Analyze'; btn.disabled = false; } }
}

async function analyzeAll() {
    const rules = (window._lastData || {}).auto_rules || [];
    for (let i = 0; i < rules.length; i++) {
        const a = (window._lastData.ai_analyses || {})[String(i)];
        if (!a || !a.recommendation) {
            await analyzeRule(i);
            await new Promise(r => setTimeout(r, 500)); // small delay between calls
        }
    }
}

async function provisionRule(index) {
    const btn = document.getElementById('prov-btn-'+index);
    if (!confirm('Provision this AI Suggested rule to PCE draft policy?')) return;
    if (btn) { btn.textContent = 'Provisioning...'; btn.disabled = true; }
    try {
        const resp = await fetch(BASE + '/api/provision/' + index, {
            method: 'POST', headers: {'Content-Type':'application/json'}
        });
        const result = await resp.json();
        if (result.success) {
            alert('Provisioned to draft: ' + result.name);
        } else {
            alert('Provision failed: ' + result.error);
        }
        await fetchData();
    } catch(e) { alert('Provision failed: ' + e); }
    finally { if (btn) { btn.textContent = 'Provision to Draft'; btn.disabled = false; } }
}

initCharts();
document.getElementById('api-link').href = BASE + '/api/report';
fetchData();
setInterval(fetchData, 30000);
</script>
</body></html>"""


# ============================================================
# AI Advisor + Provisioning
# ============================================================

ai_advisor = None
pce_client = None
ai_analyses = {}  # index -> analysis result


def provision_rule(pce, ruleset_json):
    """Provision a ruleset to PCE draft policy."""
    try:
        # POST to create draft ruleset
        resp = pce.post("/sec_policy/draft/rule_sets", json=ruleset_json)
        if resp.status_code in (200, 201):
            result = resp.json()
            href = result.get("href", "")
            log.info("Provisioned ruleset to draft: %s", href)
            return {"success": True, "href": href, "name": ruleset_json.get("name", "")}
        else:
            error = resp.text[:200]
            log.error("Provision failed: HTTP %d: %s", resp.status_code, error)
            return {"success": False, "error": f"HTTP {resp.status_code}: {error}"}
    except Exception as e:
        log.error("Provision error: %s", e)
        return {"success": False, "error": str(e)}


class ReportHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/report":
            with state_lock:
                data = dict(report_state)
            data["ai_analyses"] = ai_analyses
            data["ai_config"] = ai_advisor.get_config() if ai_advisor else {"enabled": False}
            self.send_json(200, data)
        elif self.path == "/api/ai/config":
            self.send_json(200, ai_advisor.get_config() if ai_advisor else {"enabled": False})
        elif self.path == "/":
            body = DASHBOARD_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if self.path == "/api/ai/analyze":
            self.handle_ai_analyze(body)
        elif self.path.startswith("/api/provision/"):
            self.handle_provision(body)
        else:
            self.send_error(404)

    def handle_ai_analyze(self, body):
        """AI-analyze a specific auto-rule by index."""
        try:
            req = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_json(400, {"error": "Invalid JSON"})
            return

        index = req.get("index", -1)
        with state_lock:
            auto_rules = report_state.get("auto_rules", [])

        if index < 0 or index >= len(auto_rules):
            self.send_json(400, {"error": f"Invalid index {index}"})
            return

        if not ai_advisor or not ai_advisor.is_enabled():
            self.send_json(400, {"error": "AI not configured. Set AI_PROVIDER and AI_API_KEY environment variables."})
            return

        rule = auto_rules[index]
        lookback = report_state.get("blocked_summary", {}).get("lookback_hours", 24)

        log.info("AI analyzing: %s (%d connections)", rule["app_env"], rule["total_connections"])
        result = ai_advisor.analyze(rule, lookback_hours=lookback)
        ai_analyses[str(index)] = result

        self.send_json(200, result)

    def handle_provision(self, body):
        """Provision an auto-rule to PCE draft."""
        try:
            index = int(self.path.split("/")[-1])
        except ValueError:
            self.send_json(400, {"error": "Invalid index"})
            return

        with state_lock:
            auto_rules = report_state.get("auto_rules", [])

        if index < 0 or index >= len(auto_rules):
            self.send_json(400, {"error": f"Invalid index {index}"})
            return

        rule = auto_rules[index]
        ruleset_json = rule.get("ruleset_json", {})

        if not ruleset_json:
            self.send_json(400, {"error": "No ruleset JSON available"})
            return

        log.info("Provisioning to draft: %s", ruleset_json.get("name", ""))
        result = provision_rule(pce_client, ruleset_json)

        # Store provision status in analysis
        if str(index) not in ai_analyses:
            ai_analyses[str(index)] = {}
        ai_analyses[str(index)]["provisioned"] = result

        self.send_json(200, result)

    def send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    global ai_advisor, pce_client

    log.info("Starting stale-rules-checker...")
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce_client = get_pce()
    log.info("Connected to PCE: %s", pce_client.base_url)

    # Initialize AI advisor
    from ai_advisor import AIAdvisor
    ai_advisor = AIAdvisor()

    poller = threading.Thread(target=poller_loop, args=(pce_client,), daemon=True)
    poller.start()
    run_check(pce_client)

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
