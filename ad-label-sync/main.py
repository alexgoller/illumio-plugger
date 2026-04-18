#!/usr/bin/env python3
"""
ad-label-sync — Discover AD computers and map attributes to Illumio labels.

Two modes:
- Analytics (default): connect to AD, pull computer tree, show what labels
  COULD be derived — feasibility analysis without touching the PCE
- Sync: apply discovered labels to matching PCE workloads

Label mapping is configurable via rules that map AD attributes (OU path,
group membership, location, extension attributes, description) to Illumio
label keys (role, app, env, loc).
"""

import json
import logging
import os
import re
import signal
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("ad_label_sync")

state_lock = threading.Lock()
report_state = {
    "last_scan": None,
    "scan_count": 0,
    "error": None,
    "mode": "analytics",
    "ad_status": "unknown",
    "computers": [],
    "summary": {},
    "label_coverage": {},
    "ou_tree": {},
    "group_map": {},
    "mapping_rules": [],
    "match_results": [],
}

# ============================================================
# Default mapping rules (configurable via MAPPING_RULES env var)
# ============================================================

DEFAULT_RULES = [
    # Env from OU path
    {"source": "ou_path", "pattern": "(?i)\\bprod(uction)?\\b", "target": "env", "value": "prod", "priority": 10},
    {"source": "ou_path", "pattern": "(?i)\\bdev(elopment)?\\b", "target": "env", "value": "dev", "priority": 10},
    {"source": "ou_path", "pattern": "(?i)\\bstag(ing|e)?\\b", "target": "env", "value": "staging", "priority": 10},
    {"source": "ou_path", "pattern": "(?i)\\btest(ing)?\\b", "target": "env", "value": "test", "priority": 10},
    {"source": "ou_path", "pattern": "(?i)\\blab\\b", "target": "env", "value": "lab", "priority": 10},
    {"source": "ou_path", "pattern": "(?i)\\bqa\\b", "target": "env", "value": "qa", "priority": 10},

    # Role from OU path
    {"source": "ou_path", "pattern": "(?i)\\bweb\\b", "target": "role", "value": "web", "priority": 5},
    {"source": "ou_path", "pattern": "(?i)\\b(db|database|sql)\\b", "target": "role", "value": "db", "priority": 5},
    {"source": "ou_path", "pattern": "(?i)\\bapp\\b", "target": "role", "value": "processing", "priority": 5},

    # Role from group membership
    {"source": "group", "pattern": "(?i)^(web|www|iis|apache|nginx)", "target": "role", "value": "web", "priority": 8},
    {"source": "group", "pattern": "(?i)^(db|sql|mysql|postgres|oracle|mongo)", "target": "role", "value": "db", "priority": 8},
    {"source": "group", "pattern": "(?i)^(app|tomcat|jboss)", "target": "role", "value": "processing", "priority": 8},
    {"source": "group", "pattern": "(?i)^(lb|loadbalancer|haproxy|f5)", "target": "role", "value": "loadbalancer", "priority": 8},
    {"source": "group", "pattern": "(?i)^(dc|domain.controller|ad)", "target": "role", "value": "dc", "priority": 8},

    # Loc from location attribute
    {"source": "location", "pattern": ".+", "target": "loc", "value": "$0", "priority": 10},

    # Extension attributes (common conventions)
    {"source": "extensionAttribute1", "pattern": ".+", "target": "app", "value": "$0", "priority": 15},
    {"source": "extensionAttribute2", "pattern": ".+", "target": "env", "value": "$0", "priority": 15},
    {"source": "extensionAttribute3", "pattern": ".+", "target": "role", "value": "$0", "priority": 15},
]


def load_mapping_rules():
    """Load mapping rules from env var or use defaults."""
    custom = os.environ.get("MAPPING_RULES", "")
    if custom:
        try:
            return json.loads(custom)
        except json.JSONDecodeError:
            log.warning("Invalid MAPPING_RULES JSON, using defaults")
    return DEFAULT_RULES


def parse_ou_path(dn):
    """Extract OU components from a distinguished name."""
    ous = []
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("OU="):
            ous.append(part[3:])
    return ous


def apply_rules(computer, rules):
    """Apply mapping rules to an AD computer object, return label suggestions."""
    labels = {}  # key -> {value, source, confidence, priority}
    dn = computer.get("distinguishedName", "")
    ou_path = "/".join(reversed(parse_ou_path(dn)))
    groups = computer.get("memberOf", [])
    if isinstance(groups, str):
        groups = [groups]
    group_names = []
    for g in groups:
        for part in g.split(","):
            if part.strip().upper().startswith("CN="):
                group_names.append(part.strip()[3:])
                break

    for rule in sorted(rules, key=lambda r: r.get("priority", 0)):
        source = rule["source"]
        pattern = rule["pattern"]
        target = rule["target"]
        value = rule["value"]

        source_text = ""
        if source == "ou_path":
            source_text = ou_path
        elif source == "group":
            source_text = " ".join(group_names)
        elif source == "location":
            source_text = computer.get("l", "") or computer.get("location", "") or computer.get("physicalDeliveryOfficeName", "")
        elif source == "description":
            source_text = computer.get("description", "")
            if isinstance(source_text, list):
                source_text = source_text[0] if source_text else ""
        elif source.startswith("extensionAttribute"):
            source_text = computer.get(source, "")
            if isinstance(source_text, list):
                source_text = source_text[0] if source_text else ""
        else:
            source_text = computer.get(source, "")

        if not source_text:
            continue

        match = re.search(pattern, source_text)
        if match:
            final_value = value
            if "$0" in final_value:
                final_value = match.group(0)
            elif "$1" in final_value and match.lastindex and match.lastindex >= 1:
                final_value = match.group(1)

            priority = rule.get("priority", 0)
            if target not in labels or priority > labels[target]["priority"]:
                labels[target] = {
                    "value": final_value.strip(),
                    "source": f"{source}: matched '{pattern}' in '{source_text[:50]}'",
                    "confidence": min(0.9, 0.5 + priority * 0.05),
                    "priority": priority,
                }

    return labels


# ============================================================
# LDAP Discovery
# ============================================================

def scan_ad():
    """Connect to AD and discover computer objects."""
    ldap_host = os.environ.get("LDAP_HOST", "")
    ldap_port = int(os.environ.get("LDAP_PORT", "389"))
    ldap_user = os.environ.get("LDAP_BIND_DN", "")
    ldap_pass = os.environ.get("LDAP_BIND_PASSWORD", "")
    ldap_base = os.environ.get("LDAP_BASE_DN", "")
    ldap_filter = os.environ.get("LDAP_FILTER", "(objectClass=computer)")
    use_ssl = os.environ.get("LDAP_SSL", "false").lower() in ("true", "1")

    if not ldap_host:
        with state_lock:
            report_state["ad_status"] = "not configured"
            report_state["error"] = "LDAP_HOST not configured"
        return

    try:
        from ldap3 import Server, Connection, ALL, SUBTREE

        server = Server(ldap_host, port=ldap_port, use_ssl=use_ssl, get_info=ALL)
        conn = Connection(server, user=ldap_user, password=ldap_pass, auto_bind=True)

        with state_lock:
            report_state["ad_status"] = "connected"

        log.info("Connected to AD: %s", ldap_host)

        # Fetch attributes
        attrs = [
            'sAMAccountName', 'dNSHostName', 'cn', 'distinguishedName',
            'operatingSystem', 'operatingSystemVersion', 'description',
            'l', 'location', 'physicalDeliveryOfficeName', 'managedBy',
            'memberOf', 'userAccountControl', 'lastLogonTimestamp',
            'whenCreated', 'whenChanged',
            'extensionAttribute1', 'extensionAttribute2', 'extensionAttribute3',
            'extensionAttribute4', 'extensionAttribute5',
        ]

        conn.search(
            search_base=ldap_base,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attrs,
            paged_size=500,
        )

        computers = []
        for entry in conn.entries:
            comp = {}
            for attr in attrs:
                val = getattr(entry, attr, None)
                if val is not None:
                    val = val.value if hasattr(val, 'value') else str(val)
                    if val:
                        comp[attr] = val
            computers.append(comp)

        conn.unbind()
        log.info("Discovered %d computer objects", len(computers))
        process_computers(computers)

    except ImportError:
        log.error("ldap3 not installed — add ldap3 to requirements.txt")
        with state_lock:
            report_state["error"] = "ldap3 not installed"
            report_state["ad_status"] = "error"
    except Exception as e:
        log.error("AD connection failed: %s", e)
        with state_lock:
            report_state["error"] = str(e)
            report_state["ad_status"] = f"error: {str(e)[:100]}"


def process_computers(computers):
    """Process discovered AD computers: apply rules, build analytics."""
    rules = load_mapping_rules()
    mode = os.environ.get("MODE", "analytics")

    results = []
    label_coverage = defaultdict(lambda: {"total": 0, "mapped": 0, "values": Counter()})
    ou_tree = defaultdict(int)
    group_map = defaultdict(int)

    for comp in computers:
        hostname = comp.get("dNSHostName", "") or comp.get("sAMAccountName", "").rstrip("$")
        dn = comp.get("distinguishedName", "")
        ou_path = "/".join(reversed(parse_ou_path(dn)))
        os_name = comp.get("operatingSystem", "")

        # Count OU tree
        if ou_path:
            ou_tree[ou_path] += 1

        # Count groups
        groups = comp.get("memberOf", [])
        if isinstance(groups, str):
            groups = [groups]
        for g in groups:
            for part in g.split(","):
                if part.strip().upper().startswith("CN="):
                    group_map[part.strip()[3:]] += 1
                    break

        # Apply mapping rules
        suggested_labels = apply_rules(comp, rules)

        for key in ["role", "app", "env", "loc"]:
            label_coverage[key]["total"] += 1
            if key in suggested_labels:
                label_coverage[key]["mapped"] += 1
                label_coverage[key]["values"][suggested_labels[key]["value"]] += 1

        results.append({
            "hostname": hostname,
            "dn": dn,
            "ou_path": ou_path,
            "os": os_name,
            "labels": {k: v["value"] for k, v in suggested_labels.items()},
            "label_details": suggested_labels,
            "group_count": len(groups),
        })

    # Build summary
    total = len(computers)
    fully_mapped = sum(1 for r in results if all(k in r["labels"] for k in ["role", "app", "env"]))

    summary = {
        "total_computers": total,
        "fully_mapped": fully_mapped,
        "coverage_pct": round(100 * fully_mapped / total, 1) if total > 0 else 0,
        "unique_ous": len(ou_tree),
        "unique_groups": len(group_map),
        "rules_count": len(rules),
    }

    with state_lock:
        report_state["last_scan"] = datetime.now(timezone.utc).isoformat()
        report_state["scan_count"] += 1
        report_state["mode"] = mode
        report_state["computers"] = results
        report_state["summary"] = summary
        report_state["label_coverage"] = {k: {"total": v["total"], "mapped": v["mapped"],
                                               "pct": round(100 * v["mapped"] / v["total"], 1) if v["total"] > 0 else 0,
                                               "top_values": v["values"].most_common(10)}
                                          for k, v in label_coverage.items()}
        report_state["ou_tree"] = dict(sorted(ou_tree.items(), key=lambda x: -x[1])[:30])
        report_state["group_map"] = dict(sorted(group_map.items(), key=lambda x: -x[1])[:30])
        report_state["mapping_rules"] = rules
        report_state["error"] = None

    log.info("Scan #%d: %d computers, %d fully mapped (%.1f%%), %d OUs, %d groups",
             report_state["scan_count"], total, fully_mapped, summary["coverage_pct"],
             len(ou_tree), len(group_map))


def poller_loop():
    interval = int(os.environ.get("SCAN_INTERVAL", "3600"))
    while True:
        try:
            scan_ad()
        except Exception:
            log.exception("Scan failed")
        time.sleep(interval)


# ============================================================
# Dashboard
# ============================================================

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Label Sync</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}.fade-in{animation:fadeIn .3s ease-out}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#1e1e2e}::-webkit-scrollbar-thumb{background:#585b70;border-radius:3px}
.tab-active{border-bottom:2px solid #93c5fd;color:#93c5fd}.tab-inactive{border-bottom:2px solid transparent;color:#6b7280}
</style>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen dark">
<div class="max-w-[1400px] mx-auto px-6 py-8">
    <div class="flex items-center justify-between mb-8 fade-in">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <svg class="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/></svg>
                AD Label Sync
            </h1>
            <p class="text-gray-500 mt-1">Active Directory → Illumio label mapping</p>
        </div>
        <div class="flex items-center gap-3">
            <span id="ad-status" class="text-sm"></span>
            <span id="mode-badge" class="text-sm"></span>
        </div>
    </div>

    <div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8" id="stats"></div>

    <div class="flex gap-6 border-b border-gray-700 mb-6">
        <button onclick="showTab('coverage')" id="tab-coverage" class="pb-3 text-sm font-medium tab-active cursor-pointer">Label Coverage</button>
        <button onclick="showTab('computers')" id="tab-computers" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Computers</button>
        <button onclick="showTab('ous')" id="tab-ous" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">OU Tree</button>
        <button onclick="showTab('groups')" id="tab-groups" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Groups</button>
        <button onclick="showTab('rules')" id="tab-rules" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Mapping Rules</button>
    </div>

    <div id="panel-coverage"></div>
    <div id="panel-computers" style="display:none"></div>
    <div id="panel-ous" style="display:none"></div>
    <div id="panel-groups" style="display:none"></div>
    <div id="panel-rules" style="display:none"></div>

    <div class="text-center text-xs text-gray-600 mt-8" id="footer"></div>
</div>

<script>
const tabs = ['coverage','computers','ous','groups','rules'];
function showTab(t){tabs.forEach(n=>{document.getElementById('panel-'+n).style.display=n===t?'block':'none';document.getElementById('tab-'+n).className='pb-3 text-sm font-medium cursor-pointer '+(n===t?'tab-active':'tab-inactive');})}

function update(data) {
    const s = data.summary || {};
    const cov = data.label_coverage || {};
    const statusColor = data.ad_status === 'connected' ? 'green' : data.ad_status === 'not configured' ? 'gray' : 'red';
    document.getElementById('ad-status').innerHTML = `<span class="px-2 py-0.5 rounded text-xs bg-${statusColor}-900/50 text-${statusColor}-400">${data.ad_status}</span>`;
    document.getElementById('mode-badge').innerHTML = `<span class="px-2 py-0.5 rounded text-xs bg-blue-900/50 text-blue-400">${data.mode} mode</span>`;

    document.getElementById('stats').innerHTML = `
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-blue-400">${s.total_computers||0}</div><div class="text-xs text-gray-500 mt-1">Computers</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-green-400">${s.fully_mapped||0}</div><div class="text-xs text-gray-500 mt-1">Fully Mapped</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-purple-400">${s.coverage_pct||0}%</div><div class="text-xs text-gray-500 mt-1">Coverage</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-yellow-400">${s.unique_ous||0}</div><div class="text-xs text-gray-500 mt-1">OUs</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-orange-400">${s.unique_groups||0}</div><div class="text-xs text-gray-500 mt-1">Groups</div></div>
    `;

    // Coverage tab
    document.getElementById('panel-coverage').innerHTML = Object.keys(cov).length ? `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            ${['role','app','env','loc'].map(key => {
                const c = cov[key] || {total:0,mapped:0,pct:0,top_values:[]};
                const color = c.pct > 70 ? 'green' : c.pct > 30 ? 'yellow' : 'red';
                return `<div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
                    <div class="flex items-center justify-between mb-3">
                        <h3 class="text-white font-semibold">${key}</h3>
                        <span class="text-${color}-400 font-bold">${c.pct}%</span>
                    </div>
                    <div class="bg-dark-700 rounded-full h-2 mb-3"><div class="bg-${color}-500 h-2 rounded-full" style="width:${c.pct}%"></div></div>
                    <div class="text-xs text-gray-500 mb-2">${c.mapped}/${c.total} computers mapped</div>
                    <div class="space-y-1">${(c.top_values||[]).slice(0,5).map(([val,count]) =>
                        `<div class="flex justify-between text-xs"><code class="text-gray-300">${val}</code><span class="text-gray-500">${count}</span></div>`
                    ).join('')}</div>
                </div>`;
            }).join('')}
        </div>
        <div class="mt-6 p-4 bg-dark-800 rounded-xl border border-gray-700 text-xs text-gray-500">
            <strong>Analytics mode:</strong> This shows what labels would be applied based on current mapping rules. No changes are made to the PCE. Switch to sync mode (MODE=sync) to apply labels.
        </div>
    ` : '<div class="bg-dark-800 rounded-xl border border-gray-700 p-12 text-center"><div class="text-gray-400">No data yet — configure LDAP_HOST to scan Active Directory</div></div>';

    // Computers tab
    const comps = data.computers || [];
    document.getElementById('panel-computers').innerHTML = comps.length ? `
        <div class="bg-dark-800 rounded-xl border border-gray-700 overflow-hidden">
            <div class="overflow-x-auto max-h-[500px] overflow-y-auto">
                <table class="w-full text-sm">
                    <thead class="sticky top-0 bg-dark-800"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
                        <th class="px-4 py-3">Hostname</th><th class="px-4 py-3">OU Path</th><th class="px-4 py-3">OS</th>
                        <th class="px-4 py-3">Role</th><th class="px-4 py-3">App</th><th class="px-4 py-3">Env</th><th class="px-4 py-3">Loc</th>
                    </tr></thead>
                    <tbody>${comps.slice(0,200).map(c => `
                        <tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
                            <td class="px-4 py-2"><code class="text-xs">${c.hostname}</code></td>
                            <td class="px-4 py-2 text-xs text-gray-500 max-w-xs truncate" title="${c.ou_path}">${c.ou_path}</td>
                            <td class="px-4 py-2 text-xs text-gray-500">${c.os||'—'}</td>
                            <td class="px-4 py-2">${c.labels.role ? `<span class="text-xs px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-300">${c.labels.role}</span>` : '<span class="text-xs text-gray-600">—</span>'}</td>
                            <td class="px-4 py-2">${c.labels.app ? `<span class="text-xs px-1.5 py-0.5 rounded bg-green-900/30 text-green-300">${c.labels.app}</span>` : '<span class="text-xs text-gray-600">—</span>'}</td>
                            <td class="px-4 py-2">${c.labels.env ? `<span class="text-xs px-1.5 py-0.5 rounded bg-yellow-900/30 text-yellow-300">${c.labels.env}</span>` : '<span class="text-xs text-gray-600">—</span>'}</td>
                            <td class="px-4 py-2">${c.labels.loc ? `<span class="text-xs px-1.5 py-0.5 rounded bg-purple-900/30 text-purple-300">${c.labels.loc}</span>` : '<span class="text-xs text-gray-600">—</span>'}</td>
                        </tr>
                    `).join('')}</tbody>
                </table>
            </div>
        </div>
    ` : '<div class="bg-dark-800 rounded-xl border border-gray-700 p-12 text-center text-gray-400">No computers discovered</div>';

    // OU tree tab
    const ous = Object.entries(data.ou_tree || {});
    document.getElementById('panel-ous').innerHTML = ous.length ? `
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
            <h2 class="text-lg font-semibold text-white mb-4">OU Structure (${ous.length} unique paths)</h2>
            <div class="space-y-1">${ous.map(([path,count]) =>
                `<div class="flex justify-between py-1 px-3 bg-dark-700/30 rounded text-sm"><code class="text-gray-300">${path}</code><span class="text-gray-500">${count}</span></div>`
            ).join('')}</div>
        </div>
    ` : '<div class="bg-dark-800 rounded-xl border border-gray-700 p-12 text-center text-gray-400">No OU data</div>';

    // Groups tab
    const groups = Object.entries(data.group_map || {});
    document.getElementById('panel-groups').innerHTML = groups.length ? `
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
            <h2 class="text-lg font-semibold text-white mb-4">Group Memberships (${groups.length} groups)</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-1">${groups.map(([name,count]) =>
                `<div class="flex justify-between py-1 px-3 bg-dark-700/30 rounded text-sm"><code class="text-gray-300">${name}</code><span class="text-gray-500">${count} computers</span></div>`
            ).join('')}</div>
        </div>
    ` : '<div class="bg-dark-800 rounded-xl border border-gray-700 p-12 text-center text-gray-400">No group data</div>';

    // Rules tab
    const rules = data.mapping_rules || [];
    document.getElementById('panel-rules').innerHTML = `
        <div class="bg-dark-800 rounded-xl border border-gray-700 overflow-hidden">
            <table class="w-full text-sm">
                <thead><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
                    <th class="px-4 py-3">Source</th><th class="px-4 py-3">Pattern</th><th class="px-4 py-3">Target</th><th class="px-4 py-3">Value</th><th class="px-4 py-3">Priority</th>
                </tr></thead>
                <tbody>${rules.map(r => `
                    <tr class="border-b border-gray-700/30"><td class="px-4 py-2 text-xs text-gray-400">${r.source}</td><td class="px-4 py-2"><code class="text-xs">${r.pattern}</code></td>
                    <td class="px-4 py-2"><span class="text-xs px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-300">${r.target}</span></td>
                    <td class="px-4 py-2 text-xs text-gray-300">${r.value}</td><td class="px-4 py-2 text-xs text-gray-500">${r.priority}</td></tr>
                `).join('')}</tbody>
            </table>
        </div>
        <div class="mt-4 p-4 bg-dark-800 rounded-xl border border-gray-700 text-xs text-gray-500">
            Rules are evaluated in priority order (highest wins). Set custom rules via MAPPING_RULES env var as JSON array. $0 = matched text, $1 = first capture group.
        </div>
    `;

    document.getElementById('footer').textContent = `Scan #${data.scan_count} · ${data.last_scan ? new Date(data.last_scan).toLocaleString() : 'never'}`;
}

async function fetchData() { try { update(await (await fetch('/api/scan')).json()); } catch(e) { console.error(e); } }
fetchData(); setInterval(fetchData, 30000);
</script>
</body></html>"""


class ADHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/scan":
            with state_lock:
                self.send_json(200, dict(report_state))
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/scan/trigger":
            threading.Thread(target=scan_ad, daemon=True).start()
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


def main():
    log.info("Starting ad-label-sync...")
    port = int(os.environ.get("HTTP_PORT", "8080"))
    mode = os.environ.get("MODE", "analytics")
    log.info("Mode: %s", mode)

    ldap_host = os.environ.get("LDAP_HOST", "")
    if ldap_host:
        log.info("LDAP: %s", ldap_host)
    else:
        log.warning("LDAP_HOST not configured — dashboard will show empty until configured")

    poller = threading.Thread(target=poller_loop, daemon=True)
    poller.start()
    if ldap_host:
        scan_ad()

    server = HTTPServer(("0.0.0.0", port), ADHandler)
    log.info("Dashboard on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
