#!/usr/bin/env python3
"""
policy-diff — Git-like policy change tracker for Illumio PCE.

Tracks policy changes over time with snapshots, field-level diffs,
user attribution from audit events, and an interactive timeline UI.
"""

import copy
import hashlib
import json
import logging
import os
import signal
import threading
import time
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

from illumio import PolicyComputeEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("policy_diff")

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
SNAPSHOTS_FILE = DATA_DIR / "snapshots.json"
EVENTS_FILE = DATA_DIR / "events.json"

state_lock = threading.Lock()
app_state = {
    "last_check": None,
    "check_count": 0,
    "error": None,
    # Current draft vs active comparison
    "current_diffs": [],
    "summary": {"added": 0, "modified": 0, "deleted": 0, "unchanged": 0},
    "policy_objects": {},
    # History
    "snapshots": [],       # [{timestamp, hash, summary, diffs}]
    "recent_events": [],   # PCE audit events for policy changes
    "users": {},           # user_href -> {name, type}
}

POLICY_TYPES = [
    ("rule_sets", "Rulesets"),
    ("ip_lists", "IP Lists"),
    ("services", "Services"),
    ("label_groups", "Label Groups"),
    ("virtual_services", "Virtual Services"),
    ("firewall_settings", "Firewall Settings"),
]

# Fields to ignore in diffs (noisy metadata)
IGNORE_FIELDS = {"href", "created_at", "created_by", "deleted_at", "deleted_by",
                 "update_type", "caps", "external_data_set", "external_data_reference"}


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


def load_snapshots():
    if SNAPSHOTS_FILE.exists():
        try:
            return json.loads(SNAPSHOTS_FILE.read_text())
        except Exception:
            return []
    return []


def save_snapshots(snapshots):
    # Keep last 100 snapshots
    snapshots = snapshots[-100:]
    SNAPSHOTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOTS_FILE.write_text(json.dumps(snapshots, indent=2, default=str))


def load_events():
    if EVENTS_FILE.exists():
        try:
            return json.loads(EVENTS_FILE.read_text())
        except Exception:
            return []
    return []


def save_events(events):
    events = events[-500:]
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    EVENTS_FILE.write_text(json.dumps(events, indent=2, default=str))


def hash_obj(obj):
    """Create a stable hash of a policy object for change detection."""
    cleaned = {k: v for k, v in sorted(obj.items()) if k not in IGNORE_FIELDS}
    return hashlib.sha256(json.dumps(cleaned, sort_keys=True, default=str).encode()).hexdigest()[:12]


def diff_fields(old, new):
    """Compute field-level diff between two policy objects."""
    changes = []
    all_keys = set(list(old.keys()) + list(new.keys())) - IGNORE_FIELDS

    for key in sorted(all_keys):
        old_val = old.get(key)
        new_val = new.get(key)

        if old_val == new_val:
            continue

        if old_val is None:
            changes.append({"field": key, "type": "added", "new": new_val})
        elif new_val is None:
            changes.append({"field": key, "type": "removed", "old": old_val})
        else:
            changes.append({"field": key, "type": "changed", "old": old_val, "new": new_val})

    return changes


def fetch_policy_events(pce, since_hours=24):
    """Fetch recent policy-related audit events from PCE."""
    org_id = os.environ.get("PCE_ORG_ID", "1")
    events = []
    try:
        since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = pce.get(f"/events", params={
            "timestamp[gte]": since,
            "max_results": 500,
        })
        if resp.status_code == 200:
            raw_events = resp.json()
            if isinstance(raw_events, list):
                for ev in raw_events:
                    event_type = ev.get("event_type", "")
                    # Filter policy-related events
                    if any(kw in event_type for kw in [
                        "rule_set", "ip_list", "service", "label",
                        "sec_policy", "firewall", "virtual_service",
                        "provision", "sec_rule"
                    ]):
                        created_by = ev.get("created_by", {})
                        user_href = ""
                        user_name = "system"
                        if isinstance(created_by, dict):
                            user_href = created_by.get("href", "")
                            user_name = created_by.get("username", "") or created_by.get("name", "system")

                        events.append({
                            "timestamp": ev.get("timestamp", ""),
                            "event_type": event_type,
                            "status": ev.get("status", ""),
                            "user": user_name,
                            "user_href": user_href,
                            "severity": ev.get("severity", ""),
                            "resource_href": ev.get("href", ""),
                            "notification_type": ev.get("notification_type", ""),
                        })
    except Exception as e:
        log.warning("Failed to fetch events: %s", e)

    return events


def compare_policy(pce):
    """Compare draft vs active, build diffs, snapshot, and fetch events."""
    all_diffs = []
    summary = {"added": 0, "modified": 0, "deleted": 0, "unchanged": 0}
    objects = {}
    policy_hash_parts = []

    for endpoint, label in POLICY_TYPES:
        try:
            active_resp = pce.get(f"/sec_policy/active/{endpoint}")
            active = active_resp.json() if active_resp.status_code == 200 else []

            draft_resp = pce.get(f"/sec_policy/draft/{endpoint}")
            draft = draft_resp.json() if draft_resp.status_code == 200 else []

            if not isinstance(active, list):
                active = []
            if not isinstance(draft, list):
                draft = []

            objects[label] = {"active": len(active), "draft": len(draft)}

            active_by_name = {}
            for obj in active:
                name = obj.get("name", obj.get("href", ""))
                active_by_name[name] = obj

            draft_by_name = {}
            for obj in draft:
                name = obj.get("name", obj.get("href", ""))
                draft_by_name[name] = obj

            # Additions
            for name, d_obj in draft_by_name.items():
                if name not in active_by_name:
                    all_diffs.append({
                        "type": label,
                        "change": "added",
                        "name": name,
                        "detail": "New in draft",
                        "fields": [{"field": k, "type": "added", "new": v}
                                   for k, v in d_obj.items() if k not in IGNORE_FIELDS and v],
                        "updated_by": d_obj.get("updated_by", {}).get("username", ""),
                        "updated_at": d_obj.get("updated_at", ""),
                    })
                    summary["added"] += 1
                else:
                    a_obj = active_by_name[name]
                    d_hash = hash_obj(d_obj)
                    a_hash = hash_obj(a_obj)
                    policy_hash_parts.append(d_hash)

                    if d_hash != a_hash:
                        field_changes = diff_fields(a_obj, d_obj)
                        if field_changes:
                            all_diffs.append({
                                "type": label,
                                "change": "modified",
                                "name": name,
                                "detail": f"{len(field_changes)} field{'s' if len(field_changes) != 1 else ''} changed",
                                "fields": field_changes,
                                "updated_by": d_obj.get("updated_by", {}).get("username", ""),
                                "updated_at": d_obj.get("updated_at", ""),
                            })
                            summary["modified"] += 1
                        else:
                            summary["unchanged"] += 1
                    else:
                        summary["unchanged"] += 1

            # Deletions
            for name in active_by_name:
                if name not in draft_by_name:
                    a_obj = active_by_name[name]
                    all_diffs.append({
                        "type": label,
                        "change": "deleted",
                        "name": name,
                        "detail": "Removed from draft",
                        "fields": [{"field": k, "type": "removed", "old": v}
                                   for k, v in a_obj.items() if k not in IGNORE_FIELDS and v],
                        "updated_by": "",
                        "updated_at": "",
                    })
                    summary["deleted"] += 1

        except Exception as e:
            log.warning("Failed to compare %s: %s", label, e)

    # Create snapshot
    overall_hash = hashlib.sha256("".join(sorted(policy_hash_parts)).encode()).hexdigest()[:16]
    now = datetime.now(timezone.utc).isoformat()
    total_changes = summary["added"] + summary["modified"] + summary["deleted"]

    snapshots = load_snapshots()
    # Only save snapshot if hash changed or it's the first one
    if not snapshots or snapshots[-1].get("hash") != overall_hash:
        snapshots.append({
            "timestamp": now,
            "hash": overall_hash,
            "summary": dict(summary),
            "total_changes": total_changes,
            "objects": dict(objects),
            "diffs": all_diffs,
        })
        save_snapshots(snapshots)
        log.info("New snapshot saved (hash=%s, changes=%d)", overall_hash, total_changes)

    # Fetch recent events
    events = fetch_policy_events(pce, since_hours=int(os.environ.get("EVENT_LOOKBACK_HOURS", "72")))
    if events:
        save_events(events)

    # Extract unique users
    users = {}
    for ev in events:
        if ev.get("user") and ev["user"] != "system":
            users[ev["user"]] = {"name": ev["user"], "event_count": 0}
    for ev in events:
        if ev.get("user") in users:
            users[ev["user"]]["event_count"] += 1

    with state_lock:
        app_state["last_check"] = now
        app_state["check_count"] += 1
        app_state["current_diffs"] = all_diffs
        app_state["summary"] = summary
        app_state["policy_objects"] = objects
        app_state["snapshots"] = snapshots[-50:]
        app_state["recent_events"] = events[:100]
        app_state["users"] = users
        app_state["error"] = None

    log.info("Check #%d: %d changes, %d events, %d users, hash=%s",
             app_state["check_count"], total_changes, len(events), len(users), overall_hash)


def poller_loop(pce):
    interval = int(os.environ.get("POLL_INTERVAL", "3600"))
    while True:
        try:
            compare_policy(pce)
        except Exception:
            log.exception("Policy comparison failed")
        time.sleep(interval)


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Policy Diff</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>
tailwind.config = { darkMode: 'class', theme: { extend: { colors: { dark: { 700: '#313244', 800: '#1e1e2e', 900: '#11111b' } } } } }
</script>
<style>
@keyframes fadeIn { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:translateY(0); } }
.fade-in { animation: fadeIn 0.3s ease-out; }
.diff-added { background: #16a34a15; border-left: 3px solid #22c55e; }
.diff-removed { background: #dc262615; border-left: 3px solid #ef4444; }
.diff-changed { background: #eab30815; border-left: 3px solid #eab308; }
.diff-line { font-family: ui-monospace, monospace; font-size: 12px; padding: 4px 12px; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #1e1e2e; }
::-webkit-scrollbar-thumb { background: #585b70; border-radius: 3px; }
.tab-active { border-bottom: 2px solid #93c5fd; color: #93c5fd; }
.tab-inactive { border-bottom: 2px solid transparent; color: #6b7280; }
.tab-inactive:hover { color: #9ca3af; }
.timeline-dot { width: 12px; height: 12px; border-radius: 50%; border: 2px solid #313244; }
.timeline-line { width: 2px; background: #313244; }
.user-avatar { width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 600; font-size: 13px; }
</style>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen dark">
<div class="max-w-[1400px] mx-auto px-6 py-8">

    <!-- Header -->
    <div class="flex items-center justify-between mb-8 fade-in">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <svg class="w-8 h-8 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
                </svg>
                Policy Diff
            </h1>
            <p class="text-gray-500 mt-1">Draft vs Active — change tracking with history</p>
        </div>
        <div class="flex items-center gap-3">
            <div id="status-badge" class="px-3 py-1 rounded-full text-sm font-medium bg-gray-700 text-gray-400">Loading...</div>
        </div>
    </div>

    <!-- Stats -->
    <div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in">
            <div class="text-3xl font-bold text-white" id="stat-total">—</div>
            <div class="text-xs text-gray-500 mt-1">Pending Changes</div>
        </div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in">
            <div class="text-3xl font-bold text-green-400" id="stat-added">—</div>
            <div class="text-xs text-gray-500 mt-1">Added</div>
        </div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in">
            <div class="text-3xl font-bold text-yellow-400" id="stat-modified">—</div>
            <div class="text-xs text-gray-500 mt-1">Modified</div>
        </div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in">
            <div class="text-3xl font-bold text-red-400" id="stat-deleted">—</div>
            <div class="text-xs text-gray-500 mt-1">Deleted</div>
        </div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in">
            <div class="text-3xl font-bold text-gray-400" id="stat-unchanged">—</div>
            <div class="text-xs text-gray-500 mt-1">Unchanged</div>
        </div>
    </div>

    <!-- Tabs -->
    <div class="flex gap-6 border-b border-gray-700 mb-6 fade-in">
        <button onclick="showTab('diffs')" id="tab-diffs" class="pb-3 text-sm font-medium tab-active cursor-pointer">Changes</button>
        <button onclick="showTab('timeline')" id="tab-timeline" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Timeline</button>
        <button onclick="showTab('events')" id="tab-events" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Audit Log</button>
        <button onclick="showTab('objects')" id="tab-objects" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Policy Objects</button>
    </div>

    <!-- Tab: Diffs -->
    <div id="panel-diffs">
        <div id="diffs-container"></div>
    </div>

    <!-- Tab: Timeline -->
    <div id="panel-timeline" style="display:none;">
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
            <h2 class="text-lg font-semibold text-white mb-4">Change History</h2>
            <div class="mb-6" style="height:200px;"><canvas id="chart-timeline"></canvas></div>
            <div id="timeline-list"></div>
        </div>
    </div>

    <!-- Tab: Events -->
    <div id="panel-events" style="display:none;">
        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <!-- Users sidebar -->
            <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
                <h2 class="text-lg font-semibold text-white mb-4">Active Users</h2>
                <div id="users-list"></div>
            </div>
            <!-- Events list -->
            <div class="lg:col-span-3 bg-dark-800 rounded-xl border border-gray-700 p-6">
                <h2 class="text-lg font-semibold text-white mb-4">Policy Audit Events</h2>
                <div id="events-list" class="space-y-1 max-h-[600px] overflow-y-auto"></div>
            </div>
        </div>
    </div>

    <!-- Tab: Objects -->
    <div id="panel-objects" style="display:none;">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
                <h2 class="text-lg font-semibold text-white mb-4">Policy Object Counts</h2>
                <div style="height:300px;"><canvas id="chart-objects"></canvas></div>
            </div>
            <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
                <h2 class="text-lg font-semibold text-white mb-4">Object Details</h2>
                <table class="w-full text-sm" id="objects-table">
                    <thead><tr class="text-left text-xs text-gray-500 uppercase tracking-wider">
                        <th class="pb-3">Type</th><th class="pb-3 text-center">Active</th><th class="pb-3 text-center">Draft</th><th class="pb-3 text-center">Delta</th>
                    </tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="text-center text-xs text-gray-600 mt-8">
        <span id="footer-info"></span>
        &middot; <a id="api-link" href="/api/diff" class="text-blue-500 hover:text-blue-400">JSON API</a>
    </div>
</div>

<script>
const BASE = (() => { const m = window.location.pathname.match(/^(\/plugins\/[^/]+\/ui)/); return m ? m[1] : ''; })();

const USER_COLORS = ['#f87171','#fb923c','#fbbf24','#a3e635','#34d399','#22d3ee','#818cf8','#c084fc','#f472b6','#94a3b8'];
function userColor(name) { let h=0; for(let i=0;i<name.length;i++) h=name.charCodeAt(i)+((h<<5)-h); return USER_COLORS[Math.abs(h)%USER_COLORS.length]; }
function userInitials(name) { return name.split(/[.@_-]/).filter(Boolean).slice(0,2).map(s=>s[0].toUpperCase()).join(''); }
function timeAgo(ts) {
    if(!ts) return '';
    const d = (Date.now() - new Date(ts).getTime())/1000;
    if(d<60) return 'just now'; if(d<3600) return Math.floor(d/60)+'m ago';
    if(d<86400) return Math.floor(d/3600)+'h ago'; return Math.floor(d/86400)+'d ago';
}
function formatVal(v) {
    if(v===null||v===undefined) return '<span class="text-gray-600">null</span>';
    if(typeof v==='boolean') return `<span class="${v?'text-green-400':'text-red-400'}">${v}</span>`;
    if(typeof v==='object') return `<span class="text-gray-400">${JSON.stringify(v).substring(0,80)}${JSON.stringify(v).length>80?'...':''}</span>`;
    const s = String(v);
    return s.length > 60 ? s.substring(0,60)+'...' : s;
}

let chartTimeline, chartObjects;
const tabs = ['diffs','timeline','events','objects'];

function showTab(name) {
    tabs.forEach(t => {
        document.getElementById('panel-'+t).style.display = t===name?'block':'none';
        document.getElementById('tab-'+t).className = 'pb-3 text-sm font-medium cursor-pointer '+(t===name?'tab-active':'tab-inactive');
    });
}

function initCharts() {
    chartTimeline = new Chart(document.getElementById('chart-timeline'), {
        type: 'line',
        data: { labels: [], datasets: [
            { label:'Added', data:[], borderColor:'#22c55e', backgroundColor:'#22c55e22', fill:true, tension:0.3, pointRadius:4 },
            { label:'Modified', data:[], borderColor:'#eab308', backgroundColor:'#eab30822', fill:true, tension:0.3, pointRadius:4 },
            { label:'Deleted', data:[], borderColor:'#ef4444', backgroundColor:'#ef444422', fill:true, tension:0.3, pointRadius:4 },
        ]},
        options: {
            responsive:true, maintainAspectRatio:false,
            plugins: { legend:{ labels:{ color:'#9ca3af', usePointStyle:true, pointStyle:'circle' } } },
            scales: {
                x: { grid:{color:'#31324422'}, ticks:{color:'#6b7280', font:{size:10}} },
                y: { grid:{color:'#31324422'}, ticks:{color:'#6b7280', stepSize:1}, beginAtZero:true }
            }
        }
    });
    chartObjects = new Chart(document.getElementById('chart-objects'), {
        type: 'bar',
        data: { labels:[], datasets:[
            { label:'Active', data:[], backgroundColor:'#93c5fd44', borderColor:'#93c5fd', borderWidth:1, borderRadius:4 },
            { label:'Draft', data:[], backgroundColor:'#c084fc44', borderColor:'#c084fc', borderWidth:1, borderRadius:4 },
        ]},
        options: {
            responsive:true, maintainAspectRatio:false,
            plugins: { legend:{ labels:{ color:'#9ca3af' } } },
            scales: {
                x: { grid:{display:false}, ticks:{color:'#9ca3af', font:{size:11}} },
                y: { grid:{color:'#31324422'}, ticks:{color:'#6b7280'}, beginAtZero:true }
            }
        }
    });
}

function renderDiffs(diffs) {
    const c = document.getElementById('diffs-container');
    if(!diffs.length) {
        c.innerHTML = `<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center">
            <div class="text-5xl mb-4">&#10003;</div>
            <div class="text-xl font-semibold text-green-400">Policy In Sync</div>
            <div class="text-gray-500 mt-2">Draft and active policy are identical. No pending changes.</div>
        </div>`;
        return;
    }

    const changeColors = { added:'green', modified:'yellow', deleted:'red' };
    const changeIcons = { added:'+', modified:'~', deleted:'-' };

    c.innerHTML = diffs.map((d,i) => {
        const color = changeColors[d.change] || 'gray';
        const icon = changeIcons[d.change] || '?';
        const fields = d.fields || [];
        const user = d.updated_by || '';
        const when = d.updated_at ? timeAgo(d.updated_at) : '';

        let fieldsHtml = '';
        if(fields.length) {
            fieldsHtml = `<div id="diff-fields-${i}" style="display:none;" class="mt-3 rounded-lg overflow-hidden border border-gray-700/50">
                ${fields.map(f => {
                    if(f.type==='added') return `<div class="diff-line diff-added"><span class="text-green-400">+</span> <span class="text-green-300">${f.field}</span>: ${formatVal(f.new)}</div>`;
                    if(f.type==='removed') return `<div class="diff-line diff-removed"><span class="text-red-400">-</span> <span class="text-red-300">${f.field}</span>: ${formatVal(f.old)}</div>`;
                    return `<div class="diff-line diff-removed"><span class="text-red-400">-</span> <span class="text-gray-400">${f.field}</span>: ${formatVal(f.old)}</div>
                            <div class="diff-line diff-changed"><span class="text-yellow-400">+</span> <span class="text-yellow-300">${f.field}</span>: ${formatVal(f.new)}</div>`;
                }).join('')}
            </div>`;
        }

        return `<div class="bg-dark-800 rounded-xl border border-gray-700 p-4 mb-3 fade-in hover:border-gray-600 transition-colors">
            <div class="flex items-center gap-3 cursor-pointer" onclick="toggleFields(${i})">
                <span class="w-7 h-7 rounded-lg bg-${color}-900/50 text-${color}-400 flex items-center justify-center font-bold text-sm">${icon}</span>
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2">
                        <span class="font-medium text-white">${d.name}</span>
                        <span class="px-1.5 py-0.5 rounded text-xs bg-gray-700 text-gray-400">${d.type}</span>
                    </div>
                    <div class="text-xs text-gray-500 mt-0.5">${d.detail}${fields.length?' · click to expand':''}</div>
                </div>
                ${user ? `<div class="flex items-center gap-2">
                    <div class="user-avatar" style="background:${userColor(user)}22;color:${userColor(user)}">${userInitials(user)}</div>
                    <div class="text-right"><div class="text-xs text-gray-400">${user}</div><div class="text-xs text-gray-600">${when}</div></div>
                </div>` : ''}
                ${fields.length?'<svg class="w-4 h-4 text-gray-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>':''}
            </div>
            ${fieldsHtml}
        </div>`;
    }).join('');
}

function toggleFields(i) {
    const el = document.getElementById('diff-fields-'+i);
    if(el) el.style.display = el.style.display==='none'?'block':'none';
}

function renderTimeline(snapshots) {
    // Chart
    const labels = snapshots.map(s => { const d=new Date(s.timestamp); return d.toLocaleDateString()+' '+d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}); });
    chartTimeline.data.labels = labels;
    chartTimeline.data.datasets[0].data = snapshots.map(s => s.summary.added);
    chartTimeline.data.datasets[1].data = snapshots.map(s => s.summary.modified);
    chartTimeline.data.datasets[2].data = snapshots.map(s => s.summary.deleted);
    chartTimeline.update('none');

    // List
    const list = document.getElementById('timeline-list');
    list.innerHTML = snapshots.slice().reverse().slice(0,20).map(s => {
        const total = s.total_changes;
        const color = total===0?'green':total<5?'yellow':'red';
        const dt = new Date(s.timestamp);
        return `<div class="flex items-start gap-4 py-3 border-b border-gray-700/30">
            <div class="flex flex-col items-center">
                <div class="timeline-dot bg-${color}-500/30 border-${color}-500"></div>
            </div>
            <div class="flex-1">
                <div class="flex items-center gap-2">
                    <span class="text-sm font-medium text-white">${total===0?'In sync':total+' change'+(total>1?'s':'')}</span>
                    <code class="text-xs text-gray-600">${s.hash}</code>
                </div>
                <div class="text-xs text-gray-500 mt-0.5">${dt.toLocaleString()}</div>
                ${total>0?`<div class="flex gap-3 mt-1 text-xs">
                    ${s.summary.added?`<span class="text-green-400">+${s.summary.added} added</span>`:''}
                    ${s.summary.modified?`<span class="text-yellow-400">~${s.summary.modified} modified</span>`:''}
                    ${s.summary.deleted?`<span class="text-red-400">-${s.summary.deleted} deleted</span>`:''}
                </div>`:''}
            </div>
        </div>`;
    }).join('');
}

function renderEvents(events, users) {
    // Users
    const usersList = document.getElementById('users-list');
    const sortedUsers = Object.entries(users).sort((a,b) => b[1].event_count - a[1].event_count);
    usersList.innerHTML = sortedUsers.length ? sortedUsers.map(([name,u]) => `
        <div class="flex items-center gap-3 py-2 border-b border-gray-700/30">
            <div class="user-avatar" style="background:${userColor(name)}22;color:${userColor(name)}">${userInitials(name)}</div>
            <div class="flex-1 min-w-0">
                <div class="text-sm text-white truncate">${name}</div>
                <div class="text-xs text-gray-500">${u.event_count} event${u.event_count>1?'s':''}</div>
            </div>
        </div>
    `).join('') : '<p class="text-gray-500 text-sm">No users found</p>';

    // Events
    const evList = document.getElementById('events-list');
    evList.innerHTML = events.length ? events.map(ev => {
        const typeColor = ev.event_type.includes('create')?'green':ev.event_type.includes('delete')?'red':ev.event_type.includes('update')?'yellow':'blue';
        return `<div class="flex items-center gap-3 py-2 px-3 rounded hover:bg-dark-700/30 transition-colors">
            <div class="user-avatar shrink-0" style="background:${userColor(ev.user||'system')}22;color:${userColor(ev.user||'system')};width:28px;height:28px;font-size:11px;">${userInitials(ev.user||'sys')}</div>
            <div class="flex-1 min-w-0">
                <span class="text-xs px-1.5 py-0.5 rounded bg-${typeColor}-900/30 text-${typeColor}-400 font-mono">${ev.event_type}</span>
                <span class="text-xs text-gray-500 ml-2">${ev.user||'system'}</span>
            </div>
            <span class="text-xs text-gray-600 shrink-0">${timeAgo(ev.timestamp)}</span>
        </div>`;
    }).join('') : '<p class="text-gray-500 text-sm text-center py-8">No policy events in the last 72 hours</p>';
}

function renderObjects(objects) {
    const labels = Object.keys(objects);
    chartObjects.data.labels = labels;
    chartObjects.data.datasets[0].data = labels.map(l => objects[l].active);
    chartObjects.data.datasets[1].data = labels.map(l => objects[l].draft);
    chartObjects.update('none');

    const tbody = document.querySelector('#objects-table tbody');
    tbody.innerHTML = labels.map(l => {
        const o = objects[l];
        const delta = o.draft - o.active;
        const deltaColor = delta>0?'text-green-400':delta<0?'text-red-400':'text-gray-500';
        return `<tr class="border-b border-gray-700/30"><td class="py-2">${l}</td><td class="py-2 text-center">${o.active}</td><td class="py-2 text-center">${o.draft}</td><td class="py-2 text-center ${deltaColor}">${delta>0?'+':''}${delta}</td></tr>`;
    }).join('');
}

function update(data) {
    const s = data.summary;
    const total = s.added + s.modified + s.deleted;

    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-added').textContent = s.added;
    document.getElementById('stat-modified').textContent = s.modified;
    document.getElementById('stat-deleted').textContent = s.deleted;
    document.getElementById('stat-unchanged').textContent = s.unchanged;

    const badge = document.getElementById('status-badge');
    if(total===0) { badge.textContent='In Sync'; badge.className='px-3 py-1 rounded-full text-sm font-medium bg-green-900/50 text-green-400'; }
    else if(total<5) { badge.textContent=total+' Pending'; badge.className='px-3 py-1 rounded-full text-sm font-medium bg-yellow-900/50 text-yellow-400'; }
    else { badge.textContent=total+' Pending'; badge.className='px-3 py-1 rounded-full text-sm font-medium bg-red-900/50 text-red-400'; }

    renderDiffs(data.current_diffs || []);
    renderTimeline(data.snapshots || []);
    renderEvents(data.recent_events || [], data.users || {});
    renderObjects(data.policy_objects || {});

    document.getElementById('footer-info').textContent = `Check #${data.check_count} · ${data.last_check ? timeAgo(data.last_check) : 'never'} · ${(data.snapshots||[]).length} snapshots`;
}

async function fetchData() {
    try {
        const resp = await fetch(BASE + '/api/diff');
        update(await resp.json());
    } catch(e) { console.error('Fetch failed:', e); }
}

initCharts();
fetchData();
document.getElementById('api-link').href = BASE + '/api/diff';
setInterval(fetchData, 30000);
</script>
</body></html>"""


class DiffHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/diff":
            with state_lock:
                self.send_json(200, dict(app_state))
        elif self.path == "/":
            self.send_html(DASHBOARD_HTML)
        else:
            self.send_error(404)

    def send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, fmt, *args):
        pass


def main():
    log.info("Starting policy-diff...")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce = get_pce()
    log.info("Connected to PCE: %s", pce.base_url)

    # Load previous snapshots
    prev = load_snapshots()
    if prev:
        with state_lock:
            app_state["snapshots"] = prev[-50:]
        log.info("Loaded %d previous snapshots", len(prev))

    poller = threading.Thread(target=poller_loop, args=(pce,), daemon=True)
    poller.start()
    compare_policy(pce)

    server = HTTPServer(("0.0.0.0", port), DiffHandler)
    log.info("Dashboard on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
