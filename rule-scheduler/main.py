#!/usr/bin/env python3
"""
rule-scheduler — Time-based rule/ruleset scheduler for Illumio PCE.

Enable/disable rulesets or individual rules based on configurable
schedules with day-of-week and time-of-day windows.

Use cases:
- Business hours only (9-5 weekdays)
- Maintenance windows (Saturday 2am-6am)
- Weekend-only access
- After-hours lockdown
"""

import json
import logging
import os
import signal
import threading
import time
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

from illumio import PolicyComputeEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("rule_scheduler")

state_lock = threading.Lock()
app_state = {
    "last_check": None,
    "check_count": 0,
    "error": None,
    "schedules": [],
    "history": [],
    "pce_status": "unknown",
    "timezone": "",
}

DEFAULT_SCHEDULES = [
    {
        "name": "Business Hours Access",
        "description": "Enable during business hours (Mon-Fri 9:00-17:00)",
        "targets": [],
        "target_type": "ruleset",
        "days": ["mon", "tue", "wed", "thu", "fri"],
        "start_time": "09:00",
        "end_time": "17:00",
        "action_in_window": "enable",
        "action_outside": "disable",
        "enabled": False,
        "comment": "[rule-scheduler] Business hours only",
    },
    {
        "name": "Maintenance Window",
        "description": "Enable during Saturday maintenance (02:00-06:00)",
        "targets": [],
        "target_type": "ruleset",
        "days": ["sat"],
        "start_time": "02:00",
        "end_time": "06:00",
        "action_in_window": "enable",
        "action_outside": "disable",
        "enabled": False,
        "comment": "[rule-scheduler] Maintenance window",
    },
    {
        "name": "Weekend Lockdown",
        "description": "Disable on weekends",
        "targets": [],
        "target_type": "ruleset",
        "days": ["sat", "sun"],
        "start_time": "00:00",
        "end_time": "23:59",
        "action_in_window": "disable",
        "action_outside": "enable",
        "enabled": False,
        "comment": "[rule-scheduler] Weekend lockdown",
    },
]

DAY_MAP = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


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


def load_schedules():
    """Load schedules from config file or env var."""
    config_path = os.environ.get("SCHEDULES_FILE", "/data/schedules.json")
    try:
        with open(config_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    env_schedules = os.environ.get("SCHEDULES", "")
    if env_schedules:
        try:
            return json.loads(env_schedules)
        except json.JSONDecodeError:
            pass

    return DEFAULT_SCHEDULES


def save_schedules(schedules):
    """Persist schedules to disk."""
    config_path = os.environ.get("SCHEDULES_FILE", "/data/schedules.json")
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(schedules, f, indent=2)
    except Exception as e:
        log.warning("Failed to save schedules: %s", e)


def is_in_window(schedule, now=None):
    """Check if the current time is within the schedule window."""
    tz_name = os.environ.get("TZ", "UTC")
    if now is None:
        now = datetime.now()

    current_day = now.weekday()
    current_time = now.strftime("%H:%M")

    # Check day
    schedule_days = [DAY_MAP.get(d.lower(), -1) for d in schedule.get("days", [])]
    if current_day not in schedule_days:
        return False

    # Check time window
    start = schedule.get("start_time", "00:00")
    end = schedule.get("end_time", "23:59")

    if start <= end:
        return start <= current_time <= end
    else:
        # Overnight window (e.g., 22:00 - 06:00)
        return current_time >= start or current_time <= end


def apply_schedule(pce, schedule, in_window):
    """Apply a schedule action to its targets."""
    action = schedule.get("action_in_window" if in_window else "action_outside", "")
    if not action:
        return []

    should_enable = action == "enable"
    target_type = schedule.get("target_type", "ruleset")
    targets = schedule.get("targets", [])
    comment = schedule.get("comment", "")
    changes = []

    for target_href in targets:
        if not target_href:
            continue

        try:
            # Get current state
            resp = pce.get(target_href)
            if resp.status_code != 200:
                log.warning("Failed to get %s: HTTP %d", target_href, resp.status_code)
                continue

            current = resp.json()
            current_enabled = current.get("enabled", True)

            if current_enabled == should_enable:
                continue  # Already in desired state

            # Apply change
            update_data = {"enabled": should_enable}
            if comment and target_type == "ruleset":
                update_data["description"] = comment

            put_resp = pce.put(target_href, json=update_data)
            if put_resp.status_code in (200, 204):
                action_word = "enabled" if should_enable else "disabled"
                name = current.get("name", target_href)
                log.info("Schedule '%s': %s %s '%s'", schedule["name"], action_word, target_type, name)
                changes.append({
                    "target": target_href,
                    "name": name,
                    "action": action_word,
                    "schedule": schedule["name"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            else:
                log.error("Failed to update %s: HTTP %d", target_href, put_resp.status_code)
        except Exception as e:
            log.error("Error applying schedule to %s: %s", target_href, e)

    return changes


def run_check(pce):
    """Evaluate all schedules and apply changes."""
    schedules = load_schedules()
    now = datetime.now()
    tz_name = os.environ.get("TZ", "UTC")
    all_changes = []

    schedule_status = []
    for sched in schedules:
        if not sched.get("enabled", False):
            schedule_status.append({**sched, "status": "disabled", "in_window": False})
            continue

        in_window = is_in_window(sched, now)
        changes = apply_schedule(pce, sched, in_window)
        all_changes.extend(changes)

        schedule_status.append({
            **sched,
            "status": "in_window" if in_window else "outside_window",
            "in_window": in_window,
            "last_action": changes[-1]["action"] if changes else None,
        })

    with state_lock:
        app_state["last_check"] = datetime.now(timezone.utc).isoformat()
        app_state["check_count"] += 1
        app_state["schedules"] = schedule_status
        app_state["timezone"] = tz_name
        app_state["pce_status"] = "connected"
        app_state["error"] = None
        # Append to history (keep last 100)
        app_state["history"] = (app_state["history"] + all_changes)[-100:]

    active = sum(1 for s in schedule_status if s.get("enabled"))
    in_win = sum(1 for s in schedule_status if s.get("in_window"))
    log.info("Check #%d: %d schedules (%d active, %d in window), %d changes applied [%s %s]",
             app_state["check_count"], len(schedules), active, in_win, len(all_changes),
             DAY_NAMES[now.weekday()], now.strftime("%H:%M"))


def poller_loop(pce):
    interval = int(os.environ.get("CHECK_INTERVAL", "60"))
    while True:
        try:
            run_check(pce)
        except Exception:
            log.exception("Check failed")
        time.sleep(interval)


# ============================================================
# Dashboard
# ============================================================

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rule Scheduler</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}.fade-in{animation:fadeIn .3s ease-out}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#1e1e2e}::-webkit-scrollbar-thumb{background:#585b70;border-radius:3px}
.pulse-green{animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
</style>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen dark">
<div class="max-w-[1200px] mx-auto px-6 py-8">
    <div class="flex items-center justify-between mb-8 fade-in">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <svg class="w-8 h-8 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                Rule Scheduler
            </h1>
            <p class="text-gray-500 mt-1">Time-based rule and ruleset scheduling</p>
        </div>
        <div class="flex items-center gap-3 text-sm">
            <span id="clock" class="text-gray-400 font-mono"></span>
            <span id="tz" class="text-xs text-gray-600"></span>
        </div>
    </div>

    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8" id="stats"></div>

    <!-- Schedules -->
    <div class="mb-8">
        <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold text-white">Schedules</h2>
            <button onclick="showAddForm()" class="px-3 py-1.5 text-xs rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors">+ Add Schedule</button>
        </div>
        <div id="schedules-list" class="space-y-3"></div>
    </div>

    <!-- Add/Edit Form -->
    <div id="add-form" style="display:none" class="bg-dark-800 rounded-xl border border-blue-900/30 p-6 mb-8">
        <h3 class="text-white font-semibold mb-4">New Schedule</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
                <label class="text-gray-400 text-xs block mb-1">Name</label>
                <input id="f-name" class="w-full bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-white text-sm" placeholder="Business Hours Access">
            </div>
            <div>
                <label class="text-gray-400 text-xs block mb-1">Target Type</label>
                <select id="f-type" class="w-full bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-white text-sm">
                    <option value="ruleset">Ruleset</option>
                    <option value="rule">Individual Rule</option>
                </select>
            </div>
            <div>
                <label class="text-gray-400 text-xs block mb-1">Target HREFs (comma-separated)</label>
                <input id="f-targets" class="w-full bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-white text-sm" placeholder="/orgs/1/sec_policy/draft/rule_sets/123">
            </div>
            <div>
                <label class="text-gray-400 text-xs block mb-1">Comment (added to ruleset)</label>
                <input id="f-comment" class="w-full bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-white text-sm" placeholder="[rule-scheduler] Business hours only">
            </div>
            <div>
                <label class="text-gray-400 text-xs block mb-1">Days</label>
                <div class="flex gap-1" id="f-days">
                    <button onclick="toggleDay(this,'mon')" class="px-2 py-1 rounded text-xs bg-dark-700 text-gray-400 border border-gray-600" data-day="mon">Mon</button>
                    <button onclick="toggleDay(this,'tue')" class="px-2 py-1 rounded text-xs bg-dark-700 text-gray-400 border border-gray-600" data-day="tue">Tue</button>
                    <button onclick="toggleDay(this,'wed')" class="px-2 py-1 rounded text-xs bg-dark-700 text-gray-400 border border-gray-600" data-day="wed">Wed</button>
                    <button onclick="toggleDay(this,'thu')" class="px-2 py-1 rounded text-xs bg-dark-700 text-gray-400 border border-gray-600" data-day="thu">Thu</button>
                    <button onclick="toggleDay(this,'fri')" class="px-2 py-1 rounded text-xs bg-dark-700 text-gray-400 border border-gray-600" data-day="fri">Fri</button>
                    <button onclick="toggleDay(this,'sat')" class="px-2 py-1 rounded text-xs bg-dark-700 text-gray-400 border border-gray-600" data-day="sat">Sat</button>
                    <button onclick="toggleDay(this,'sun')" class="px-2 py-1 rounded text-xs bg-dark-700 text-gray-400 border border-gray-600" data-day="sun">Sun</button>
                </div>
            </div>
            <div class="flex gap-4">
                <div class="flex-1">
                    <label class="text-gray-400 text-xs block mb-1">Start Time</label>
                    <input id="f-start" type="time" value="09:00" class="w-full bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-white text-sm">
                </div>
                <div class="flex-1">
                    <label class="text-gray-400 text-xs block mb-1">End Time</label>
                    <input id="f-end" type="time" value="17:00" class="w-full bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-white text-sm">
                </div>
            </div>
            <div>
                <label class="text-gray-400 text-xs block mb-1">In Window</label>
                <select id="f-action-in" class="w-full bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-white text-sm">
                    <option value="enable">Enable rules</option>
                    <option value="disable">Disable rules</option>
                </select>
            </div>
            <div>
                <label class="text-gray-400 text-xs block mb-1">Outside Window</label>
                <select id="f-action-out" class="w-full bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-white text-sm">
                    <option value="disable">Disable rules</option>
                    <option value="enable">Enable rules</option>
                    <option value="">No action</option>
                </select>
            </div>
        </div>
        <div class="flex gap-2 mt-4">
            <button onclick="saveSchedule()" class="px-4 py-2 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white">Save Schedule</button>
            <button onclick="hideAddForm()" class="px-4 py-2 text-sm rounded bg-dark-700 text-gray-400">Cancel</button>
        </div>
    </div>

    <!-- History -->
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
        <h2 class="text-lg font-semibold text-white mb-4">Change History</h2>
        <div id="history-list" class="space-y-1 max-h-[300px] overflow-y-auto"></div>
    </div>

    <div class="text-center text-xs text-gray-600 mt-8" id="footer"></div>
</div>

<script>
let selectedDays = new Set();

function toggleDay(btn, day) {
    if (selectedDays.has(day)) {
        selectedDays.delete(day);
        btn.className = 'px-2 py-1 rounded text-xs bg-dark-700 text-gray-400 border border-gray-600';
    } else {
        selectedDays.add(day);
        btn.className = 'px-2 py-1 rounded text-xs bg-blue-600 text-white border border-blue-500';
    }
}

function showAddForm() { document.getElementById('add-form').style.display = 'block'; }
function hideAddForm() { document.getElementById('add-form').style.display = 'none'; }

function update(data) {
    const scheds = data.schedules || [];
    const active = scheds.filter(s => s.enabled).length;
    const inWindow = scheds.filter(s => s.in_window).length;
    const history = data.history || [];

    document.getElementById('stats').innerHTML = `
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-blue-400">${scheds.length}</div><div class="text-xs text-gray-500 mt-1">Schedules</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-green-400">${active}</div><div class="text-xs text-gray-500 mt-1">Active</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-amber-400">${inWindow}</div><div class="text-xs text-gray-500 mt-1">In Window</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-purple-400">${history.length}</div><div class="text-xs text-gray-500 mt-1">Changes</div></div>
    `;

    const dayNames = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
    document.getElementById('schedules-list').innerHTML = scheds.map((s, i) => {
        const statusColor = !s.enabled ? 'gray' : s.in_window ? 'green' : 'yellow';
        const statusText = !s.enabled ? 'disabled' : s.in_window ? 'IN WINDOW' : 'outside';
        const days = (s.days||[]).map(d => d.charAt(0).toUpperCase()+d.slice(1,3)).join(' ');
        return `
        <div class="bg-dark-800 rounded-xl border border-${statusColor}-900/30 p-4">
            <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-3">
                    <span class="${s.in_window && s.enabled ? 'pulse-green' : ''} w-2.5 h-2.5 rounded-full bg-${statusColor}-500"></span>
                    <span class="text-white font-medium">${s.name}</span>
                    <span class="px-1.5 py-0.5 rounded text-[10px] bg-${statusColor}-900/50 text-${statusColor}-400 uppercase">${statusText}</span>
                    <span class="text-xs text-gray-600">${s.target_type}</span>
                </div>
                <div class="flex items-center gap-2">
                    <button onclick="toggleSchedule(${i})" class="px-2 py-0.5 text-[10px] rounded ${s.enabled ? 'bg-red-800 text-red-200' : 'bg-green-800 text-green-200'}">${s.enabled ? 'Disable' : 'Enable'}</button>
                    <button onclick="deleteSchedule(${i})" class="px-2 py-0.5 text-[10px] rounded bg-dark-700 text-gray-400">Delete</button>
                </div>
            </div>
            <div class="flex items-center gap-4 text-xs text-gray-400">
                <span class="font-mono">${days}</span>
                <span class="font-mono">${s.start_time} — ${s.end_time}</span>
                <span>In window: <span class="text-${statusColor}-400">${s.action_in_window}</span></span>
                <span>Outside: <span class="text-gray-500">${s.action_outside||'none'}</span></span>
                <span class="text-gray-600">${(s.targets||[]).length} target${(s.targets||[]).length!==1?'s':''}</span>
            </div>
            ${s.description ? `<div class="text-xs text-gray-500 mt-1">${s.description}</div>` : ''}
        </div>`;
    }).join('') || '<div class="text-gray-500 text-sm text-center py-8">No schedules configured. Click "+ Add Schedule" to create one.</div>';

    // History
    document.getElementById('history-list').innerHTML = history.slice().reverse().map(h => `
        <div class="flex items-center justify-between py-1.5 px-3 bg-dark-700/30 rounded text-xs">
            <div class="flex items-center gap-2">
                <span class="px-1.5 py-0.5 rounded ${h.action==='enabled'?'bg-green-900/50 text-green-400':'bg-red-900/50 text-red-400'}">${h.action}</span>
                <span class="text-gray-300">${h.name}</span>
                <span class="text-gray-600">via ${h.schedule}</span>
            </div>
            <span class="text-gray-600">${new Date(h.timestamp).toLocaleString()}</span>
        </div>
    `).join('') || '<div class="text-gray-500 text-sm text-center py-4">No changes yet</div>';

    document.getElementById('clock').textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
    document.getElementById('tz').textContent = data.timezone || 'UTC';
    document.getElementById('footer').textContent = `Check #${data.check_count} · ${data.last_check ? new Date(data.last_check).toLocaleString() : 'never'} · checking every ${CHECK_INTERVAL}s`;
}

async function fetchData() { try { update(await (await fetch('/api/status')).json()); } catch(e) { console.error(e); } }

async function saveSchedule() {
    const sched = {
        name: document.getElementById('f-name').value,
        description: '',
        targets: document.getElementById('f-targets').value.split(',').map(s=>s.trim()).filter(Boolean),
        target_type: document.getElementById('f-type').value,
        days: Array.from(selectedDays),
        start_time: document.getElementById('f-start').value,
        end_time: document.getElementById('f-end').value,
        action_in_window: document.getElementById('f-action-in').value,
        action_outside: document.getElementById('f-action-out').value,
        comment: document.getElementById('f-comment').value,
        enabled: true,
    };
    if (!sched.name || !sched.days.length || !sched.targets.length) { alert('Fill in name, days, and targets'); return; }
    try {
        await fetch('/api/schedules', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(sched)});
        hideAddForm(); selectedDays.clear(); await fetchData();
    } catch(e) { alert('Failed: '+e); }
}

async function toggleSchedule(index) {
    try { await fetch('/api/schedules/'+index+'/toggle', {method:'POST'}); await fetchData(); } catch(e) { alert('Failed: '+e); }
}

async function deleteSchedule(index) {
    if (!confirm('Delete this schedule?')) return;
    try { await fetch('/api/schedules/'+index, {method:'DELETE'}); await fetchData(); } catch(e) { alert('Failed: '+e); }
}

const CHECK_INTERVAL = 60;
fetchData();
setInterval(fetchData, 10000);
setInterval(() => { document.getElementById('clock').textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}); }, 1000);
</script>
</body></html>"""


# ============================================================
# HTTP Server
# ============================================================

pce_client = None


class SchedulerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/status":
            with state_lock:
                self.send_json(200, dict(app_state))
        elif self.path == "/api/rulesets":
            self.handle_list_rulesets()
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
        else:
            self.send_error(404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if self.path == "/api/schedules":
            self.handle_add_schedule(body)
        elif self.path.startswith("/api/schedules/") and self.path.endswith("/toggle"):
            self.handle_toggle_schedule()
        else:
            self.send_error(404)

    def do_DELETE(self):
        if self.path.startswith("/api/schedules/"):
            self.handle_delete_schedule()
        else:
            self.send_error(404)

    def handle_add_schedule(self, body):
        try:
            sched = json.loads(body)
        except json.JSONDecodeError:
            self.send_json(400, {"error": "Invalid JSON"})
            return
        schedules = load_schedules()
        schedules.append(sched)
        save_schedules(schedules)
        self.send_json(200, {"success": True})

    def handle_toggle_schedule(self):
        try:
            index = int(self.path.split("/")[3])
        except (ValueError, IndexError):
            self.send_json(400, {"error": "Invalid index"})
            return
        schedules = load_schedules()
        if 0 <= index < len(schedules):
            schedules[index]["enabled"] = not schedules[index].get("enabled", False)
            save_schedules(schedules)
            self.send_json(200, {"success": True, "enabled": schedules[index]["enabled"]})
        else:
            self.send_json(400, {"error": "Invalid index"})

    def handle_delete_schedule(self):
        try:
            index = int(self.path.split("/")[3])
        except (ValueError, IndexError):
            self.send_json(400, {"error": "Invalid index"})
            return
        schedules = load_schedules()
        if 0 <= index < len(schedules):
            schedules.pop(index)
            save_schedules(schedules)
            self.send_json(200, {"success": True})
        else:
            self.send_json(400, {"error": "Invalid index"})

    def handle_list_rulesets(self):
        """List available rulesets for target selection."""
        try:
            resp = pce_client.get("/sec_policy/draft/rule_sets")
            rulesets = resp.json() if resp.status_code == 200 else []
            result = [{"href": rs.get("href", ""), "name": rs.get("name", ""), "enabled": rs.get("enabled", True)} for rs in rulesets if isinstance(rs, dict)]
            self.send_json(200, result)
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    global pce_client

    log.info("Starting rule-scheduler...")
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce_client = get_pce()
    log.info("Connected to PCE: %s", pce_client.base_url)

    schedules = load_schedules()
    active = sum(1 for s in schedules if s.get("enabled"))
    log.info("Loaded %d schedules (%d active)", len(schedules), active)

    poller = threading.Thread(target=poller_loop, args=(pce_client,), daemon=True)
    poller.start()
    run_check(pce_client)

    server = HTTPServer(("0.0.0.0", port), SchedulerHandler)
    log.info("Dashboard on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
