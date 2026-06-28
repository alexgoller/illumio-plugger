#!/usr/bin/env python3
"""policy-backup — snapshot PCE policy + inventory, diff over time, guarded restore.

Backs up all policy objects (and a workload inventory) to timestamped JSON
directories under /data/backups, with retention and optional git push. Diffs
any two backups (or a backup vs current live policy). Restore is guarded:
preview the change set, confirm explicitly, then write to DRAFT policy only —
it never provisions.
"""

import hashlib
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone

from plugger_sdk import Plugin

app = Plugin("policy-backup")

BACKUP_DIR = "/data/backups"
RETENTION = int(app.env("RETENTION_COUNT", "30"))
GIT_REMOTE = app.env("GIT_REMOTE", "").strip()
GIT_BRANCH = app.env("GIT_BRANCH", "main").strip() or "main"
GIT_TOKEN = app.env("GIT_TOKEN", "").strip()
REPORT_ON_CHANGE = app.env("REPORT_ON_CHANGE", "false").lower() in ("1", "true", "yes")

# Object types captured in each backup.
#   name        — output filename / logical type
#   get_path    — active-policy collection endpoint (org-relative)
#   draft_path  — draft collection endpoint for restore (None = not restorable)
OBJECT_TYPES = [
    ("labels", "/labels", "/labels"),
    ("services", "/sec_policy/active/services", "/sec_policy/draft/services"),
    ("ip_lists", "/sec_policy/active/ip_lists", "/sec_policy/draft/ip_lists"),
    ("label_groups", "/sec_policy/active/label_groups", "/sec_policy/draft/label_groups"),
    ("enforcement_boundaries", "/sec_policy/active/enforcement_boundaries", "/sec_policy/draft/enforcement_boundaries"),
    ("rule_sets", "/sec_policy/active/rule_sets", "/sec_policy/draft/rule_sets"),
    ("pairing_profiles", "/pairing_profiles", "/pairing_profiles"),
    ("workloads", "/workloads", None),  # inventory snapshot — never restored
]

# Restore applies these types, in dependency order (referenced objects first).
RESTORE_ORDER = ["labels", "services", "ip_lists", "label_groups",
                 "enforcement_boundaries", "rule_sets", "pairing_profiles"]

# Server-managed fields stripped from bodies before create/update.
READONLY_FIELDS = {
    "href", "created_at", "updated_at", "deleted_at", "created_by", "updated_by",
    "deleted_by", "caps", "update_type", "deleted",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch(pce, path):
    resp = pce.get(path, params={"max_results": 100000})
    if resp.status_code >= 400:
        raise RuntimeError(f"GET {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    return data if isinstance(data, list) else [data]


def _content_hash(obj):
    """Stable hash of an object ignoring server-managed/volatile fields."""
    clean = {k: v for k, v in obj.items() if k not in READONLY_FIELDS}
    return hashlib.sha256(json.dumps(clean, sort_keys=True).encode()).hexdigest()


def _strip_readonly(obj):
    return {k: v for k, v in obj.items() if k not in READONLY_FIELDS}


def _list_backups():
    if not os.path.isdir(BACKUP_DIR):
        return []
    out = []
    for name in sorted(os.listdir(BACKUP_DIR)):
        d = os.path.join(BACKUP_DIR, name)
        mpath = os.path.join(d, "manifest.json")
        if os.path.isdir(d) and os.path.isfile(mpath):
            try:
                with open(mpath) as f:
                    out.append(json.load(f))
            except (OSError, ValueError):
                pass
    return out


def _load_backup_type(ts, name):
    path = os.path.join(BACKUP_DIR, ts, f"{name}.json")
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def _index_by_href(items):
    return {o["href"]: o for o in items if isinstance(o, dict) and o.get("href")}


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

def do_backup(pce):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    dest = os.path.join(BACKUP_DIR, ts)
    os.makedirs(dest, exist_ok=True)

    counts = {}
    for name, get_path, _ in OBJECT_TYPES:
        data = _fetch(pce, get_path)
        with open(os.path.join(dest, f"{name}.json"), "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        counts[name] = len(data)

    manifest = {
        "timestamp": ts,
        "pce_host": os.environ.get("PCE_HOST", ""),
        "org_id": os.environ.get("PCE_ORG_ID", ""),
        "counts": counts,
        "total_objects": sum(counts.values()),
    }
    with open(os.path.join(dest, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    app.log.info("Backup %s: %d objects across %d types", ts, manifest["total_objects"], len(counts))
    _prune_old()
    if GIT_REMOTE:
        _git_push(ts)
    return manifest


def _prune_old():
    backups = sorted(os.listdir(BACKUP_DIR)) if os.path.isdir(BACKUP_DIR) else []
    backups = [b for b in backups if os.path.isdir(os.path.join(BACKUP_DIR, b)) and b != ".git"]
    excess = len(backups) - RETENTION
    for old in backups[:max(0, excess)]:
        shutil.rmtree(os.path.join(BACKUP_DIR, old), ignore_errors=True)
        app.log.info("Pruned old backup %s", old)


def _git_push(ts):
    """Commit the backups dir and push to the configured remote (best-effort)."""
    remote = GIT_REMOTE
    if GIT_TOKEN and remote.startswith("https://") and "@" not in remote:
        remote = remote.replace("https://", f"https://x-access-token:{GIT_TOKEN}@")
    try:
        if not os.path.isdir(os.path.join(BACKUP_DIR, ".git")):
            subprocess.run(["git", "init", "-q"], cwd=BACKUP_DIR, check=True)
            subprocess.run(["git", "config", "user.email", "policy-backup@plugger"], cwd=BACKUP_DIR, check=True)
            subprocess.run(["git", "config", "user.name", "plugger policy-backup"], cwd=BACKUP_DIR, check=True)
        subprocess.run(["git", "add", "-A"], cwd=BACKUP_DIR, check=True)
        subprocess.run(["git", "commit", "-q", "-m", f"backup {ts}"], cwd=BACKUP_DIR, check=True)
        subprocess.run(["git", "push", "-q", remote, f"HEAD:{GIT_BRANCH}"], cwd=BACKUP_DIR, check=True)
        app.log.info("Pushed backup %s to git", ts)
    except subprocess.CalledProcessError as e:
        app.log.warning("git push failed: %s", e)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def _live_snapshot(pce):
    snap = {}
    for name, get_path, _ in OBJECT_TYPES:
        try:
            snap[name] = _fetch(pce, get_path)
        except RuntimeError as e:
            app.log.warning("live fetch %s failed: %s", name, e)
            snap[name] = []
    return snap


def diff_snapshots(a_by_type, b_by_type):
    """Diff two {type: [objects]} snapshots. Returns per-type added/removed/changed."""
    result = {}
    for name, _, _ in OBJECT_TYPES:
        a = _index_by_href(a_by_type.get(name, []))
        b = _index_by_href(b_by_type.get(name, []))
        added = [b[h] for h in b if h not in a]
        removed = [a[h] for h in a if h not in b]
        changed = [{"href": h, "name": b[h].get("name", h)}
                   for h in a if h in b and _content_hash(a[h]) != _content_hash(b[h])]
        if added or removed or changed:
            result[name] = {
                "added": [{"href": o.get("href"), "name": o.get("name", o.get("value", o.get("href")))} for o in added],
                "removed": [{"href": o.get("href"), "name": o.get("name", o.get("value", o.get("href")))} for o in removed],
                "changed": changed,
            }
    return result


def _load_snapshot(ts):
    return {name: _load_backup_type(ts, name) for name, _, _ in OBJECT_TYPES}


# ---------------------------------------------------------------------------
# Guarded restore (draft-only, never provisions)
# ---------------------------------------------------------------------------

def plan_restore(pce, ts):
    """Compute the create/update plan for restoring a backup into draft policy."""
    live = _live_snapshot(pce)
    plan = []
    for name in RESTORE_ORDER:
        draft_path = next((d for n, _, d in OBJECT_TYPES if n == name), None)
        if not draft_path:
            continue
        backup_objs = _index_by_href(_load_backup_type(ts, name))
        live_objs = _index_by_href(live.get(name, []))
        creates = [h for h in backup_objs if h not in live_objs]
        updates = [h for h in backup_objs
                   if h in live_objs and _content_hash(backup_objs[h]) != _content_hash(live_objs[h])]
        if creates or updates:
            plan.append({
                "type": name,
                "creates": [{"href": h, "name": backup_objs[h].get("name", backup_objs[h].get("value", h))} for h in creates],
                "updates": [{"href": h, "name": backup_objs[h].get("name", backup_objs[h].get("value", h))} for h in updates],
            })
    return plan


def apply_restore(pce, ts):
    """Apply a backup to DRAFT policy: create missing, update changed. Best-effort,
    per-object results, dependency order. Never deletes, never provisions."""
    results = {"created": [], "updated": [], "failed": []}
    for name in RESTORE_ORDER:
        draft_path = next((d for n, _, d in OBJECT_TYPES if n == name), None)
        if not draft_path:
            continue
        backup_objs = _index_by_href(_load_backup_type(ts, name))
        try:
            live_objs = _index_by_href(_fetch(pce, next(g for n, g, _ in OBJECT_TYPES if n == name)))
        except RuntimeError as e:
            results["failed"].append({"type": name, "error": str(e)})
            continue

        for href, obj in backup_objs.items():
            body = _strip_readonly(obj)
            try:
                if href not in live_objs:
                    resp = pce.post(draft_path, json=body)
                    bucket = "created"
                else:
                    if _content_hash(obj) == _content_hash(live_objs[href]):
                        continue  # unchanged
                    draft_href = href.replace("/sec_policy/active/", "/sec_policy/draft/")
                    resp = pce.put(draft_href, json=body)
                    bucket = "updated"
                if getattr(resp, "status_code", 0) >= 400:
                    results["failed"].append({"type": name, "name": obj.get("name", href),
                                              "http": resp.status_code, "error": resp.text[:200]})
                else:
                    results[bucket].append({"type": name, "name": obj.get("name", obj.get("value", href))})
            except Exception as e:  # noqa: BLE001 — best-effort, keep going
                results["failed"].append({"type": name, "name": obj.get("name", href), "error": str(e)})
    return results


# ---------------------------------------------------------------------------
# Scheduled backup
# ---------------------------------------------------------------------------

@app.poll(interval_env="BACKUP_INTERVAL", default=86400)
def scheduled_backup(pce):
    prev = _list_backups()
    prev_ts = prev[-1]["timestamp"] if prev else None
    manifest = do_backup(pce)

    changes = None
    if prev_ts:
        changes = diff_snapshots(_load_snapshot(prev_ts), _load_snapshot(manifest["timestamp"]))

    app.update_state({
        "last_backup": manifest,
        "backup_count": len(_list_backups()),
        "last_changes": changes or {},
    })

    if REPORT_ON_CHANGE and changes:
        _publish_change_report(manifest, changes)


def _publish_change_report(manifest, changes):
    import requests
    url = os.environ.get("PLUGGER_URL")
    token = os.environ.get("PLUGGER_WEBHOOK_TOKEN")
    if not url:
        return
    lines = [f"- **{t}**: +{len(c['added'])} / -{len(c['removed'])} / ~{len(c['changed'])}"
             for t, c in changes.items()]
    try:
        requests.post(f"{url}/api/reports/publish",
                      headers={"Authorization": f"Bearer {token}"},
                      json={"plugin": "policy-backup", "title": "PCE policy changed since last backup",
                            "severity": "info", "body": "## Policy changes\n" + "\n".join(lines),
                            "tags": ["backup", "policy-change"]},
                      timeout=10)
    except requests.RequestException as e:
        app.log.warning("report publish failed: %s", e)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.api("GET", "/api/backups")
def list_backups(request):
    return {"backups": _list_backups(), "retention": RETENTION, "git": bool(GIT_REMOTE)}


@app.api("POST", "/api/backup")
def trigger_backup(request):
    return do_backup(app.pce)


@app.api("GET", "/api/diff")
def get_diff(request):
    a = request.query.get("a", "")
    b = request.query.get("b", "")  # "live" or a timestamp
    if not a:
        return {"error": "param 'a' (backup timestamp) is required"}, 400
    snap_a = _load_snapshot(a)
    snap_b = _live_snapshot(app.pce) if b in ("", "live") else _load_snapshot(b)
    return {"a": a, "b": b or "live", "diff": diff_snapshots(snap_a, snap_b)}


@app.api("GET", "/api/restore/plan")
def restore_plan(request):
    ts = request.query.get("backup", "")
    if not ts:
        return {"error": "param 'backup' is required"}, 400
    return {"backup": ts, "plan": plan_restore(app.pce, ts)}


@app.api("POST", "/api/restore/apply")
def restore_apply(request):
    ts = (request.json or {}).get("backup", "")
    if not ts:
        return {"error": "backup is required"}, 400
    if not (request.json or {}).get("confirm"):
        return {"error": "confirm:true is required — restore writes to draft policy"}, 400
    app.log.info("Restoring backup %s to draft policy", ts)
    return apply_restore(app.pce, ts)


@app.api("GET", "/api/state")
def get_state(request):
    return app.state


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.dashboard
def render():
    return DASHBOARD_HTML


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Policy Backup</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<link rel="stylesheet" href="/brand/style.css" onerror="this.remove()">
<style>body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}</style>
</head>
<body class="min-h-screen">
<div class="max-w-6xl mx-auto px-6 py-8">
  <div class="flex items-center justify-between mb-8">
    <div>
      <h1 class="text-2xl font-bold text-white">Policy Backup</h1>
      <p class="text-sm text-gray-500 mt-1">Snapshot PCE policy &amp; inventory · diff · guarded restore</p>
    </div>
    <button onclick="backupNow()" id="btn-backup"
      class="px-4 py-2 text-sm rounded bg-blue-700 hover:bg-blue-600 text-white">Back up now</button>
  </div>

  <div id="summary" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"></div>

  <div class="bg-dark-800 rounded-xl border border-gray-700 overflow-hidden mb-8">
    <div class="px-5 py-3 border-b border-gray-700 flex items-center justify-between">
      <h2 class="text-lg font-semibold text-white">Backups</h2>
      <div class="flex items-center gap-2 text-xs">
        <button onclick="diffSelected()" class="px-2 py-1 rounded bg-dark-700 border border-gray-600 text-gray-300">Diff selected (or vs live)</button>
      </div>
    </div>
    <div class="overflow-x-auto max-h-[420px] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-dark-800"><tr class="text-left text-xs text-gray-500 uppercase border-b border-gray-700">
          <th class="px-4 py-3">Pick</th><th class="px-4 py-3">Timestamp</th><th class="px-4 py-3">Objects</th>
          <th class="px-4 py-3">PCE</th><th class="px-4 py-3 text-right">Actions</th>
        </tr></thead>
        <tbody id="backups"></tbody>
      </table>
    </div>
  </div>

  <div id="panel" class="bg-dark-800 rounded-xl border border-gray-700 p-5 hidden"></div>
  <div class="text-center text-xs text-gray-600 mt-6" id="footer"></div>
</div>
<script>
const BASE = location.pathname.replace(/\/$/,'');
let picks = [];

function fmt(n){return (n||0).toLocaleString();}

async function load(){
  const data = await (await fetch(BASE+'/api/backups')).json();
  const st = await (await fetch(BASE+'/api/state')).json();
  const backups = data.backups||[];
  const last = st.last_backup;
  document.getElementById('summary').innerHTML = [
    ['Backups', backups.length],
    ['Last objects', last? last.total_objects : 0],
    ['Retention', data.retention],
    ['Git', data.git? 'on':'off'],
  ].map(([k,v])=>`<div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold text-white">${fmt(v)}</div><div class="text-xs text-gray-500 mt-1">${k}</div></div>`).join('');

  document.getElementById('backups').innerHTML = backups.slice().reverse().map(b=>{
    const counts = Object.entries(b.counts||{}).map(([k,v])=>k+':'+v).join('  ');
    return `<tr class="border-b border-gray-800 hover:bg-dark-700/30">
      <td class="px-4 py-2"><input type="checkbox" value="${b.timestamp}" onchange="pick(this)"></td>
      <td class="px-4 py-2 font-mono text-gray-300">${b.timestamp}</td>
      <td class="px-4 py-2 text-gray-400" title="${counts}">${fmt(b.total_objects)}</td>
      <td class="px-4 py-2 text-gray-500">${b.pce_host||''}</td>
      <td class="px-4 py-2 text-right">
        <button onclick="diffLive('${b.timestamp}')" class="text-xs text-blue-400 hover:underline">diff vs live</button>
        <button onclick="planRestore('${b.timestamp}')" class="text-xs text-amber-400 hover:underline ml-3">restore…</button>
      </td></tr>`;
  }).join('') || '<tr><td colspan="5" class="px-4 py-6 text-center text-gray-600">No backups yet — click "Back up now".</td></tr>';
  document.getElementById('footer').textContent = backups.length+' backup(s) · retention '+data.retention;
}

function pick(cb){ picks = cb.checked ? [...picks, cb.value] : picks.filter(v=>v!==cb.value); }

async function backupNow(){
  const b=document.getElementById('btn-backup'); b.disabled=true; b.textContent='Backing up…';
  try{ await fetch(BASE+'/api/backup',{method:'POST'}); await load(); }catch(e){ alert('Backup failed: '+e); }
  b.disabled=false; b.textContent='Back up now';
}

function renderDiff(d, title){
  const types = Object.keys(d.diff||{});
  const body = types.length ? types.map(t=>{
    const c=d.diff[t];
    const rows = ['added','removed','changed'].flatMap(k=>(c[k]||[]).map(o=>
      `<tr><td class="px-3 py-1 text-gray-500">${t}</td><td class="px-3 py-1 ${k==='added'?'text-green-400':k==='removed'?'text-red-400':'text-amber-400'}">${k}</td><td class="px-3 py-1 text-gray-300">${o.name||o.href}</td></tr>`));
    return rows.join('');
  }).join('') : '<tr><td colspan="3" class="px-3 py-4 text-center text-gray-500">No differences.</td></tr>';
  show(`<h3 class="text-white font-semibold mb-3">${title}</h3>
    <table class="w-full text-sm"><thead><tr class="text-left text-xs text-gray-500 uppercase border-b border-gray-700"><th class="px-3 py-2">Type</th><th class="px-3 py-2">Change</th><th class="px-3 py-2">Object</th></tr></thead><tbody>${body}</tbody></table>`);
}

async function diffLive(ts){ const d=await (await fetch(BASE+'/api/diff?a='+ts+'&b=live')).json(); renderDiff(d, ts+'  →  live'); }
async function diffSelected(){
  if(picks.length===1){ return diffLive(picks[0]); }
  if(picks.length!==2){ alert('Pick 1 backup (diff vs live) or 2 backups.'); return; }
  const [a,b]=picks.sort(); const d=await (await fetch(BASE+'/api/diff?a='+a+'&b='+b)).json(); renderDiff(d, a+'  →  '+b);
}

async function planRestore(ts){
  const r = await (await fetch(BASE+'/api/restore/plan?backup='+ts)).json();
  const plan = r.plan||[];
  const rows = plan.length ? plan.map(p=>
    `<tr><td class="px-3 py-1 text-gray-400">${p.type}</td><td class="px-3 py-1 text-green-400">${p.creates.length} create</td><td class="px-3 py-1 text-amber-400">${p.updates.length} update</td></tr>`).join('')
    : '<tr><td colspan="3" class="px-3 py-4 text-center text-gray-500">Draft already matches this backup — nothing to restore.</td></tr>';
  show(`<h3 class="text-white font-semibold mb-2">Restore preview — ${ts}</h3>
    <p class="text-xs text-gray-500 mb-3">Writes to <b>draft</b> policy only (creates missing, updates changed). It never deletes and never provisions — review &amp; provision in the PCE console.</p>
    <table class="w-full text-sm mb-4"><thead><tr class="text-left text-xs text-gray-500 uppercase border-b border-gray-700"><th class="px-3 py-2">Type</th><th class="px-3 py-2">Create</th><th class="px-3 py-2">Update</th></tr></thead><tbody>${rows}</tbody></table>
    ${plan.length?`<button onclick="applyRestore('${ts}')" class="px-4 py-2 text-sm rounded bg-amber-600 hover:bg-amber-500 text-white">Confirm restore to draft</button>`:''}`);
}

async function applyRestore(ts){
  if(!confirm('Write this backup to DRAFT policy on the live PCE? It will not provision.')) return;
  show('<p class="text-gray-400">Restoring to draft…</p>');
  const r = await (await fetch(BASE+'/api/restore/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({backup:ts,confirm:true})})).json();
  show(`<h3 class="text-white font-semibold mb-3">Restore result — ${ts}</h3>
    <p class="text-sm"><span class="text-green-400">${(r.created||[]).length} created</span> · <span class="text-amber-400">${(r.updated||[]).length} updated</span> · <span class="text-red-400">${(r.failed||[]).length} failed</span></p>
    ${(r.failed||[]).length?'<pre class="mt-3 text-xs text-red-300 bg-dark-900 p-3 rounded overflow-x-auto">'+JSON.stringify(r.failed,null,2)+'</pre>':''}
    <p class="text-xs text-gray-500 mt-3">Review the draft in the PCE console and provision when ready.</p>`);
}

function show(html){ const p=document.getElementById('panel'); p.innerHTML=html; p.classList.remove('hidden'); p.scrollIntoView({behavior:'smooth'}); }

load(); setInterval(load, 30000);
</script>
</body></html>"""


if __name__ == "__main__":
    app.run()
