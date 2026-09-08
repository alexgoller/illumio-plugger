#!/usr/bin/env python3
"""dragos-sync — sync OT/ICS asset inventory from the Dragos Platform into
Illumio as unmanaged workloads with labels.

Pulls assets from the Dragos SiteStore API (GET /api/v{N}/assets, HTTP Basic
with an API ID/Secret) and upserts them as Illumio unmanaged workloads, made
idempotent with external_data_set="dragos" + external_data_reference=<asset id>
so re-syncs update rather than duplicate. Dragos attributes become Illumio
labels (device type -> role, zone -> loc, Purdue level -> env, vendor and
criticality as custom dimensions); missing label values are created on demand.

The exact Dragos asset JSON keys vary by SiteStore version, so field extraction
tries a list of candidate keys per attribute and the whole mapping is
overridable via LABEL_MAP. Enable DEBUG to dump a raw asset + its computed
mapping to tune the field map against your Dragos version.
"""

import base64
import json
import os
import time
from datetime import datetime, timezone

import requests

from plugger_sdk import Plugin

app = Plugin("dragos-sync")

DRAGOS_HOST = app.env("DRAGOS_HOST", "").strip().rstrip("/")
DRAGOS_API_VERSION = app.env("DRAGOS_API_VERSION", "v2").strip().strip("/")
DRAGOS_API_ID = app.env("DRAGOS_API_ID", "").strip()
DRAGOS_API_SECRET = app.env("DRAGOS_API_SECRET", "").strip()
DRAGOS_TLS_SKIP_VERIFY = app.env("DRAGOS_TLS_SKIP_VERIFY", "true").lower() in ("1", "true", "yes")
CREATE_LABELS = app.env("CREATE_LABELS", "true").lower() in ("1", "true", "yes")
DRY_RUN = app.env("DRY_RUN", "false").lower() in ("1", "true", "yes")
EXTERNAL_DATA_SET = "dragos"
PAGE_SIZE = int(app.env("PAGE_SIZE", "500"))

debug_enabled = app.env("DEBUG", "false").lower() in ("1", "true", "yes")

# Illumio label key -> ordered candidate Dragos asset field names.
# Purdue level maps to env per design; vendor/criticality are custom dimensions.
DEFAULT_LABEL_MAP = {
    "role": ["device_type", "asset_type", "type", "role", "device_role"],
    "loc": ["zone", "zone_name", "site", "location"],
    "env": ["purdue_level", "purdue", "level"],
    "vendor": ["vendor", "manufacturer", "make"],
    "criticality": ["criticality", "importance", "risk"],
}
CORE_DIMS = {"role", "app", "env", "loc"}  # dimensions Illumio ships by default

ID_FIELDS = ["id", "asset_id", "uuid", "_id", "assetId"]
HOST_FIELDS = ["hostname", "name", "display_name", "host_name"]
IP_FIELDS = ["ip_addresses", "ip_address", "ips", "ip", "addresses"]


def _label_map():
    override = app.env("LABEL_MAP", "").strip()
    if override:
        try:
            m = json.loads(override)
            # normalize each value to a list of candidate keys
            return {k: (v if isinstance(v, list) else [v]) for k, v in m.items()}
        except ValueError:
            app.log.warning("LABEL_MAP is not valid JSON — using defaults")
    return DEFAULT_LABEL_MAP


def _first(asset, keys):
    for k in keys:
        v = asset.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


def _asset_ips(asset):
    raw = _first(asset, IP_FIELDS)
    ips = []
    for item in (raw if isinstance(raw, list) else [raw] if raw else []):
        if isinstance(item, str):
            ips.append(item)
        elif isinstance(item, dict):
            v = item.get("ip") or item.get("address") or item.get("value")
            if v:
                ips.append(v)
    # keep IPv4-looking, dedupe, drop empties
    out = []
    for ip in ips:
        ip = str(ip).strip()
        if ip and ":" not in ip and ip not in out:
            out.append(ip)
    return out


# ---------------------------------------------------------------------------
# Dragos SiteStore client
# ---------------------------------------------------------------------------

class DragosClient:
    def __init__(self):
        self.base = f"{DRAGOS_HOST}/api/{DRAGOS_API_VERSION}"
        self.session = requests.Session()
        self.session.verify = not DRAGOS_TLS_SKIP_VERIFY
        token = base64.b64encode(f"{DRAGOS_API_ID}:{DRAGOS_API_SECRET}".encode()).decode()
        self.session.headers.update({"Authorization": f"Basic {token}", "Accept": "application/json"})

    def get_assets(self):
        """Fetch all assets, tolerating list-or-envelope responses and common
        pagination shapes (page/page_size). Returns a list of asset dicts."""
        assets, page = [], 1
        while page <= 10000:  # safety cap
            r = self.session.get(f"{self.base}/assets",
                                 params={"page": page, "page_size": PAGE_SIZE}, timeout=60)
            if r.status_code >= 400:
                raise RuntimeError(f"Dragos GET /assets page {page} -> HTTP {r.status_code}: {r.text[:200]}")
            body = r.json()
            batch = self._extract_list(body)
            assets.extend(batch)
            if len(batch) < PAGE_SIZE:
                break
            page += 1
        return assets

    @staticmethod
    def _extract_list(body):
        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            for key in ("data", "assets", "results", "items", "records"):
                if isinstance(body.get(key), list):
                    return body[key]
        return []


# ---------------------------------------------------------------------------
# Illumio label + dimension helpers (via the SDK-provided pce client)
# ---------------------------------------------------------------------------

def _load_labels(pce):
    resp = pce.get("/labels", params={"max_results": 100000})
    labels = resp.json() if resp.status_code < 400 else []
    return {(l["key"], l["value"]): l["href"] for l in labels if l.get("key") and l.get("value")}


def _ensure_dimensions(pce, needed_keys):
    """Ensure custom label dimensions exist (best-effort). Returns the set of
    usable dimension keys (core + any custom that exist or were created)."""
    usable = set(CORE_DIMS)
    custom = [k for k in needed_keys if k not in CORE_DIMS]
    if not custom:
        return usable
    try:
        resp = pce.get("/label_dimensions", params={"max_results": 1000})
        existing = {d["key"] for d in resp.json()} if resp.status_code < 400 else set()
    except Exception:  # noqa: BLE001 — older PCE may lack this endpoint
        existing = set()
    for k in custom:
        if k in existing:
            usable.add(k)
        elif CREATE_LABELS and not DRY_RUN:
            try:
                r = pce.post("/label_dimensions", json={"key": k, "display_name": k.capitalize()})
                if getattr(r, "status_code", 500) < 400:
                    usable.add(k)
                    app.log.info("Created label dimension '%s'", k)
                else:
                    app.log.warning("Could not create dimension '%s' (HTTP %s) — skipping those labels", k, r.status_code)
            except Exception as e:  # noqa: BLE001
                app.log.warning("Dimension '%s' unavailable (%s) — skipping", k, e)
    return usable


def _label_href(pce, cache, key, value):
    value = str(value).strip()
    if not value:
        return None
    if (key, value) in cache:
        return cache[(key, value)]
    if not (CREATE_LABELS and not DRY_RUN):
        return None
    r = pce.post("/labels", json={"key": key, "value": value})
    if getattr(r, "status_code", 500) < 400:
        href = r.json().get("href")
        cache[(key, value)] = href
        return href
    app.log.warning("Create label %s=%s -> HTTP %s", key, value, getattr(r, "status_code", "?"))
    return None


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------

def build_workload(asset, label_map, pce, label_cache, usable_dims, sample=None):
    asset_id = _first(asset, ID_FIELDS)
    if not asset_id:
        return None
    hostname = _first(asset, HOST_FIELDS) or f"dragos-{asset_id}"
    ips = _asset_ips(asset)

    label_hrefs = []
    computed = {}
    for key, candidates in label_map.items():
        if key not in usable_dims:
            continue
        val = _first(asset, candidates)
        if val in (None, "", [], {}):
            continue
        val = str(val)
        computed[key] = val
        href = _label_href(pce, label_cache, key, val)
        if href:
            label_hrefs.append({"href": href})

    if sample is not None:
        sample.append({"asset_id": str(asset_id), "hostname": hostname, "ips": ips, "labels": computed})

    wl = {
        "name": hostname,
        "hostname": hostname,
        "interfaces": [{"name": f"eth{i}", "address": ip} for i, ip in enumerate(ips)],
        "labels": label_hrefs,
        "external_data_set": EXTERNAL_DATA_SET,
        "external_data_reference": str(asset_id),
    }
    return wl


def _existing_synced(pce):
    """Map external_data_reference -> workload href for previously-synced assets."""
    resp = pce.get("/workloads", params={"external_data_set": EXTERNAL_DATA_SET, "max_results": 100000})
    out = {}
    if resp.status_code < 400:
        for w in resp.json():
            ref = w.get("external_data_reference")
            if ref:
                out[ref] = w.get("href")
    return out


def _bulk(pce, path, method, items, results_key):
    """Run a bulk_create/bulk_update in batches of 1000, tallying per-item status."""
    ok = fail = 0
    for i in range(0, len(items), 1000):
        batch = items[i:i + 1000]
        r = pce.post(path, json=batch) if method == "post" else pce.put(path, json=batch)
        try:
            resp = r.json()
        except Exception:  # noqa: BLE001
            resp = []
        if getattr(r, "status_code", 500) >= 400 and not isinstance(resp, list):
            fail += len(batch)
            app.log.warning("%s -> HTTP %s: %s", path, r.status_code, str(resp)[:200])
            continue
        for item in (resp if isinstance(resp, list) else []):
            if str(item.get("status", "")).lower() in ("created", "updated", ""):
                ok += 1
            else:
                fail += 1
        # if the API returned no per-item array, assume batch ok on 2xx
        if not isinstance(resp, list):
            ok += len(batch)
    return ok, fail


def run_sync(pce):
    start = time.time()
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "running", "dragos_host": DRAGOS_HOST,
        "assets": 0, "created": 0, "updated": 0, "labels_created": 0,
        "stale": 0, "dry_run": DRY_RUN, "error": None, "debug": {},
    }
    try:
        if not (DRAGOS_HOST and DRAGOS_API_ID and DRAGOS_API_SECRET):
            raise RuntimeError("DRAGOS_HOST, DRAGOS_API_ID and DRAGOS_API_SECRET are required")

        app.log.info("Fetching assets from Dragos %s/api/%s ...", DRAGOS_HOST, DRAGOS_API_VERSION)
        assets = DragosClient().get_assets()
        result["assets"] = len(assets)
        app.log.info("Fetched %d Dragos assets", len(assets))

        label_map = _label_map()
        label_cache = _load_labels(pce)
        before_labels = len(label_cache)
        usable_dims = _ensure_dimensions(pce, label_map.keys())

        sample = [] if debug_enabled else None
        desired = []
        for a in assets:
            wl = build_workload(a, label_map, pce, label_cache, usable_dims, sample)
            if wl:
                desired.append(wl)
        result["labels_created"] = max(0, len(label_cache) - before_labels)

        existing = _existing_synced(pce)
        creates, updates = [], []
        seen_refs = set()
        for wl in desired:
            ref = wl["external_data_reference"]
            seen_refs.add(ref)
            if ref in existing:
                updates.append({**wl, "href": existing[ref]})
            else:
                creates.append(wl)

        stale = [ref for ref in existing if ref not in seen_refs]
        result["stale"] = len(stale)

        if debug_enabled:
            result["debug"] = {
                "sample_assets": (assets[:2] if assets else []),
                "sample_mapping": (sample[:10] if sample else []),
                "usable_dimensions": sorted(usable_dims),
                "stale_refs": stale[:20],
            }

        if DRY_RUN:
            result["created"], result["updated"] = len(creates), len(updates)
            app.log.info("DRY_RUN: would create %d, update %d, %d stale", len(creates), len(updates), len(stale))
        else:
            if creates:
                ok, _ = _bulk(pce, "/workloads/bulk_create", "post", creates, "created")
                result["created"] = ok
            if updates:
                ok, _ = _bulk(pce, "/workloads/bulk_update", "put", updates, "updated")
                result["updated"] = ok
            app.log.info("Synced: %d created, %d updated, %d stale (flagged, not deleted)",
                         result["created"], result["updated"], len(stale))

        result["status"] = "success"
    except Exception as e:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = str(e)
        app.log.exception("Dragos sync failed")
    result["duration"] = round(time.time() - start, 1)
    return result


# ---------------------------------------------------------------------------
# Lifecycle + API
# ---------------------------------------------------------------------------

@app.poll(interval_env="SYNC_INTERVAL", default=3600)
def scheduled_sync(pce):
    result = run_sync(pce)
    app.update_state({
        "last_sync": result,
        "sync_count": app.state.get("sync_count", 0) + 1,
        "history": ([result] + app.state.get("history", []))[:20],
    })


@app.api("GET", "/api/state")
def get_state(request):
    return app.state


@app.api("POST", "/api/debug")
def toggle_debug(request):
    global debug_enabled
    debug_enabled = bool((request.json or {}).get("enabled", not debug_enabled))
    return {"debug": debug_enabled}


@app.api("POST", "/api/sync")
def trigger_sync(request):
    result = run_sync(app.pce)
    app.update_state({
        "last_sync": result,
        "sync_count": app.state.get("sync_count", 0) + 1,
        "history": ([result] + app.state.get("history", []))[:20],
    })
    return result


@app.dashboard
def render():
    return DASHBOARD_HTML


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dragos Sync</title>
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
      <h1 class="text-2xl font-bold text-white">Dragos Sync</h1>
      <p class="text-sm text-gray-500 mt-1">OT/ICS assets from Dragos &rarr; Illumio unmanaged workloads + labels</p>
    </div>
    <div class="flex items-center gap-3">
      <label class="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer"><input type="checkbox" id="dbg" onchange="toggleDebug()"> debug</label>
      <button onclick="syncNow()" id="btn" class="px-4 py-2 text-sm rounded bg-blue-700 hover:bg-blue-600 text-white">Sync now</button>
    </div>
  </div>
  <div id="summary" class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8"></div>
  <div id="meta" class="text-sm text-gray-400 mb-6"></div>
  <div id="debug" class="bg-dark-800 rounded-xl border border-gray-700 p-5 hidden"></div>
  <div class="text-center text-xs text-gray-600 mt-6" id="footer"></div>
</div>
<script>
const BASE = location.pathname.replace(/\/$/,'');
function fmt(n){return (n||0).toLocaleString();}
async function refresh(){
  const st = await (await fetch(BASE+'/api/state')).json();
  const s = st.last_sync || {};
  document.getElementById('summary').innerHTML = [
    ['Assets', s.assets, 'text-white'],
    ['Created', s.created, 'text-green-400'],
    ['Updated', s.updated, 'text-blue-400'],
    ['Labels +', s.labels_created, 'text-violet-400'],
    ['Stale', s.stale, 'text-amber-400'],
  ].map(([k,v,c])=>`<div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold ${c}">${fmt(v)}</div><div class="text-xs text-gray-500 mt-1">${k}</div></div>`).join('');
  const status = s.status==='error' ? `<span class="text-red-400">error: ${s.error||''}</span>` : (s.status||'—');
  document.getElementById('meta').innerHTML = `Last sync: ${s.timestamp||'never'} · status: ${status}${s.dry_run?' · <b>DRY RUN</b>':''} · Dragos: ${s.dragos_host||'(unset)'}`;
  const dbg = s.debug||{};
  const dp = document.getElementById('debug');
  if(Object.keys(dbg).length){
    dp.classList.remove('hidden');
    dp.innerHTML = '<h3 class="text-white font-semibold mb-2">Debug — raw asset &amp; computed mapping</h3><pre class="text-xs text-gray-300 overflow-x-auto">'+JSON.stringify(dbg,null,2).replace(/</g,'&lt;')+'</pre>';
  } else { dp.classList.add('hidden'); }
  document.getElementById('footer').textContent = (st.sync_count||0)+' sync(s) run';
}
async function syncNow(){const b=document.getElementById('btn');b.disabled=true;b.textContent='Syncing…';try{await fetch(BASE+'/api/sync',{method:'POST'});await refresh();}catch(e){alert('Sync failed: '+e);}b.disabled=false;b.textContent='Sync now';}
async function toggleDebug(){await fetch(BASE+'/api/debug',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:document.getElementById('dbg').checked})});}
refresh(); setInterval(refresh, 30000);
</script>
</body></html>"""


if __name__ == "__main__":
    app.run()
