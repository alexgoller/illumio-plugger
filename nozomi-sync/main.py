#!/usr/bin/env python3
"""nozomi-sync — sync OT/ICS/IoT asset inventory from Nozomi Networks into
Illumio as unmanaged workloads with labels.

Supports both Nozomi deployment models:
  - Vantage (cloud): sign in with an API key name + token to get a JWT, then
    GET /api/v1/assets (paginated).
  - Guardian / CMC (on-prem): sign in with username/password, then query the
    Nozomi Query Language (NQL) endpoint /api/open/query/do?query=assets.

Assets are upserted as Illumio unmanaged workloads, made idempotent with
external_data_set="nozomi" + external_data_reference=<nozomi asset id> so
re-syncs update rather than duplicate. Nozomi attributes become Illumio labels
(type -> role, zone -> loc, Purdue level -> env, vendor and criticality as
custom dimensions); missing label values are created on demand.

Nozomi asset JSON keys vary by product/version, so field extraction tries a
list of candidate keys per attribute and the whole mapping is overridable via
LABEL_MAP. Enable DEBUG to dump a raw asset + its computed mapping.
"""

import json
import os
import time
from datetime import datetime, timezone

import requests

from plugger_sdk import Plugin

app = Plugin("nozomi-sync")

NOZOMI_MODE = app.env("NOZOMI_MODE", "vantage").strip().lower()  # vantage | guardian
NOZOMI_HOST = app.env("NOZOMI_HOST", "").strip().rstrip("/")
# Vantage credentials
NOZOMI_KEY_NAME = app.env("NOZOMI_KEY_NAME", "").strip()
NOZOMI_KEY_TOKEN = app.env("NOZOMI_KEY_TOKEN", "").strip()
# Guardian credentials
NOZOMI_USERNAME = app.env("NOZOMI_USERNAME", "").strip()
NOZOMI_PASSWORD = app.env("NOZOMI_PASSWORD", "").strip()

NOZOMI_TLS_SKIP_VERIFY = app.env("NOZOMI_TLS_SKIP_VERIFY", "true").lower() in ("1", "true", "yes")
CREATE_LABELS = app.env("CREATE_LABELS", "true").lower() in ("1", "true", "yes")
DRY_RUN = app.env("DRY_RUN", "false").lower() in ("1", "true", "yes")
PAGE_SIZE = int(app.env("PAGE_SIZE", "500"))
EXTERNAL_DATA_SET = "nozomi"

debug_enabled = app.env("DEBUG", "false").lower() in ("1", "true", "yes")

# Illumio label key -> ordered candidate Nozomi asset field names.
# Purdue level ('level' in Guardian) maps to env; vendor/criticality are custom.
DEFAULT_LABEL_MAP = {
    "role": ["type", "product_name", "device_type", "role", "asset_type"],
    "loc": ["zone", "site", "zone_name", "location"],
    "env": ["level", "purdue_level", "purdue"],
    "vendor": ["vendor", "mac_vendor", "manufacturer"],
    "criticality": ["criticality", "risk", "importance"],
}
CORE_DIMS = {"role", "app", "env", "loc"}

ID_FIELDS = ["id", "uuid", "asset_id", "_id"]
HOST_FIELDS = ["name", "hostname", "label", "display_name"]
IP_FIELDS = ["ip", "ip_addresses", "ips", "addresses"]


def _label_map():
    override = app.env("LABEL_MAP", "").strip()
    if override:
        try:
            m = json.loads(override)
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
            # Guardian 'ip' can be a comma/space separated string
            ips.extend(part for part in item.replace(",", " ").split())
        elif isinstance(item, dict):
            v = item.get("ip") or item.get("address") or item.get("value")
            if v:
                ips.append(v)
    out = []
    for ip in ips:
        ip = str(ip).strip()
        if ip and ":" not in ip and ip not in out:
            out.append(ip)
    return out


# ---------------------------------------------------------------------------
# Nozomi client (Vantage + Guardian)
# ---------------------------------------------------------------------------

class NozomiClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = not NOZOMI_TLS_SKIP_VERIFY
        self.session.headers.update({"Accept": "application/json"})
        self.mode = NOZOMI_MODE
        self._authenticated = False

    def _auth(self):
        if self._authenticated:
            return
        if self.mode == "vantage":
            r = self.session.post(f"{NOZOMI_HOST}/api/v1/keys/sign_in",
                                  json={"key_name": NOZOMI_KEY_NAME, "key_token": NOZOMI_KEY_TOKEN},
                                  timeout=30)
            if r.status_code >= 400:
                raise RuntimeError(f"Vantage sign_in -> HTTP {r.status_code}: {r.text[:200]}")
            token = None
            # token may be in JSON body or an Authorization response header
            try:
                token = (r.json() or {}).get("token")
            except ValueError:
                pass
            token = token or r.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                raise RuntimeError("Vantage sign_in returned no token")
            self.session.headers["Authorization"] = f"Bearer {token}"
        else:  # guardian
            r = self.session.post(f"{NOZOMI_HOST}/api/open/sign_in",
                                  json={"username": NOZOMI_USERNAME, "password": NOZOMI_PASSWORD},
                                  timeout=30)
            if r.status_code >= 400:
                raise RuntimeError(f"Guardian sign_in -> HTTP {r.status_code}: {r.text[:200]}")
            # Guardian returns a CSRF token used on subsequent requests
            csrf = None
            try:
                csrf = (r.json() or {}).get("csrf_token")
            except ValueError:
                pass
            csrf = csrf or self.session.cookies.get("_sqopen_csrf_token")
            if csrf:
                self.session.headers["X-CSRF-Token"] = csrf
        self._authenticated = True

    def get_assets(self):
        self._auth()
        return self._vantage_assets() if self.mode == "vantage" else self._guardian_assets()

    def _vantage_assets(self):
        assets, page = [], 1
        while page <= 10000:
            r = self.session.get(f"{NOZOMI_HOST}/api/v1/assets",
                                 params={"page[size]": PAGE_SIZE, "page[number]": page}, timeout=60)
            if r.status_code == 401:  # JWT expired (30 min) — re-auth once
                self._authenticated = False
                self._auth()
                continue
            if r.status_code >= 400:
                raise RuntimeError(f"Vantage GET /assets page {page} -> HTTP {r.status_code}: {r.text[:200]}")
            batch = _extract_list(r.json())
            assets.extend(batch)
            if len(batch) < PAGE_SIZE:
                break
            page += 1
        return assets

    def _guardian_assets(self):
        # NQL: return assets; the query endpoint responds with {"result": [...]}
        r = self.session.get(f"{NOZOMI_HOST}/api/open/query/do",
                            params={"query": "assets"}, timeout=120)
        if r.status_code >= 400:
            raise RuntimeError(f"Guardian query assets -> HTTP {r.status_code}: {r.text[:200]}")
        return _extract_list(r.json())


def _extract_list(body):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in ("result", "data", "assets", "results", "items", "records"):
            if isinstance(body.get(key), list):
                return body[key]
    return []


# ---------------------------------------------------------------------------
# Illumio label + dimension helpers
# ---------------------------------------------------------------------------

def _load_labels(pce):
    resp = pce.get("/labels", params={"max_results": 100000})
    labels = resp.json() if resp.status_code < 400 else []
    return {(l["key"], l["value"]): l["href"] for l in labels if l.get("key") and l.get("value")}


def _ensure_dimensions(pce, needed_keys):
    usable = set(CORE_DIMS)
    custom = [k for k in needed_keys if k not in CORE_DIMS]
    if not custom:
        return usable
    try:
        resp = pce.get("/label_dimensions", params={"max_results": 1000})
        existing = {d["key"] for d in resp.json()} if resp.status_code < 400 else set()
    except Exception:  # noqa: BLE001
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
                    app.log.warning("Could not create dimension '%s' (HTTP %s) — skipping", k, r.status_code)
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
    hostname = _first(asset, HOST_FIELDS) or f"nozomi-{asset_id}"
    ips = _asset_ips(asset)

    label_hrefs, computed = [], {}
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

    return {
        "name": hostname,
        "hostname": hostname,
        "interfaces": [{"name": f"eth{i}", "address": ip} for i, ip in enumerate(ips)],
        "labels": label_hrefs,
        "external_data_set": EXTERNAL_DATA_SET,
        "external_data_reference": str(asset_id),
    }


def _existing_synced(pce):
    resp = pce.get("/workloads", params={"external_data_set": EXTERNAL_DATA_SET, "max_results": 100000})
    out = {}
    if resp.status_code < 400:
        for w in resp.json():
            ref = w.get("external_data_reference")
            if ref:
                out[ref] = w.get("href")
    return out


def _bulk(pce, path, method, items):
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
        if isinstance(resp, list):
            for item in resp:
                if str(item.get("status", "")).lower() in ("created", "updated", ""):
                    ok += 1
                else:
                    fail += 1
        else:
            ok += len(batch)
    return ok, fail


def run_sync(pce):
    start = time.time()
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "status": "running",
        "mode": NOZOMI_MODE, "nozomi_host": NOZOMI_HOST,
        "assets": 0, "created": 0, "updated": 0, "labels_created": 0,
        "stale": 0, "dry_run": DRY_RUN, "error": None, "debug": {},
    }
    try:
        if not NOZOMI_HOST:
            raise RuntimeError("NOZOMI_HOST is required")
        if NOZOMI_MODE == "vantage" and not (NOZOMI_KEY_NAME and NOZOMI_KEY_TOKEN):
            raise RuntimeError("Vantage mode requires NOZOMI_KEY_NAME and NOZOMI_KEY_TOKEN")
        if NOZOMI_MODE == "guardian" and not (NOZOMI_USERNAME and NOZOMI_PASSWORD):
            raise RuntimeError("Guardian mode requires NOZOMI_USERNAME and NOZOMI_PASSWORD")

        app.log.info("Fetching assets from Nozomi %s (%s) ...", NOZOMI_HOST, NOZOMI_MODE)
        assets = NozomiClient().get_assets()
        result["assets"] = len(assets)
        app.log.info("Fetched %d Nozomi assets", len(assets))

        label_map = _label_map()
        label_cache = _load_labels(pce)
        before = len(label_cache)
        usable_dims = _ensure_dimensions(pce, label_map.keys())

        sample = [] if debug_enabled else None
        desired = [wl for a in assets
                   if (wl := build_workload(a, label_map, pce, label_cache, usable_dims, sample))]
        result["labels_created"] = max(0, len(label_cache) - before)

        existing = _existing_synced(pce)
        creates, updates, seen = [], [], set()
        for wl in desired:
            ref = wl["external_data_reference"]
            seen.add(ref)
            (updates if ref in existing else creates).append(
                {**wl, "href": existing[ref]} if ref in existing else wl)
        stale = [ref for ref in existing if ref not in seen]
        result["stale"] = len(stale)

        if debug_enabled:
            result["debug"] = {
                "sample_assets": assets[:2] if assets else [],
                "sample_mapping": sample[:10] if sample else [],
                "usable_dimensions": sorted(usable_dims),
                "stale_refs": stale[:20],
            }

        if DRY_RUN:
            result["created"], result["updated"] = len(creates), len(updates)
            app.log.info("DRY_RUN: would create %d, update %d, %d stale", len(creates), len(updates), len(stale))
        else:
            if creates:
                result["created"], _ = _bulk(pce, "/workloads/bulk_create", "post", creates)
            if updates:
                result["updated"], _ = _bulk(pce, "/workloads/bulk_update", "put", updates)
            app.log.info("Synced: %d created, %d updated, %d stale (flagged)",
                         result["created"], result["updated"], len(stale))
        result["status"] = "success"
    except Exception as e:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = str(e)
        app.log.exception("Nozomi sync failed")
    result["duration"] = round(time.time() - start, 1)
    return result


# ---------------------------------------------------------------------------
# Lifecycle + API
# ---------------------------------------------------------------------------

@app.poll(interval_env="SYNC_INTERVAL", default=3600)
def scheduled_sync(pce):
    result = run_sync(pce)
    app.update_state({"last_sync": result, "sync_count": app.state.get("sync_count", 0) + 1,
                      "history": ([result] + app.state.get("history", []))[:20]})


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
    app.update_state({"last_sync": result, "sync_count": app.state.get("sync_count", 0) + 1,
                      "history": ([result] + app.state.get("history", []))[:20]})
    return result


@app.dashboard
def render():
    return DASHBOARD_HTML


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nozomi Sync</title>
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
      <h1 class="text-2xl font-bold text-white">Nozomi Sync</h1>
      <p class="text-sm text-gray-500 mt-1">OT/ICS/IoT assets from Nozomi &rarr; Illumio unmanaged workloads + labels</p>
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
    ['Assets', s.assets, 'text-white'],['Created', s.created, 'text-green-400'],
    ['Updated', s.updated, 'text-blue-400'],['Labels +', s.labels_created, 'text-violet-400'],
    ['Stale', s.stale, 'text-amber-400'],
  ].map(([k,v,c])=>`<div class="bg-dark-800 rounded-xl border border-gray-700 p-5"><div class="text-3xl font-bold ${c}">${fmt(v)}</div><div class="text-xs text-gray-500 mt-1">${k}</div></div>`).join('');
  const status = s.status==='error' ? `<span class="text-red-400">error: ${s.error||''}</span>` : (s.status||'—');
  document.getElementById('meta').innerHTML = `Last sync: ${s.timestamp||'never'} · mode: ${s.mode||'?'} · status: ${status}${s.dry_run?' · <b>DRY RUN</b>':''} · Nozomi: ${s.nozomi_host||'(unset)'}`;
  const dbg = s.debug||{}, dp = document.getElementById('debug');
  if(Object.keys(dbg).length){ dp.classList.remove('hidden'); dp.innerHTML='<h3 class="text-white font-semibold mb-2">Debug — raw asset &amp; computed mapping</h3><pre class="text-xs text-gray-300 overflow-x-auto">'+JSON.stringify(dbg,null,2).replace(/</g,'&lt;')+'</pre>'; }
  else { dp.classList.add('hidden'); }
  document.getElementById('footer').textContent = (st.sync_count||0)+' sync(s) run';
}
async function syncNow(){const b=document.getElementById('btn');b.disabled=true;b.textContent='Syncing…';try{await fetch(BASE+'/api/sync',{method:'POST'});await refresh();}catch(e){alert('Sync failed: '+e);}b.disabled=false;b.textContent='Sync now';}
async function toggleDebug(){await fetch(BASE+'/api/debug',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:document.getElementById('dbg').checked})});}
refresh(); setInterval(refresh, 30000);
</script>
</body></html>"""


if __name__ == "__main__":
    app.run()
