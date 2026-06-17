#!/usr/bin/env python3
"""
vmaps-handler — Import vulnerability scan data into Illumio PCE
vulnerability maps (vmaps). Supports Nessus, Qualys, and Tenable
file imports and live API pulls.
"""

import json
import os
import time
import traceback
from datetime import datetime, timezone

from plugger_sdk import Plugin

app = Plugin("vmaps-handler")

SCANNER_TYPE = app.env("SCANNER_TYPE", "").strip()
IMPORT_FILE = app.env("IMPORT_FILE", "").strip()
REPORT_NAME = app.env("REPORT_NAME", "plugger-vmaps")
AUTHORITATIVE = app.env("AUTHORITATIVE", "false").lower() in ("true", "1")

# Scanner API credentials
SCANNER_HOST = app.env("SCANNER_HOST", "")
SCANNER_USER = app.env("SCANNER_USER", "")
SCANNER_PASSWORD = app.env("SCANNER_PASSWORD", "")
SCANNER_ACCESS_KEY = app.env("SCANNER_ACCESS_KEY", "")
SCANNER_SECRET_KEY = app.env("SCANNER_SECRET_KEY", "")

# File-based scanner types
FILE_SCANNERS = {"nessus-file", "qualys-file", "tenable-sc-csv", "tenable-io-csv"}
# API-based scanner types
API_SCANNERS = {"qualys-api", "tenable-sc-api", "tenable-io-api"}

# ---------------------------------------------------------------------------
# PCE vulnerability API client (uses raw requests, not illumio SDK)
# ---------------------------------------------------------------------------

import requests
import ipaddress
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VulnPCEClient:
    def __init__(self, host, port, org_id, api_key, api_secret, verify=False):
        self.base = f"https://{host}:{port}/api/v2"
        self.org_id = org_id
        self.auth = (api_key, api_secret)
        self.verify = verify
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = self.verify
        self.session.headers.update({"Content-Type": "application/json"})

    def post_vulnerabilities(self, vulns):
        url = f"{self.base}/orgs/{self.org_id}/vulnerabilities"
        resp = self.session.post(url, json=vulns, headers={"Prefer": "respond-async"})
        return resp.status_code, resp.text[:500]

    def put_report(self, reference_id, report_body):
        url = f"{self.base}/orgs/{self.org_id}/vulnerability_reports/{reference_id}"
        resp = self.session.put(url, json=report_body, headers={"Prefer": "respond-async"})
        return resp.status_code, resp.text[:500]

    def get_workloads(self):
        url = f"{self.base}/orgs/{self.org_id}/workloads"
        resp = self.session.get(url, params={"max_results": 10000})
        if resp.status_code == 200:
            return resp.json()
        return []


def build_ip_to_workload_map(workloads):
    ip_map = {}
    for wl in workloads:
        href = wl.get("href", "")
        if not href:
            continue
        for iface in wl.get("interfaces", []):
            addr = iface.get("address", "")
            if addr and ":" not in addr:
                try:
                    normalized = str(ipaddress.ip_address(addr))
                    ip_map[normalized] = href
                except ValueError:
                    pass
            pub = iface.get("public_ip", "")
            if pub and ":" not in pub:
                try:
                    normalized = str(ipaddress.ip_address(pub))
                    ip_map[normalized] = href
                except ValueError:
                    pass
    return ip_map


# ---------------------------------------------------------------------------
# Import orchestration
# ---------------------------------------------------------------------------

def create_processor(scanner_type, import_file=""):
    from illumio_vuln_import.nessus import NessusProXMLReportProcessor
    from illumio_vuln_import.qualys import QualysXMLReportProcessor, QualysAPIProcessor
    from illumio_vuln_import.tenable import (
        TenableSCCSVReportProcessor, TenableIOCSVReportProcessor,
        TenableSCAPIReportProcessor, TenableIOAPIReportProcessor,
    )

    if scanner_type == "nessus-file":
        return NessusProXMLReportProcessor(import_file)
    elif scanner_type == "qualys-file":
        return QualysXMLReportProcessor(import_file)
    elif scanner_type == "tenable-sc-csv":
        return TenableSCCSVReportProcessor(import_file)
    elif scanner_type == "tenable-io-csv":
        return TenableIOCSVReportProcessor(import_file)
    elif scanner_type == "qualys-api":
        return QualysAPIProcessor(
            host=SCANNER_HOST,
            username=SCANNER_USER,
            password=SCANNER_PASSWORD,
        )
    elif scanner_type == "tenable-sc-api":
        return TenableSCAPIReportProcessor(
            host=SCANNER_HOST,
            username=SCANNER_USER,
            password=SCANNER_PASSWORD,
            access_key=SCANNER_ACCESS_KEY,
            secret_key=SCANNER_SECRET_KEY,
        )
    elif scanner_type == "tenable-io-api":
        return TenableIOAPIReportProcessor(
            host=SCANNER_HOST or "cloud.tenable.com",
            access_key=SCANNER_ACCESS_KEY,
            secret_key=SCANNER_SECRET_KEY,
        )
    else:
        raise ValueError(f"Unknown scanner type: {scanner_type}")


def run_import(pce_client, scanner_type, import_file=""):
    start = time.time()
    result = {
        "scanner_type": scanner_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "vulns_defined": 0,
        "detections_total": 0,
        "detections_matched": 0,
        "detections_dropped": 0,
        "workloads_scanned": 0,
        "ips_scanned": 0,
        "error": None,
    }

    try:
        # Create processor and parse/pull data
        app.log.info("Creating %s processor...", scanner_type)
        processor = create_processor(scanner_type, import_file)

        app.log.info("Processing scan data...")
        processor.process()

        vulns = processor.vulnerabilities
        detections = processor.detected_vulnerabilities
        app.log.info("Parsed %d vulnerability definitions, %d detections", len(vulns), len(detections))

        result["vulns_defined"] = len(vulns)
        result["detections_total"] = len(detections)

        # Upload vulnerability definitions in batches of 1000
        vuln_list = list(vulns.values())
        for i in range(0, len(vuln_list), 1000):
            batch = vuln_list[i:i+1000]
            status, resp = pce_client.post_vulnerabilities(batch)
            if status not in (200, 201, 204):
                app.log.warning("Vuln upload batch %d: HTTP %d — %s", i//1000, status, resp)

        # Fetch workloads and build IP map
        app.log.info("Fetching workloads for IP mapping...")
        workloads = pce_client.get_workloads()
        ip_map = build_ip_to_workload_map(workloads)
        result["workloads_scanned"] = len(workloads)
        app.log.info("Built IP map: %d IPs from %d workloads", len(ip_map), len(workloads))

        # Match detections to workloads
        matched = []
        scanned_ips = set()
        for det in detections:
            ip = det.get("ip_address", "")
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                continue
            scanned_ips.add(ip)
            href = ip_map.get(ip)
            if href:
                matched.append({
                    "ip_address": ip,
                    "workload": {"href": href},
                    "vulnerability": {"href": f"/orgs/{pce_client.org_id}/vulnerabilities/{det['vulnerability_id']}"},
                    "port": det.get("port"),
                    "proto": det.get("proto"),
                })

        result["detections_matched"] = len(matched)
        result["detections_dropped"] = len(detections) - len(matched)
        result["ips_scanned"] = len(scanned_ips)

        app.log.info("Matched %d/%d detections (%d IPs, %d dropped)",
                     len(matched), len(detections), len(scanned_ips),
                     len(detections) - len(matched))

        # Upload report with detections
        if matched:
            report_body = {
                "name": REPORT_NAME,
                "report_type": scanner_type.split("-")[0],
                "authoritative": AUTHORITATIVE,
                "scanned_ips": list(scanned_ips),
                "detected_vulnerabilities": matched,
            }
            status, resp = pce_client.put_report(REPORT_NAME, report_body)
            if status in (200, 201, 204):
                app.log.info("Report uploaded: %d detections", len(matched))
            else:
                result["error"] = f"Report upload failed: HTTP {status}"
                app.log.error("Report upload: HTTP %d — %s", status, resp)

        duration = time.time() - start
        result["duration"] = round(duration, 1)
        result["status"] = "success" if not result["error"] else "error"

    except Exception as e:
        result["error"] = str(e)
        result["status"] = "error"
        result["duration"] = round(time.time() - start, 1)
        app.log.exception("Import failed")

    return result


# ---------------------------------------------------------------------------
# Plugin lifecycle
# ---------------------------------------------------------------------------

@app.poll(interval_env="POLL_INTERVAL", default=3600)
def poll_import(pce):
    if not SCANNER_TYPE:
        app.log.info("No SCANNER_TYPE configured — waiting for file upload or manual trigger")
        return

    pce_client = VulnPCEClient(
        host=os.environ["PCE_HOST"],
        port=int(os.environ.get("PCE_PORT", "8443")),
        org_id=int(os.environ.get("PCE_ORG_ID", "1")),
        api_key=os.environ["PCE_API_KEY"],
        api_secret=os.environ["PCE_API_SECRET"],
        verify=os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() != "true",
    )

    import_file = IMPORT_FILE
    if SCANNER_TYPE in FILE_SCANNERS and not import_file:
        # Check for files in /data/imports/
        import_dir = "/data/imports"
        if os.path.isdir(import_dir):
            files = sorted(os.listdir(import_dir))
            if files:
                import_file = os.path.join(import_dir, files[-1])
                app.log.info("Found import file: %s", import_file)

    if SCANNER_TYPE in FILE_SCANNERS and not import_file:
        app.log.info("File scanner configured but no import file found in /data/imports/")
        return

    result = run_import(pce_client, SCANNER_TYPE, import_file)

    app.update_state({
        "last_import": result,
        "import_count": app.state.get("import_count", 0) + 1,
        "history": ([result] + app.state.get("history", []))[:20],
    })

    if result["status"] == "success" and result["detections_matched"] > 0:
        app.report(
            title=f"Vulnerability import: {result['detections_matched']} findings uploaded",
            body=f"**Scanner:** {result['scanner_type']}\n"
                 f"- Vulnerabilities defined: {result['vulns_defined']}\n"
                 f"- Detections matched: {result['detections_matched']}/{result['detections_total']}\n"
                 f"- IPs scanned: {result['ips_scanned']}\n"
                 f"- Duration: {result['duration']}s",
            severity="info",
            tags=["vulnerability", "vmaps", "import"],
            data=result,
        )


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.api("GET", "/api/state")
def get_state(request):
    return app.state


@app.api("POST", "/api/import")
def trigger_import(request):
    scanner_type = request.json.get("scanner_type", SCANNER_TYPE)
    import_file = request.json.get("import_file", IMPORT_FILE)

    if not scanner_type:
        return {"error": "scanner_type is required"}, 400

    pce_client = VulnPCEClient(
        host=os.environ["PCE_HOST"],
        port=int(os.environ.get("PCE_PORT", "8443")),
        org_id=int(os.environ.get("PCE_ORG_ID", "1")),
        api_key=os.environ["PCE_API_KEY"],
        api_secret=os.environ["PCE_API_SECRET"],
        verify=os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() != "true",
    )

    result = run_import(pce_client, scanner_type, import_file)

    app.update_state({
        "last_import": result,
        "import_count": app.state.get("import_count", 0) + 1,
        "history": ([result] + app.state.get("history", []))[:20],
    })

    return result


@app.api("POST", "/api/upload")
def upload_file(request):
    import_dir = "/data/imports"
    os.makedirs(import_dir, exist_ok=True)

    filename = request.query.get("filename", f"upload_{int(time.time())}")
    filepath = os.path.join(import_dir, filename)
    with open(filepath, "wb") as f:
        f.write(request.body)

    app.log.info("Uploaded file: %s (%d bytes)", filepath, len(request.body))
    return {"status": "uploaded", "path": filepath, "size": len(request.body)}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability Maps Handler</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#11111b}::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-6xl mx-auto px-6 py-8">

<div class="flex items-center justify-between mb-8">
  <div>
    <h1 class="text-2xl font-bold text-white">Vulnerability Maps Handler</h1>
    <p class="text-sm text-gray-500 mt-1">Import vulnerability scans into Illumio PCE vmaps</p>
  </div>
  <div class="flex items-center gap-3">
    <span id="status" class="text-sm text-gray-400"></span>
    <button onclick="triggerImport()" class="px-3 py-1.5 text-sm rounded bg-blue-700 hover:bg-blue-600 text-white transition-colors">Import Now</button>
  </div>
</div>

<!-- Stats -->
<div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-vulns" class="text-2xl font-bold text-blue-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Vulns Defined</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-detections" class="text-2xl font-bold text-purple-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Detections</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-matched" class="text-2xl font-bold text-green-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Matched</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-dropped" class="text-2xl font-bold text-red-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Dropped</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div id="stat-ips" class="text-2xl font-bold text-yellow-400">--</div>
    <div class="text-xs text-gray-500 mt-1">IPs Scanned</div>
  </div>
</div>

<!-- Last Import -->
<div class="bg-dark-800 rounded-xl border border-gray-700 p-6 mb-8">
  <h2 class="text-lg font-semibold text-white mb-3">Last Import</h2>
  <div id="last-import" class="text-sm text-gray-400">No imports yet</div>
</div>

<!-- Upload -->
<div class="bg-dark-800 rounded-xl border border-gray-700 p-6 mb-8">
  <h2 class="text-lg font-semibold text-white mb-3">Upload Scan File</h2>
  <div class="flex items-center gap-3">
    <select id="upload-type" class="bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-300">
      <option value="nessus-file">Nessus XML</option>
      <option value="qualys-file">Qualys XML</option>
      <option value="tenable-sc-csv">Tenable.sc CSV</option>
      <option value="tenable-io-csv">Tenable.io CSV</option>
    </select>
    <input type="file" id="scan-file" class="text-sm text-gray-400">
    <button onclick="uploadAndImport()" class="px-3 py-1.5 text-sm rounded bg-green-700 hover:bg-green-600 text-white transition-colors">Upload & Import</button>
  </div>
  <div id="upload-status" class="mt-2 text-xs text-gray-500"></div>
</div>

<!-- History -->
<div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
  <h2 class="text-lg font-semibold text-white mb-3">Import History</h2>
  <div id="history" class="space-y-2"></div>
</div>

<div id="footer" class="text-xs text-gray-600 text-center mt-6"></div>
</div>

<script>
const BASE = (() => { const m = window.location.pathname.match(/^(\/plugins\/[^/]+\/ui)/); return m ? m[1] : ''; })();

async function fetchData() {
  try {
    const d = await (await fetch(BASE+'/api/state')).json();
    renderAll(d);
  } catch(e) { console.error(e); }
}

function renderAll(data) {
  const last = data.last_import || {};
  document.getElementById('stat-vulns').textContent = last.vulns_defined || 0;
  document.getElementById('stat-detections').textContent = last.detections_total || 0;
  document.getElementById('stat-matched').textContent = last.detections_matched || 0;
  document.getElementById('stat-dropped').textContent = last.detections_dropped || 0;
  document.getElementById('stat-ips').textContent = last.ips_scanned || 0;

  if (last.timestamp) {
    const statusColor = last.status === 'success' ? 'text-green-400' : last.status === 'error' ? 'text-red-400' : 'text-yellow-400';
    document.getElementById('last-import').innerHTML = `
      <div class="grid grid-cols-2 gap-3">
        <div><span class="text-gray-500">Scanner:</span> <span class="text-white">${last.scanner_type || '—'}</span></div>
        <div><span class="text-gray-500">Status:</span> <span class="${statusColor} font-medium">${last.status}</span></div>
        <div><span class="text-gray-500">Time:</span> <span class="text-white">${new Date(last.timestamp).toLocaleString()}</span></div>
        <div><span class="text-gray-500">Duration:</span> <span class="text-white">${last.duration || 0}s</span></div>
        ${last.error ? `<div class="col-span-2"><span class="text-gray-500">Error:</span> <span class="text-red-400">${last.error}</span></div>` : ''}
      </div>
    `;
  }

  document.getElementById('status').textContent = 'Import #' + (data.import_count || 0);

  const history = data.history || [];
  document.getElementById('history').innerHTML = history.map(h => {
    const sc = h.status === 'success' ? 'bg-green-900/30 border-green-800/50' : 'bg-red-900/30 border-red-800/50';
    const tc = h.status === 'success' ? 'text-green-400' : 'text-red-400';
    return `<div class="px-3 py-2 rounded border ${sc} flex items-center justify-between text-xs">
      <span class="${tc} font-medium">${h.status}</span>
      <span class="text-gray-400">${h.scanner_type || '—'}</span>
      <span class="text-gray-500">${h.vulns_defined || 0} vulns, ${h.detections_matched || 0}/${h.detections_total || 0} matched</span>
      <span class="text-gray-500">${h.duration || 0}s</span>
      <span class="text-gray-600">${new Date(h.timestamp).toLocaleTimeString()}</span>
    </div>`;
  }).join('');

  document.getElementById('footer').textContent = `Import count: ${data.import_count || 0}`;
}

async function triggerImport() {
  try {
    document.getElementById('status').textContent = 'Importing...';
    const resp = await fetch(BASE+'/api/import', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({})
    });
    const result = await resp.json();
    if (result.error) alert('Import error: ' + result.error);
    else alert('Import complete: ' + result.detections_matched + ' detections matched');
    fetchData();
  } catch(e) { alert('Failed: ' + e); }
}

async function uploadAndImport() {
  const file = document.getElementById('scan-file').files[0];
  if (!file) { alert('Select a file first'); return; }
  const scannerType = document.getElementById('upload-type').value;
  const statusEl = document.getElementById('upload-status');

  statusEl.textContent = 'Uploading...';
  try {
    const uploadResp = await fetch(BASE+'/api/upload?filename=' + encodeURIComponent(file.name), {
      method: 'POST', body: await file.arrayBuffer()
    });
    const uploadResult = await uploadResp.json();
    if (uploadResult.error) { statusEl.textContent = 'Upload failed: ' + uploadResult.error; return; }

    statusEl.textContent = 'Importing...';
    const importResp = await fetch(BASE+'/api/import', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({scanner_type: scannerType, import_file: uploadResult.path})
    });
    const result = await importResp.json();
    if (result.error) statusEl.textContent = 'Error: ' + result.error;
    else statusEl.textContent = 'Done: ' + result.detections_matched + ' detections imported';
    fetchData();
  } catch(e) { statusEl.textContent = 'Failed: ' + e; }
}

fetchData();
setInterval(fetchData, 15000);
</script>
</body></html>"""


@app.dashboard
def render():
    return DASHBOARD_HTML


app.run()
