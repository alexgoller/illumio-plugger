#!/usr/bin/env python3
"""
pce-health-monitor — Shows PCE health status on a web page.

Polls the PCE node health API and serves a live dashboard on port 8080.
"""

import base64
import json
import logging
import os
import signal
import ssl
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("pce_health_monitor")

# Global health state updated by the poller thread
health_state = {
    "status": "unknown",
    "last_check": None,
    "last_error": None,
    "pce_host": "",
    "pce_port": "",
    "org_id": "",
    "response": None,
    "check_count": 0,
}
state_lock = threading.Lock()


def check_pce_health():
    """Poll the PCE health endpoint and update global state."""
    host = os.environ.get("PCE_HOST", "")
    port = os.environ.get("PCE_PORT", "8443")
    api_key = os.environ.get("PCE_API_KEY", "")
    api_secret = os.environ.get("PCE_API_SECRET", "")
    org_id = os.environ.get("PCE_ORG_ID", "1")
    skip_tls = os.environ.get("PCE_TLS_SKIP_VERIFY", "false").lower() in ("true", "1", "yes")

    with state_lock:
        health_state["pce_host"] = host
        health_state["pce_port"] = port
        health_state["org_id"] = org_id

    # Try multiple health endpoints
    endpoints = [
        f"https://{host}:{port}/api/v2/health",
        f"https://{host}:{port}/api/v2/node_available",
        f"https://{host}:{port}/api/v2/orgs/{org_id}/workloads?max_results=1",
    ]

    ctx = ssl.create_default_context()
    if skip_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    # Preemptive basic auth header
    credentials = base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()
    auth_header = f"Basic {credentials}"

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
    )

    result = {
        "endpoints": {},
        "reachable": False,
        "authenticated": False,
    }

    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={
                "Accept": "application/json",
                "Authorization": auth_header,
            })
            resp = opener.open(req, timeout=10)
            status_code = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = body[:500]

            result["endpoints"][url.split("/api/")[-1]] = {
                "status": status_code,
                "ok": 200 <= status_code < 300,
                "data": data,
            }
            result["reachable"] = True
            if status_code != 401:
                result["authenticated"] = True
        except urllib.error.HTTPError as e:
            result["endpoints"][url.split("/api/")[-1]] = {
                "status": e.code,
                "ok": False,
                "error": str(e.reason),
            }
            result["reachable"] = True
            if e.code != 401:
                result["authenticated"] = True
        except Exception as e:
            result["endpoints"][url.split("/api/")[-1]] = {
                "status": 0,
                "ok": False,
                "error": str(e),
            }

    now = datetime.now(timezone.utc).isoformat()
    overall = "healthy" if result["reachable"] and result["authenticated"] else (
        "degraded" if result["reachable"] else "unreachable"
    )

    with state_lock:
        health_state["status"] = overall
        health_state["last_check"] = now
        health_state["last_error"] = None if overall == "healthy" else "See endpoint details"
        health_state["response"] = result
        health_state["check_count"] += 1

    log.info("Health check #%d: %s (reachable=%s, auth=%s)",
             health_state["check_count"], overall, result["reachable"], result["authenticated"])


def poller_loop():
    """Background thread that polls PCE health periodically."""
    interval = int(os.environ.get("POLL_INTERVAL", "120"))
    while True:
        try:
            check_pce_health()
        except Exception:
            log.exception("Health check failed")
            with state_lock:
                health_state["status"] = "error"
                health_state["last_error"] = "Check failed — see logs"
        time.sleep(interval)


class HealthHandler(BaseHTTPRequestHandler):
    """HTTP handler serving the health dashboard and API."""

    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/health":
            with state_lock:
                data = dict(health_state)
            self.send_json(200, data)
        elif self.path == "/":
            self.send_dashboard()
        else:
            self.send_error(404)

    def send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_dashboard(self):
        with state_lock:
            s = dict(health_state)

        status = s["status"]
        color = {"healthy": "#22c55e", "degraded": "#eab308", "unreachable": "#ef4444", "unknown": "#6b7280", "error": "#ef4444"}.get(status, "#6b7280")
        bg = {"healthy": "#052e16", "degraded": "#422006", "unreachable": "#450a0a", "unknown": "#1f2937", "error": "#450a0a"}.get(status, "#1f2937")

        endpoints_html = ""
        if s["response"] and s["response"].get("endpoints"):
            for name, info in s["response"]["endpoints"].items():
                ok = info.get("ok", False)
                icon = "&#10003;" if ok else "&#10007;"
                ec = "#22c55e" if ok else "#ef4444"
                status_code = info.get("status", "?")
                detail = info.get("error", "")
                if not detail and isinstance(info.get("data"), dict):
                    detail = json.dumps(info["data"], indent=2, default=str)
                elif not detail and isinstance(info.get("data"), str):
                    detail = info["data"][:200]
                endpoints_html += f"""
                <div style="background:#1e1e2e;border-radius:8px;padding:16px;margin-bottom:8px;">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span style="color:{ec};font-size:18px;">{icon}</span>
                        <code style="color:#93c5fd;">/api/{name}</code>
                        <span style="color:#9ca3af;margin-left:auto;">HTTP {status_code}</span>
                    </div>
                    {f'<pre style="color:#6b7280;font-size:12px;margin-top:8px;white-space:pre-wrap;max-height:150px;overflow:auto;">{detail}</pre>' if detail else ''}
                </div>"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta http-equiv="refresh" content="15">
    <title>PCE Health Monitor</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#11111b; color:#cdd6f4; min-height:100vh; padding:32px; }}
        .container {{ max-width:720px; margin:0 auto; }}
        h1 {{ font-size:24px; font-weight:600; margin-bottom:24px; }}
        .card {{ background:#1e1e2e; border-radius:12px; padding:24px; margin-bottom:16px; border:1px solid #313244; }}
        .status-badge {{ display:inline-flex; align-items:center; gap:8px; padding:8px 16px; border-radius:999px; font-weight:600; font-size:14px; }}
        .dot {{ width:10px; height:10px; border-radius:50%; }}
        .meta {{ color:#9ca3af; font-size:13px; margin-top:12px; }}
        code {{ background:#313244; padding:2px 6px; border-radius:4px; font-size:13px; }}
        pre {{ background:#11111b; padding:12px; border-radius:6px; overflow:auto; font-size:12px; }}
        .pulse {{ animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0%,100% {{ opacity:1 }} 50% {{ opacity:.5 }} }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PCE Health Monitor</h1>

        <div class="card" style="background:{bg};border-color:{color}33;">
            <div style="display:flex;align-items:center;justify-content:space-between;">
                <div class="status-badge" style="background:{color}22;color:{color};">
                    <span class="dot {'pulse' if status == 'healthy' else ''}" style="background:{color};"></span>
                    {status.upper()}
                </div>
                <span class="meta">Check #{s['check_count']}</span>
            </div>
            <div class="meta" style="margin-top:16px;">
                <strong>PCE:</strong> {s['pce_host']}:{s['pce_port']} (org {s['org_id']})<br>
                <strong>Last check:</strong> {s['last_check'] or 'never'}<br>
                {f'<strong>Error:</strong> {s["last_error"]}<br>' if s['last_error'] else ''}
            </div>
        </div>

        <div class="card">
            <h2 style="font-size:16px;margin-bottom:16px;">Endpoint Status</h2>
            {endpoints_html if endpoints_html else '<p style="color:#6b7280;">No checks performed yet.</p>'}
        </div>

        <p class="meta" style="text-align:center;margin-top:24px;">
            Auto-refreshes every 15s &middot; <a href="/api/health" style="color:#93c5fd;">JSON API</a>
        </p>
    </div>
</body>
</html>"""

        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # suppress default HTTP logging


def main():
    log.info("Starting pce-health-monitor...")

    port = int(os.environ.get("HTTP_PORT", "8080"))

    # Start health poller in background
    poller = threading.Thread(target=poller_loop, daemon=True)
    poller.start()

    # Run initial check immediately
    check_pce_health()

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    log.info("Dashboard listening on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server.serve_forever()
    log.info("Stopped.")


if __name__ == "__main__":
    main()
