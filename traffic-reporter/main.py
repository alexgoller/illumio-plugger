#!/usr/bin/env python3
"""
traffic-reporter — Poll PCE traffic flows and serve a summary dashboard.

Shows top talkers, blocked connections, unknown services, and flow
statistics on a web UI with auto-refresh.
"""

import json
import logging
import os
import signal
import threading
import time
from collections import Counter
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

from illumio import PolicyComputeEngine
from illumio.explorer import TrafficQuery

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("traffic_reporter")

state_lock = threading.Lock()
traffic_state = {
    "last_poll": None,
    "poll_count": 0,
    "total_flows": 0,
    "top_sources": [],
    "top_destinations": [],
    "top_services": [],
    "blocked_flows": [],
    "policy_decisions": {},
    "error": None,
}


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


def poll_traffic(pce):
    """Poll traffic analysis from PCE and update state."""
    lookback_hours = int(os.environ.get("LOOKBACK_HOURS", "24"))

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback_hours)

    log.info("Querying traffic flows (last %dh)...", lookback_hours)

    try:
        traffic_query = TrafficQuery.build(
            start_date=start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_date=end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            policy_decisions=["allowed", "blocked", "potentially_blocked", "unknown"],
            max_results=int(os.environ.get("MAX_RESULTS", "10000")),
        )

        raw_flows = pce.get_traffic_flows_async(
            query_name="plugger-traffic-reporter",
            traffic_query=traffic_query,
        )

        # Convert TrafficFlow objects to dicts for processing
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

        src_counter = Counter()
        dst_counter = Counter()
        svc_counter = Counter()
        decisions = Counter()
        blocked = []

        for flow in flows:
            src = flow.get("src", {})
            dst = flow.get("dst", {})
            service = flow.get("service", {})

            src_name = ""
            if isinstance(src, dict):
                src_name = (src.get("workload", {}) or {}).get("hostname", "") or src.get("ip", "unknown")
            dst_name = ""
            if isinstance(dst, dict):
                dst_name = (dst.get("workload", {}) or {}).get("hostname", "") or dst.get("ip", "unknown")

            port = service.get("port", "?") if isinstance(service, dict) else "?"
            proto = service.get("proto", "?") if isinstance(service, dict) else "?"
            svc_name = f"{port}/{proto}"

            num_connections = flow.get("num_connections", 1)

            src_counter[src_name] += num_connections
            dst_counter[dst_name] += num_connections
            svc_counter[svc_name] += num_connections

            decision = flow.get("policy_decision", "unknown")
            decisions[decision] += num_connections

            if decision in ("blocked", "potentially_blocked"):
                blocked.append({
                    "src": src_name,
                    "dst": dst_name,
                    "service": svc_name,
                    "decision": decision,
                    "connections": num_connections,
                })

        with state_lock:
            traffic_state["last_poll"] = datetime.now(timezone.utc).isoformat()
            traffic_state["poll_count"] += 1
            traffic_state["total_flows"] = len(flows)
            traffic_state["top_sources"] = src_counter.most_common(20)
            traffic_state["top_destinations"] = dst_counter.most_common(20)
            traffic_state["top_services"] = svc_counter.most_common(20)
            traffic_state["blocked_flows"] = sorted(blocked, key=lambda x: x["connections"], reverse=True)[:50]
            traffic_state["policy_decisions"] = dict(decisions)
            traffic_state["error"] = None

        log.info("Poll #%d: %d flows, %d blocked",
                 traffic_state["poll_count"], len(flows), len(blocked))

    except Exception as e:
        log.exception("Traffic poll failed")
        with state_lock:
            traffic_state["error"] = str(e)


def poller_loop(pce):
    interval = int(os.environ.get("POLL_INTERVAL", "300"))
    while True:
        poll_traffic(pce)
        time.sleep(interval)


class TrafficHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/traffic":
            with state_lock:
                self.send_json(200, dict(traffic_state))
        elif self.path == "/":
            self.send_dashboard()
        else:
            self.send_error(404)

    def send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def send_dashboard(self):
        with state_lock:
            s = dict(traffic_state)

        decisions = s.get("policy_decisions", {})
        allowed = decisions.get("allowed", 0)
        blocked = decisions.get("blocked", 0) + decisions.get("potentially_blocked", 0)
        unknown = decisions.get("unknown", 0)

        def table_rows(items):
            if not items:
                return '<tr><td colspan="2" style="color:#6b7280;padding:8px;">No data yet</td></tr>'
            rows = ""
            for name, count in items[:15]:
                rows += f'<tr><td style="padding:6px 8px;border-bottom:1px solid #313244;"><code style="font-size:12px;">{name}</code></td><td style="padding:6px 8px;border-bottom:1px solid #313244;text-align:right;">{count:,}</td></tr>'
            return rows

        blocked_rows = ""
        for b in s.get("blocked_flows", [])[:20]:
            blocked_rows += f'''<tr>
                <td style="padding:6px 8px;border-bottom:1px solid #313244;"><code style="font-size:11px;">{b["src"]}</code></td>
                <td style="padding:6px 8px;border-bottom:1px solid #313244;"><code style="font-size:11px;">{b["dst"]}</code></td>
                <td style="padding:6px 8px;border-bottom:1px solid #313244;">{b["service"]}</td>
                <td style="padding:6px 8px;border-bottom:1px solid #313244;text-align:right;">{b["connections"]:,}</td>
            </tr>'''
        if not blocked_rows:
            blocked_rows = '<tr><td colspan="4" style="color:#6b7280;padding:8px;">No blocked flows</td></tr>'

        error_html = f'<span style="color:#ef4444;">Error: {s["error"]}</span>' if s.get("error") else ""

        html = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>Traffic Reporter</title>
<style>
* {{ margin:0;padding:0;box-sizing:border-box; }}
body {{ font-family:-apple-system,sans-serif;background:#11111b;color:#cdd6f4;padding:24px; }}
.container {{ max-width:1200px;margin:0 auto; }}
h1 {{ font-size:22px;margin-bottom:20px; }}
h2 {{ font-size:16px;margin-bottom:12px;color:#a6adc8; }}
.grid {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin-bottom:24px; }}
.card {{ background:#1e1e2e;border:1px solid #313244;border-radius:10px;padding:20px; }}
.stat {{ font-size:32px;font-weight:700; }}
.stat-label {{ font-size:13px;color:#9ca3af;margin-top:4px; }}
table {{ width:100%;border-collapse:collapse; }}
th {{ text-align:left;padding:8px;border-bottom:2px solid #313244;color:#9ca3af;font-size:12px;font-weight:500; }}
code {{ background:#313244;padding:1px 5px;border-radius:3px;font-size:12px; }}
.meta {{ color:#6b7280;font-size:12px;text-align:center;margin-top:24px; }}
</style>
</head><body>
<div class="container">
<h1>Traffic Reporter</h1>
<div class="grid">
    <div class="card"><div class="stat" style="color:#93c5fd;">{s['total_flows']:,}</div><div class="stat-label">Total Flows (last {os.environ.get('LOOKBACK_HOURS','24')}h)</div></div>
    <div class="card"><div class="stat" style="color:#22c55e;">{allowed:,}</div><div class="stat-label">Allowed</div></div>
    <div class="card"><div class="stat" style="color:#ef4444;">{blocked:,}</div><div class="stat-label">Blocked</div></div>
    <div class="card"><div class="stat" style="color:#eab308;">{unknown:,}</div><div class="stat-label">Unknown</div></div>
</div>
{f'<div class="card" style="border-color:#ef444444;margin-bottom:24px;"><h2 style="color:#ef4444;">Blocked Flows</h2><table><tr><th>Source</th><th>Destination</th><th>Service</th><th style="text-align:right;">Connections</th></tr>{blocked_rows}</table></div>' if blocked > 0 else ''}
<div class="grid">
    <div class="card"><h2>Top Sources</h2><table><tr><th>Host</th><th style="text-align:right;">Connections</th></tr>{table_rows(s['top_sources'])}</table></div>
    <div class="card"><h2>Top Destinations</h2><table><tr><th>Host</th><th style="text-align:right;">Connections</th></tr>{table_rows(s['top_destinations'])}</table></div>
    <div class="card"><h2>Top Services</h2><table><tr><th>Port/Proto</th><th style="text-align:right;">Connections</th></tr>{table_rows(s['top_services'])}</table></div>
</div>
<p class="meta">Poll #{s['poll_count']} &middot; Last: {s['last_poll'] or 'never'} &middot; Refreshes every 30s &middot; <a href="/api/traffic" style="color:#93c5fd;">JSON API</a> {error_html}</p>
</div></body></html>"""

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, fmt, *args):
        pass


def main():
    log.info("Starting traffic-reporter...")
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce = get_pce()
    log.info("Connected to PCE: %s", pce.base_url)

    poller = threading.Thread(target=poller_loop, args=(pce,), daemon=True)
    poller.start()
    poll_traffic(pce)

    server = HTTPServer(("0.0.0.0", port), TrafficHandler)
    log.info("Dashboard on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
