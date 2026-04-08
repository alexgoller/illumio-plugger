#!/usr/bin/env python3
"""
policy-diff — Snapshot draft vs active policy and report differences.

Compares PCE draft and active policy objects (rulesets, IP lists, services,
label groups) and shows what changed on a web dashboard.
"""

import json
import logging
import os
import signal
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

from illumio import PolicyComputeEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("policy_diff")

state_lock = threading.Lock()
diff_state = {
    "last_check": None,
    "check_count": 0,
    "error": None,
    "diffs": [],
    "summary": {"added": 0, "modified": 0, "deleted": 0, "unchanged": 0},
    "policy_objects": {},
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


POLICY_TYPES = [
    ("rule_sets", "Rulesets"),
    ("ip_lists", "IP Lists"),
    ("services", "Services"),
    ("label_groups", "Label Groups"),
]


def compare_policy(pce):
    """Compare draft vs active policy objects using the illumio SDK."""
    all_diffs = []
    summary = {"added": 0, "modified": 0, "deleted": 0, "unchanged": 0}
    objects = {}

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

            # Build lookup by name for comparison
            active_by_name = {}
            for obj in active:
                name = obj.get("name", obj.get("href", ""))
                active_by_name[name] = obj

            draft_by_name = {}
            for obj in draft:
                name = obj.get("name", obj.get("href", ""))
                draft_by_name[name] = obj

            # Find additions and modifications
            for name, d_obj in draft_by_name.items():
                if name not in active_by_name:
                    all_diffs.append({
                        "type": label,
                        "change": "added",
                        "name": name,
                        "detail": "New in draft, not yet provisioned",
                    })
                    summary["added"] += 1
                else:
                    a_obj = active_by_name[name]
                    d_updated = d_obj.get("updated_at", "")
                    a_updated = a_obj.get("updated_at", "")
                    if d_updated and a_updated and d_updated != a_updated:
                        all_diffs.append({
                            "type": label,
                            "change": "modified",
                            "name": name,
                            "detail": f"Draft updated: {d_updated}",
                        })
                        summary["modified"] += 1
                    else:
                        summary["unchanged"] += 1

            # Find deletions
            for name in active_by_name:
                if name not in draft_by_name:
                    all_diffs.append({
                        "type": label,
                        "change": "deleted",
                        "name": name,
                        "detail": "Removed from draft",
                    })
                    summary["deleted"] += 1

        except Exception as e:
            log.warning("Failed to compare %s: %s", label, e)
            all_diffs.append({
                "type": label,
                "change": "error",
                "name": label,
                "detail": str(e),
            })

    with state_lock:
        diff_state["last_check"] = datetime.now(timezone.utc).isoformat()
        diff_state["check_count"] += 1
        diff_state["diffs"] = all_diffs
        diff_state["summary"] = summary
        diff_state["policy_objects"] = objects
        diff_state["error"] = None

    total_changes = summary["added"] + summary["modified"] + summary["deleted"]
    log.info("Check #%d: %d changes (%d added, %d modified, %d deleted, %d unchanged)",
             diff_state["check_count"], total_changes,
             summary["added"], summary["modified"], summary["deleted"], summary["unchanged"])


def poller_loop(pce):
    interval = int(os.environ.get("POLL_INTERVAL", "300"))
    while True:
        try:
            compare_policy(pce)
        except Exception:
            log.exception("Policy comparison failed")
        time.sleep(interval)


class DiffHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/diff":
            with state_lock:
                self.send_json(200, dict(diff_state))
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
            s = dict(diff_state)

        sm = s["summary"]
        total = sm["added"] + sm["modified"] + sm["deleted"]
        status_color = "#22c55e" if total == 0 else "#eab308" if total < 5 else "#ef4444"
        status_text = "In Sync" if total == 0 else f"{total} Pending Change{'s' if total != 1 else ''}"

        obj_rows = ""
        for label, counts in s.get("policy_objects", {}).items():
            obj_rows += f'<tr><td style="padding:6px 8px;border-bottom:1px solid #313244;">{label}</td><td style="padding:6px 8px;border-bottom:1px solid #313244;text-align:center;">{counts["active"]}</td><td style="padding:6px 8px;border-bottom:1px solid #313244;text-align:center;">{counts["draft"]}</td></tr>'

        diff_rows = ""
        change_colors = {"added": "#22c55e", "modified": "#eab308", "deleted": "#ef4444", "error": "#9ca3af"}
        change_icons = {"added": "+", "modified": "~", "deleted": "-", "error": "!"}
        for d in s.get("diffs", []):
            c = d["change"]
            color = change_colors.get(c, "#9ca3af")
            icon = change_icons.get(c, "?")
            diff_rows += f'''<tr>
                <td style="padding:6px 8px;border-bottom:1px solid #313244;"><span style="color:{color};font-weight:700;font-size:16px;width:24px;display:inline-block;text-align:center;">{icon}</span></td>
                <td style="padding:6px 8px;border-bottom:1px solid #313244;">{d["type"]}</td>
                <td style="padding:6px 8px;border-bottom:1px solid #313244;"><code style="font-size:12px;background:#313244;padding:1px 5px;border-radius:3px;">{d["name"]}</code></td>
                <td style="padding:6px 8px;border-bottom:1px solid #313244;color:#9ca3af;font-size:12px;">{d["detail"]}</td>
            </tr>'''
        if not diff_rows:
            diff_rows = '<tr><td colspan="4" style="color:#6b7280;padding:16px;text-align:center;">No pending changes — draft and active policy are in sync.</td></tr>'

        html = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>Policy Diff</title>
<style>
* {{ margin:0;padding:0;box-sizing:border-box; }}
body {{ font-family:-apple-system,sans-serif;background:#11111b;color:#cdd6f4;padding:24px; }}
.container {{ max-width:960px;margin:0 auto; }}
h1 {{ font-size:22px;margin-bottom:20px; }}
h2 {{ font-size:16px;margin-bottom:12px;color:#a6adc8; }}
.grid {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px; }}
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
<h1>Policy Diff — Draft vs Active</h1>
<div class="grid">
    <div class="card" style="border-color:{status_color}33;"><div class="stat" style="color:{status_color};">{status_text}</div><div class="stat-label">Policy Status</div></div>
    <div class="card"><div class="stat" style="color:#22c55e;">{sm['added']}</div><div class="stat-label">Added</div></div>
    <div class="card"><div class="stat" style="color:#eab308;">{sm['modified']}</div><div class="stat-label">Modified</div></div>
    <div class="card"><div class="stat" style="color:#ef4444;">{sm['deleted']}</div><div class="stat-label">Deleted</div></div>
</div>
<div class="card" style="margin-bottom:24px;"><h2>Changes</h2><table><tr><th style="width:30px;"></th><th>Type</th><th>Name</th><th>Detail</th></tr>{diff_rows}</table></div>
<div class="card" style="margin-bottom:24px;"><h2>Policy Objects</h2><table><tr><th>Type</th><th style="text-align:center;">Active</th><th style="text-align:center;">Draft</th></tr>{obj_rows if obj_rows else '<tr><td colspan="3" style="color:#6b7280;padding:8px;">Loading...</td></tr>'}</table></div>
<p class="meta">Check #{s['check_count']} &middot; Last: {s['last_check'] or 'never'} &middot; Refreshes every 30s &middot; <a href="/api/diff" style="color:#93c5fd;">JSON API</a></p>
</div></body></html>"""

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, fmt, *args):
        pass


def main():
    log.info("Starting policy-diff...")
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce = get_pce()
    log.info("Connected to PCE: %s", pce.base_url)

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
