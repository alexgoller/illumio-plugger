#!/usr/bin/env python3
"""
pce-posture-report — Generate a PCE security posture report.

Cron plugin that queries workloads, labels, rulesets, enforcement modes,
and policy coverage, then writes an HTML + JSON report to /data.
"""

import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone

from illumio import PolicyComputeEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("pce_posture_report")


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


def collect_data(pce):
    """Collect all posture data from the PCE."""
    log.info("Collecting workloads...")
    wl_resp = pce.get("/workloads", params={"max_results": 10000})
    workloads = wl_resp.json() if wl_resp.status_code == 200 else []

    log.info("Collecting labels...")
    label_resp = pce.get("/labels")
    labels = label_resp.json() if label_resp.status_code == 200 else []

    log.info("Collecting rulesets (active)...")
    rs_resp = pce.get("/sec_policy/active/rule_sets")
    rulesets_active = rs_resp.json() if rs_resp.status_code == 200 else []

    log.info("Collecting rulesets (draft)...")
    rs_draft_resp = pce.get("/sec_policy/draft/rule_sets")
    rulesets_draft = rs_draft_resp.json() if rs_draft_resp.status_code == 200 else []

    log.info("Collecting IP lists...")
    ip_resp = pce.get("/sec_policy/active/ip_lists")
    ip_lists = ip_resp.json() if ip_resp.status_code == 200 else []

    log.info("Collecting services...")
    svc_resp = pce.get("/sec_policy/active/services")
    services = svc_resp.json() if svc_resp.status_code == 200 else []

    return {
        "workloads": workloads if isinstance(workloads, list) else [],
        "labels": labels if isinstance(labels, list) else [],
        "rulesets_active": rulesets_active if isinstance(rulesets_active, list) else [],
        "rulesets_draft": rulesets_draft if isinstance(rulesets_draft, list) else [],
        "ip_lists": ip_lists if isinstance(ip_lists, list) else [],
        "services": services if isinstance(services, list) else [],
    }


def analyze(data):
    """Analyze collected data and produce posture metrics."""
    workloads = data["workloads"]
    labels = data["labels"]

    # Workload counts
    total_workloads = len(workloads)
    enforcement_modes = Counter()
    managed_count = 0
    unmanaged_count = 0
    online_count = 0
    offline_count = 0
    os_counter = Counter()
    label_coverage = {"has_role": 0, "has_app": 0, "has_env": 0, "has_loc": 0, "fully_labeled": 0, "unlabeled": 0}

    for wl in workloads:
        # Enforcement mode
        mode = wl.get("enforcement_mode", "idle")
        enforcement_modes[mode] += 1

        # Managed vs unmanaged
        if wl.get("agent", {}) and wl["agent"].get("href"):
            managed_count += 1
        else:
            unmanaged_count += 1

        # Online/offline
        if wl.get("online", False):
            online_count += 1
        else:
            offline_count += 1

        # OS
        os_type = wl.get("os_type", "unknown") or "unknown"
        os_counter[os_type] += 1

        # Label coverage
        wl_labels = wl.get("labels", [])
        label_keys = set()
        if isinstance(wl_labels, list):
            for lbl in wl_labels:
                if isinstance(lbl, dict):
                    label_keys.add(lbl.get("key", ""))

        if "role" in label_keys:
            label_coverage["has_role"] += 1
        if "app" in label_keys:
            label_coverage["has_app"] += 1
        if "env" in label_keys:
            label_coverage["has_env"] += 1
        if "loc" in label_keys:
            label_coverage["has_loc"] += 1
        if {"role", "app", "env", "loc"}.issubset(label_keys):
            label_coverage["fully_labeled"] += 1
        if not label_keys:
            label_coverage["unlabeled"] += 1

    # Label summary
    label_keys_counter = Counter()
    for lbl in labels:
        if isinstance(lbl, dict):
            label_keys_counter[lbl.get("key", "unknown")] += 1

    # Policy summary
    rulesets_active = data["rulesets_active"]
    rulesets_draft = data["rulesets_draft"]
    total_rules_active = sum(len(rs.get("rules", [])) for rs in rulesets_active if isinstance(rs, dict))
    total_rules_draft = sum(len(rs.get("rules", [])) for rs in rulesets_draft if isinstance(rs, dict))
    pending_changes = len(rulesets_draft) - len(rulesets_active)

    # Security posture score (simple heuristic)
    score = 0
    if total_workloads > 0:
        # Up to 25 points for enforcement coverage
        enforced = enforcement_modes.get("full", 0) + enforcement_modes.get("selective", 0)
        score += min(25, int(25 * enforced / total_workloads))

        # Up to 25 points for label coverage
        score += min(25, int(25 * label_coverage["fully_labeled"] / total_workloads))

        # Up to 25 points for having active policy
        if total_rules_active > 0:
            score += min(25, 10 + min(15, total_rules_active))

        # Up to 25 points for managed workloads
        score += min(25, int(25 * managed_count / total_workloads))

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pce_host": os.environ.get("PCE_HOST", ""),
        "score": score,
        "workloads": {
            "total": total_workloads,
            "managed": managed_count,
            "unmanaged": unmanaged_count,
            "online": online_count,
            "offline": offline_count,
            "enforcement_modes": dict(enforcement_modes),
            "os_types": dict(os_counter.most_common(10)),
            "label_coverage": label_coverage,
        },
        "labels": {
            "total": len(labels),
            "by_key": dict(label_keys_counter),
        },
        "policy": {
            "rulesets_active": len(rulesets_active),
            "rulesets_draft": len(rulesets_draft),
            "rules_active": total_rules_active,
            "rules_draft": total_rules_draft,
            "pending_changes": pending_changes,
            "ip_lists": len(data["ip_lists"]),
            "services": len(data["services"]),
        },
    }


def generate_html(report):
    """Generate an HTML report."""
    w = report["workloads"]
    p = report["policy"]
    lbl = report["labels"]
    score = report["score"]

    score_color = "#22c55e" if score >= 75 else "#eab308" if score >= 50 else "#ef4444"

    def bar(label, value, total, color="#93c5fd"):
        pct = int(100 * value / total) if total > 0 else 0
        return f'''<div style="margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:2px;">
                <span>{label}</span><span style="color:#9ca3af;">{value:,} ({pct}%)</span>
            </div>
            <div style="background:#313244;border-radius:4px;height:8px;overflow:hidden;">
                <div style="background:{color};width:{pct}%;height:100%;border-radius:4px;"></div>
            </div>
        </div>'''

    enforcement_bars = ""
    mode_colors = {"full": "#22c55e", "selective": "#a3e635", "visibility_only": "#eab308", "idle": "#6b7280"}
    for mode, count in sorted(w["enforcement_modes"].items(), key=lambda x: -x[1]):
        enforcement_bars += bar(mode.replace("_", " ").title(), count, w["total"], mode_colors.get(mode, "#93c5fd"))

    os_bars = ""
    for os_type, count in sorted(w["os_types"].items(), key=lambda x: -x[1]):
        os_bars += bar(os_type, count, w["total"], "#c084fc")

    label_bars = ""
    label_bars += bar("Role", w["label_coverage"]["has_role"], w["total"], "#22c55e")
    label_bars += bar("App", w["label_coverage"]["has_app"], w["total"], "#3b82f6")
    label_bars += bar("Env", w["label_coverage"]["has_env"], w["total"], "#eab308")
    label_bars += bar("Loc", w["label_coverage"]["has_loc"], w["total"], "#a78bfa")
    label_bars += bar("Fully Labeled", w["label_coverage"]["fully_labeled"], w["total"], "#22c55e")
    label_bars += bar("Unlabeled", w["label_coverage"]["unlabeled"], w["total"], "#ef4444")

    html = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PCE Posture Report — {report['timestamp'][:10]}</title>
<style>
* {{ margin:0;padding:0;box-sizing:border-box; }}
body {{ font-family:-apple-system,sans-serif;background:#11111b;color:#cdd6f4;padding:24px; }}
.container {{ max-width:1000px;margin:0 auto; }}
h1 {{ font-size:24px;margin-bottom:4px; }}
h2 {{ font-size:16px;margin-bottom:12px;color:#a6adc8; }}
.subtitle {{ color:#6b7280;font-size:13px;margin-bottom:24px; }}
.grid {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:24px; }}
.card {{ background:#1e1e2e;border:1px solid #313244;border-radius:10px;padding:20px; }}
.stat {{ font-size:36px;font-weight:700; }}
.stat-sm {{ font-size:24px;font-weight:700; }}
.stat-label {{ font-size:12px;color:#9ca3af;margin-top:4px; }}
.section {{ background:#1e1e2e;border:1px solid #313244;border-radius:10px;padding:20px;margin-bottom:16px; }}
.score-ring {{ width:120px;height:120px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-direction:column;border:6px solid {score_color}; }}
.footer {{ text-align:center;color:#6b7280;font-size:11px;margin-top:24px; }}
</style>
</head><body>
<div class="container">

<h1>PCE Security Posture Report</h1>
<div class="subtitle">{report['pce_host']} &middot; Generated {report['timestamp'][:19].replace('T',' ')} UTC</div>

<!-- Score + Key Stats -->
<div style="display:flex;gap:24px;margin-bottom:24px;flex-wrap:wrap;">
    <div class="card" style="display:flex;align-items:center;gap:20px;flex:0 0 auto;">
        <div class="score-ring">
            <div style="font-size:32px;font-weight:800;color:{score_color};">{score}</div>
            <div style="font-size:10px;color:#9ca3af;">/ 100</div>
        </div>
        <div>
            <div style="font-size:14px;font-weight:600;color:{score_color};">
                {'Excellent' if score >= 75 else 'Moderate' if score >= 50 else 'Needs Improvement'}
            </div>
            <div style="font-size:11px;color:#6b7280;margin-top:2px;">Security Posture Score</div>
        </div>
    </div>
    <div style="flex:1;display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;">
        <div class="card"><div class="stat-sm" style="color:#93c5fd;">{w['total']:,}</div><div class="stat-label">Workloads</div></div>
        <div class="card"><div class="stat-sm" style="color:#22c55e;">{w['online']:,}</div><div class="stat-label">Online</div></div>
        <div class="card"><div class="stat-sm" style="color:#a78bfa;">{w['managed']:,}</div><div class="stat-label">Managed</div></div>
        <div class="card"><div class="stat-sm" style="color:#eab308;">{p['rules_active']:,}</div><div class="stat-label">Active Rules</div></div>
        <div class="card"><div class="stat-sm" style="color:#f97316;">{p['pending_changes']}</div><div class="stat-label">Pending Changes</div></div>
    </div>
</div>

<!-- Enforcement + Labels -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
    <div class="section">
        <h2>Enforcement Modes</h2>
        {enforcement_bars if enforcement_bars else '<p style="color:#6b7280;">No workloads</p>'}
    </div>
    <div class="section">
        <h2>Label Coverage</h2>
        {label_bars}
    </div>
</div>

<!-- OS + Policy -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
    <div class="section">
        <h2>Operating Systems</h2>
        {os_bars if os_bars else '<p style="color:#6b7280;">No OS data</p>'}
    </div>
    <div class="section">
        <h2>Policy Summary</h2>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
            <div class="card" style="padding:12px;"><div style="font-size:20px;font-weight:700;">{p['rulesets_active']}</div><div class="stat-label">Active Rulesets</div></div>
            <div class="card" style="padding:12px;"><div style="font-size:20px;font-weight:700;">{p['rulesets_draft']}</div><div class="stat-label">Draft Rulesets</div></div>
            <div class="card" style="padding:12px;"><div style="font-size:20px;font-weight:700;">{p['ip_lists']}</div><div class="stat-label">IP Lists</div></div>
            <div class="card" style="padding:12px;"><div style="font-size:20px;font-weight:700;">{p['services']}</div><div class="stat-label">Services</div></div>
        </div>
    </div>
</div>

<!-- Labels -->
<div class="section">
    <h2>Labels by Type ({lbl['total']} total)</h2>
    <div style="display:flex;gap:16px;flex-wrap:wrap;">
        {''.join(f'<div class="card" style="padding:12px;min-width:100px;"><div style="font-size:20px;font-weight:700;">{count}</div><div class="stat-label">{key}</div></div>' for key, count in sorted(lbl['by_key'].items(), key=lambda x: -x[1]))}
    </div>
</div>

<div class="footer">
    Generated by plugger pce-posture-report &middot; {report['timestamp']}
</div>

</div></body></html>"""
    return html


def main():
    log.info("Starting PCE posture report...")
    pce = get_pce()
    log.info("Connected to PCE: %s", pce.base_url)

    # Collect
    data = collect_data(pce)
    log.info("Collected: %d workloads, %d labels, %d rulesets, %d IP lists, %d services",
             len(data["workloads"]), len(data["labels"]),
             len(data["rulesets_active"]), len(data["ip_lists"]), len(data["services"]))

    # Analyze
    report = analyze(data)
    log.info("Posture score: %d/100", report["score"])

    # Write reports
    data_dir = os.environ.get("DATA_DIR", "/data")
    os.makedirs(data_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # JSON report
    json_path = os.path.join(data_dir, f"posture_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info("JSON report: %s", json_path)

    # HTML report
    html_path = os.path.join(data_dir, f"posture_{timestamp}.html")
    with open(html_path, "w") as f:
        f.write(generate_html(report))
    log.info("HTML report: %s", html_path)

    # Also write "latest" symlinks
    latest_json = os.path.join(data_dir, "posture_latest.json")
    latest_html = os.path.join(data_dir, "posture_latest.html")
    for target, link in [(json_path, latest_json), (html_path, latest_html)]:
        try:
            os.remove(link)
        except FileNotFoundError:
            pass
        os.symlink(os.path.basename(target), link)

    log.info("Report complete. Score: %d/100", report["score"])


if __name__ == "__main__":
    main()
