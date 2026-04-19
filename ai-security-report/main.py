#!/usr/bin/env python3
"""
AI Security Report — Comprehensive security posture analysis for Illumio PCE.

Collects workloads, traffic, policy, and process data. Runs 10 security analysis
categories, scores each 0-100, generates optional AI narratives, and presents
an interactive dashboard with charts, heatmaps, and PDF export.
"""

import json
import logging
import os
import re
import signal
import sys
import threading
import time
import glob as globmod
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from illumio import PolicyComputeEngine
from illumio.explorer import TrafficQuery

from ai_advisor import AIAdvisor

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("ai-security-report")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
report_state = {
    "last_scan": None,
    "scan_count": 0,
    "scanning": False,
    "error": None,
    "latest_report": None,
    "scan_requested": False,
}

label_cache = {}  # href -> {key, value}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCAN_INTERVAL = max(3600, int(os.environ.get("SCAN_INTERVAL", "86400")))
LOOKBACK_DAYS = int(os.environ.get("LOOKBACK_DAYS", "7"))
MAX_TRAFFIC_RESULTS = int(os.environ.get("MAX_TRAFFIC_RESULTS", "100000"))
PROCESS_SAMPLE_SIZE = int(os.environ.get("PROCESS_SAMPLE_SIZE", "50"))
REPORT_RETENTION = int(os.environ.get("REPORT_RETENTION", "30"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

# ---------------------------------------------------------------------------
# Category weights (must sum to 100)
# ---------------------------------------------------------------------------
CATEGORY_WEIGHTS = {
    "enforcement_coverage": 15,
    "os_lifecycle": 8,
    "label_hygiene": 12,
    "env_separation": 15,
    "risky_services": 10,
    "policy_analysis": 12,
    "traffic_anomalies": 8,
    "lateral_movement": 10,
    "agent_health": 5,
    "compliance": 5,
}

CATEGORY_TITLES = {
    "enforcement_coverage": "Enforcement Coverage",
    "os_lifecycle": "OS Lifecycle Risk",
    "label_hygiene": "Label Hygiene",
    "env_separation": "Environmental Separation",
    "risky_services": "Risky Services & Protocols",
    "policy_analysis": "Policy Analysis",
    "traffic_anomalies": "Traffic Anomalies",
    "lateral_movement": "Lateral Movement Surface",
    "agent_health": "Agent Health",
    "compliance": "Compliance Mapping",
}

CATEGORY_ICONS = {
    "enforcement_coverage": "shield",
    "os_lifecycle": "server",
    "label_hygiene": "tag",
    "env_separation": "layers",
    "risky_services": "alert-triangle",
    "policy_analysis": "file-text",
    "traffic_anomalies": "activity",
    "lateral_movement": "git-branch",
    "agent_health": "heart",
    "compliance": "check-square",
}

# ---------------------------------------------------------------------------
# OS EOL Database
# ---------------------------------------------------------------------------
OS_EOL_DATABASE = [
    (r"windows.*2008", "2020-01-14", "critical", "Windows Server 2008/2008 R2"),
    (r"windows.*2012", "2023-10-10", "critical", "Windows Server 2012/2012 R2"),
    (r"windows.*2016", "2027-01-12", "medium", "Windows Server 2016"),
    (r"windows.*2019", "2029-01-09", "info", "Windows Server 2019"),
    (r"windows.*2022", "2031-10-14", "info", "Windows Server 2022"),
    (r"centos[- ]*6", "2020-11-30", "critical", "CentOS 6"),
    (r"centos[- ]*7", "2024-06-30", "critical", "CentOS 7"),
    (r"centos[- ]*8(?!.*stream)", "2021-12-31", "critical", "CentOS 8"),
    (r"(rhel|red\s*hat).*6", "2020-11-30", "critical", "RHEL 6"),
    (r"(rhel|red\s*hat).*7", "2024-06-30", "critical", "RHEL 7"),
    (r"(rhel|red\s*hat).*8", "2029-05-31", "info", "RHEL 8"),
    (r"ubuntu.*14\.04", "2019-04-30", "critical", "Ubuntu 14.04 LTS"),
    (r"ubuntu.*16\.04", "2021-04-30", "critical", "Ubuntu 16.04 LTS"),
    (r"ubuntu.*18\.04", "2023-04-30", "critical", "Ubuntu 18.04 LTS"),
    (r"ubuntu.*20\.04", "2025-04-30", "high", "Ubuntu 20.04 LTS"),
    (r"ubuntu.*22\.04", "2027-04-30", "info", "Ubuntu 22.04 LTS"),
    (r"debian.*8", "2020-06-30", "critical", "Debian 8 (Jessie)"),
    (r"debian.*9", "2022-06-30", "critical", "Debian 9 (Stretch)"),
    (r"debian.*10", "2024-06-30", "high", "Debian 10 (Buster)"),
    (r"debian.*11", "2026-08-31", "info", "Debian 11 (Bullseye)"),
    (r"sles.*11", "2022-03-31", "critical", "SUSE Linux Enterprise 11"),
    (r"sles.*12", "2027-10-31", "medium", "SUSE Linux Enterprise 12"),
    (r"amazon.*201[0-9]", "2023-12-31", "critical", "Amazon Linux 1"),
    (r"amazon.*2(?!023)", "2025-06-30", "high", "Amazon Linux 2"),
    (r"oracle.*6", "2021-03-30", "critical", "Oracle Linux 6"),
    (r"oracle.*7", "2024-12-31", "high", "Oracle Linux 7"),
]

# ---------------------------------------------------------------------------
# Risky Services Database
# ---------------------------------------------------------------------------
RISKY_SERVICES = {
    21: ("FTP", "critical", "Unencrypted file transfer — use SFTP/SCP instead"),
    23: ("Telnet", "critical", "Unencrypted remote access — use SSH instead"),
    20: ("FTP Data", "high", "FTP data channel — use SFTP/SCP instead"),
    513: ("rlogin", "critical", "Insecure remote login — use SSH instead"),
    514: ("rsh", "critical", "Insecure remote shell — use SSH instead"),
    69: ("TFTP", "high", "Trivial File Transfer — no authentication"),
    161: ("SNMP v1/v2", "medium", "Unencrypted SNMP — upgrade to SNMPv3"),
    445: ("SMB", "high", "SMB/CIFS — ransomware propagation vector"),
    135: ("RPC", "high", "MS-RPC — common exploit target"),
    139: ("NetBIOS", "high", "NetBIOS session — legacy Windows networking"),
    3389: ("RDP", "medium", "Remote Desktop — review for sprawl/lateral movement"),
    5900: ("VNC", "high", "VNC remote access — often unencrypted"),
    80: ("HTTP", "low", "Unencrypted web — consider HTTPS (443)"),
    2049: ("NFS", "medium", "Network File System — verify access controls"),
    1433: ("MSSQL", "medium", "Database port — restrict to app tier only"),
    3306: ("MySQL", "medium", "Database port — restrict to app tier only"),
    5432: ("PostgreSQL", "medium", "Database port — restrict to app tier only"),
    1521: ("Oracle DB", "medium", "Database port — restrict to app tier only"),
    27017: ("MongoDB", "medium", "Database port — restrict to app tier only"),
    6379: ("Redis", "medium", "In-memory store — often no authentication"),
    11211: ("Memcached", "medium", "Cache — often no authentication"),
}

# ---------------------------------------------------------------------------
# Compliance Mapping (finding prefix -> [(framework, control_id, control_name)])
# ---------------------------------------------------------------------------
COMPLIANCE_MAP = {
    "ec": [
        ("NIST CSF", "PR.AC-5", "Network integrity is protected"),
        ("NIST CSF", "PR.PT-4", "Communications and control networks are protected"),
        ("CIS Controls", "CIS.13", "Network Monitoring and Defense"),
        ("PCI-DSS", "PCI.1.2", "Restrict connections between untrusted networks"),
    ],
    "os": [
        ("NIST CSF", "ID.AM-2", "Software platforms are inventoried"),
        ("NIST CSF", "PR.IP-12", "Vulnerability management plan is implemented"),
        ("CIS Controls", "CIS.2", "Inventory and Control of Software Assets"),
        ("CIS Controls", "CIS.7", "Continuous Vulnerability Management"),
        ("PCI-DSS", "PCI.6.2", "Protect from known vulnerabilities"),
    ],
    "lh": [
        ("NIST CSF", "ID.AM-1", "Physical devices and systems are inventoried"),
        ("NIST CSF", "ID.AM-5", "Resources prioritized by classification"),
        ("CIS Controls", "CIS.1", "Inventory and Control of Enterprise Assets"),
    ],
    "es": [
        ("NIST CSF", "PR.AC-5", "Network integrity is protected"),
        ("NIST CSF", "DE.CM-1", "Network is monitored for cybersecurity events"),
        ("CIS Controls", "CIS.12", "Network Infrastructure Management"),
        ("PCI-DSS", "PCI.1.3", "Prohibit direct public access to cardholder data"),
        ("PCI-DSS", "PCI.6.4.1", "Separate dev/test from production"),
    ],
    "rs": [
        ("NIST CSF", "PR.AC-3", "Remote access is managed"),
        ("NIST CSF", "PR.DS-2", "Data in transit is protected"),
        ("CIS Controls", "CIS.4", "Secure Configuration"),
        ("PCI-DSS", "PCI.2.2.2", "Enable only necessary services"),
        ("PCI-DSS", "PCI.4.1", "Use strong cryptography for data in transit"),
    ],
    "pa": [
        ("NIST CSF", "PR.AC-4", "Access permissions managed with least privilege"),
        ("NIST CSF", "PR.IP-1", "Configuration baselines maintained"),
        ("CIS Controls", "CIS.3", "Data Protection"),
        ("PCI-DSS", "PCI.7.1", "Limit access to system components"),
    ],
    "ta": [
        ("NIST CSF", "DE.AE-1", "Baseline of network operations established"),
        ("NIST CSF", "DE.CM-1", "Network monitored for cybersecurity events"),
        ("CIS Controls", "CIS.13", "Network Monitoring and Defense"),
    ],
    "lm": [
        ("NIST CSF", "PR.AC-5", "Network integrity is protected"),
        ("NIST CSF", "DE.CM-7", "Monitoring for unauthorized activity"),
        ("CIS Controls", "CIS.13", "Network Monitoring and Defense"),
        ("PCI-DSS", "PCI.11.4", "Use intrusion detection/prevention"),
    ],
    "ah": [
        ("NIST CSF", "PR.MA-1", "Maintenance performed and logged"),
        ("NIST CSF", "DE.CM-8", "Vulnerability scans are performed"),
        ("CIS Controls", "CIS.1", "Inventory and Control of Enterprise Assets"),
    ],
}

# ---------------------------------------------------------------------------
# PCE helpers
# ---------------------------------------------------------------------------

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
    verify = os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() != "true"
    pce.set_tls_settings(verify=verify)
    return pce


def fetch_labels(pce):
    global label_cache
    try:
        resp = pce.get("/labels")
        labels = resp.json() if resp.status_code == 200 else []
        cache = {}
        for lbl in labels:
            href = lbl.get("href", "")
            cache[href] = {"key": lbl.get("key", ""), "value": lbl.get("value", "")}
        label_cache = cache
        return labels
    except Exception as e:
        log.error("Failed to fetch labels: %s", e)
        return []


def resolve_label(href):
    return label_cache.get(href, {})


def endpoint_labels(ep):
    """Extract label dict {key: value} from a traffic flow endpoint."""
    labels = {}
    wl = ep.get("workload", {}) if isinstance(ep, dict) else {}
    for lbl in wl.get("labels", []):
        href = lbl.get("href", "")
        resolved = resolve_label(href)
        if resolved:
            labels[resolved["key"]] = resolved["value"]
    return labels


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def collect_workloads(pce):
    try:
        resp = pce.get("/workloads", params={"max_results": 10000})
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        log.error("Failed to fetch workloads: %s", e)
    return []


def collect_traffic(pce):
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=LOOKBACK_DAYS)
        traffic_query = TrafficQuery.build(
            start_date=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_date=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            policy_decisions=["allowed", "blocked", "potentially_blocked"],
            max_results=MAX_TRAFFIC_RESULTS,
        )
        raw_flows = pce.get_traffic_flows_async(
            query_name="plugger-ai-security-report",
            traffic_query=traffic_query,
        )
        flows = []
        for f in raw_flows:
            if hasattr(f, "to_json"):
                flow = f.to_json()
                if isinstance(flow, str):
                    flow = json.loads(flow)
            elif hasattr(f, "__dict__"):
                flow = f.__dict__
            elif isinstance(f, dict):
                flow = f
            else:
                continue
            flows.append(flow)
        return flows
    except Exception as e:
        log.error("Failed to fetch traffic: %s", e)
        return []


def collect_policy(pce):
    rulesets = []
    services = []
    ip_lists = []
    try:
        resp = pce.get("/sec_policy/active/rule_sets", params={"max_results": 5000})
        if resp.status_code == 200:
            rulesets = resp.json()
    except Exception as e:
        log.error("Failed to fetch rulesets: %s", e)
    try:
        resp = pce.get("/sec_policy/active/services")
        if resp.status_code == 200:
            services = resp.json()
    except Exception as e:
        log.error("Failed to fetch services: %s", e)
    try:
        resp = pce.get("/sec_policy/active/ip_lists")
        if resp.status_code == 200:
            ip_lists = resp.json()
    except Exception as e:
        log.error("Failed to fetch IP lists: %s", e)
    return {"rulesets": rulesets, "services": services, "ip_lists": ip_lists}


def collect_processes(pce, workloads):
    """Sample process data from a subset of workloads."""
    process_data = {}
    sampled = workloads[:PROCESS_SAMPLE_SIZE]
    for wl in sampled:
        href = wl.get("href", "")
        hostname = wl.get("hostname", "(unknown)")
        try:
            resp = pce.get(f"{href}/processes")
            if resp.status_code == 200:
                process_data[hostname] = resp.json()
        except Exception:
            pass
    return process_data


def collect_all_data(pce):
    log.info("Collecting PCE data...")
    labels = fetch_labels(pce)
    workloads = collect_workloads(pce)
    log.info("Collected %d workloads, %d labels", len(workloads), len(labels))
    traffic = collect_traffic(pce)
    log.info("Collected %d traffic flows", len(traffic))
    policy = collect_policy(pce)
    log.info("Collected %d rulesets", len(policy["rulesets"]))
    processes = collect_processes(pce, workloads)
    log.info("Sampled processes from %d workloads", len(processes))
    return {
        "workloads": workloads,
        "traffic": traffic,
        "policy": policy,
        "labels": labels,
        "processes": processes,
    }


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def calculate_category_score(findings):
    score = 100
    for f in findings:
        sev = f.get("severity", "info")
        if sev == "critical":
            score -= 15
        elif sev == "high":
            score -= 8
        elif sev == "medium":
            score -= 4
        elif sev == "low":
            score -= 2
    return max(0, min(100, score))


def score_to_grade(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def calculate_overall_score(category_scores):
    total = 0
    for cat_id, weight in CATEGORY_WEIGHTS.items():
        total += category_scores.get(cat_id, 50) * weight
    return round(total / 100)


# ---------------------------------------------------------------------------
# Analysis Section 1: Enforcement Coverage
# ---------------------------------------------------------------------------

def analyze_enforcement_coverage(workloads):
    findings = []
    modes = Counter()
    managed_count = 0
    unmanaged_count = 0

    for wl in workloads:
        mode = wl.get("enforcement_mode", "idle")
        modes[mode] += 1
        if wl.get("managed", True):
            managed_count += 1
        else:
            unmanaged_count += 1

    total = len(workloads) or 1

    # Finding: idle workloads
    idle = modes.get("idle", 0)
    if idle > 0:
        pct = idle / total * 100
        severity = "critical" if pct > 50 else "high" if pct > 20 else "medium"
        findings.append({
            "id": "ec-001",
            "title": f"{idle} workloads in idle mode ({pct:.0f}%)",
            "description": f"{idle} of {total} workloads ({pct:.1f}%) are in idle enforcement mode, providing zero segmentation protection. These workloads have no visibility or enforcement.",
            "severity": severity,
            "affected_count": idle,
            "affected_items": [wl.get("hostname", "") for wl in workloads if wl.get("enforcement_mode") == "idle"][:20],
            "remediation": "Move idle workloads to visibility_only mode as a first step toward enforcement.",
        })

    # Finding: visibility_only workloads
    vis = modes.get("visibility_only", 0)
    if vis > 0:
        pct = vis / total * 100
        severity = "medium" if pct > 50 else "low"
        findings.append({
            "id": "ec-002",
            "title": f"{vis} workloads in visibility-only mode ({pct:.0f}%)",
            "description": f"{vis} workloads are in visibility_only mode — traffic is monitored but not enforced. Policy violations will be logged but not blocked.",
            "severity": severity,
            "affected_count": vis,
            "affected_items": [wl.get("hostname", "") for wl in workloads if wl.get("enforcement_mode") == "visibility_only"][:20],
            "remediation": "After validating traffic patterns, progress to selective or full enforcement.",
        })

    # Finding: full enforcement percentage
    full = modes.get("full", 0)
    if total > 0 and full / total < 0.5:
        findings.append({
            "id": "ec-003",
            "title": f"Only {full / total * 100:.0f}% of workloads in full enforcement",
            "description": f"Only {full} of {total} workloads have full enforcement enabled. The remaining workloads are not fully protected by micro-segmentation policy.",
            "severity": "high" if full / total < 0.2 else "medium",
            "affected_count": total - full,
            "affected_items": [],
            "remediation": "Develop an enforcement progression plan: idle → visibility → selective → full.",
        })

    # Finding: unmanaged workloads
    if unmanaged_count > 0:
        findings.append({
            "id": "ec-004",
            "title": f"{unmanaged_count} unmanaged workloads",
            "description": f"{unmanaged_count} workloads are unmanaged (no VEN agent). These workloads cannot be enforced by Illumio.",
            "severity": "medium" if unmanaged_count > 10 else "low",
            "affected_count": unmanaged_count,
            "affected_items": [wl.get("hostname", "") for wl in workloads if not wl.get("managed", True)][:20],
            "remediation": "Install VEN agents on unmanaged workloads or create unmanaged workload entries with static policies.",
        })

    chart_data = {
        "enforcement_distribution": dict(modes),
        "managed_vs_unmanaged": {"managed": managed_count, "unmanaged": unmanaged_count},
    }

    return findings, chart_data


# ---------------------------------------------------------------------------
# Analysis Section 2: OS Lifecycle Risk
# ---------------------------------------------------------------------------

def analyze_os_lifecycle(workloads):
    findings = []
    eol_counts = Counter()
    eol_severity = {}
    affected_hosts = defaultdict(list)
    os_distribution = Counter()
    now = datetime.now()

    for wl in workloads:
        os_id = (wl.get("os_id") or "").lower()
        os_detail = (wl.get("os_detail") or "").lower()
        os_string = f"{os_id} {os_detail}"
        hostname = wl.get("hostname", "(unknown)")

        # Track OS distribution
        os_name = wl.get("os_id") or wl.get("os_detail") or "Unknown"
        os_distribution[os_name] += 1

        for pattern, eol_date_str, severity, display_name in OS_EOL_DATABASE:
            if re.search(pattern, os_string, re.IGNORECASE):
                eol_date = datetime.strptime(eol_date_str, "%Y-%m-%d")
                days_remaining = (eol_date - now).days
                if days_remaining < 0:
                    # Past EOL
                    eol_counts[display_name] += 1
                    eol_severity[display_name] = severity
                    affected_hosts[display_name].append(hostname)
                elif days_remaining < 365:
                    # Approaching EOL
                    label = f"{display_name} (EOL in {days_remaining}d)"
                    eol_counts[label] += 1
                    eol_severity[label] = "medium"
                    affected_hosts[label].append(hostname)
                break

    idx = 1
    for os_name, count in eol_counts.most_common():
        approaching = "EOL in" in os_name
        severity = eol_severity.get(os_name, "medium")
        findings.append({
            "id": f"os-{idx:03d}",
            "title": f"{'Approaching ' if approaching else ''}End-of-life: {os_name} ({count} workloads)",
            "description": f"{count} workloads running {os_name}. {'This OS is approaching' if approaching else 'This OS has reached'} end of life and no longer receives security patches.",
            "severity": severity,
            "affected_count": count,
            "affected_items": affected_hosts[os_name][:20],
            "remediation": f"Plan migration from {os_name.split(' (')[0]} to a currently supported version.",
        })
        idx += 1

    if not eol_counts and len(workloads) > 0:
        findings.append({
            "id": "os-000",
            "title": "No end-of-life operating systems detected",
            "description": f"All {len(workloads)} workloads are running supported OS versions.",
            "severity": "info",
            "affected_count": 0,
            "affected_items": [],
            "remediation": "Continue monitoring for upcoming EOL dates.",
        })

    chart_data = {
        "os_distribution": dict(os_distribution.most_common(15)),
        "eol_breakdown": {k: v for k, v in eol_counts.most_common(10)},
    }

    return findings, chart_data


# ---------------------------------------------------------------------------
# Analysis Section 3: Label Hygiene
# ---------------------------------------------------------------------------

def analyze_label_hygiene(workloads):
    findings = []
    required_keys = ["app", "env", "role", "loc"]
    coverage = {k: 0 for k in required_keys}
    fully_labeled = 0
    unlabeled = []
    partially_labeled = []

    for wl in workloads:
        labels = {}
        for lbl in wl.get("labels", []):
            href = lbl.get("href", "")
            resolved = resolve_label(href)
            if resolved:
                labels[resolved["key"]] = resolved["value"]

        missing = [k for k in required_keys if k not in labels]
        for k in required_keys:
            if k in labels:
                coverage[k] += 1

        if not missing:
            fully_labeled += 1
        elif len(missing) == len(required_keys):
            unlabeled.append(wl.get("hostname", "(unknown)"))
        else:
            partially_labeled.append({
                "hostname": wl.get("hostname", "(unknown)"),
                "missing": missing,
            })

    total = len(workloads) or 1

    # Finding: fully unlabeled workloads
    if unlabeled:
        pct = len(unlabeled) / total * 100
        findings.append({
            "id": "lh-001",
            "title": f"{len(unlabeled)} workloads have no labels ({pct:.0f}%)",
            "description": f"{len(unlabeled)} workloads have zero labels assigned. Without labels, these workloads cannot be included in any segmentation policy.",
            "severity": "critical" if len(unlabeled) > 20 else "high",
            "affected_count": len(unlabeled),
            "affected_items": unlabeled[:20],
            "remediation": "Assign at minimum app and env labels to all workloads. Use hostname patterns or AD integration for bulk labeling.",
        })

    # Finding: partially labeled
    if partially_labeled:
        pct = len(partially_labeled) / total * 100
        missing_summary = Counter()
        for p in partially_labeled:
            for m in p["missing"]:
                missing_summary[m] += 1
        findings.append({
            "id": "lh-002",
            "title": f"{len(partially_labeled)} workloads partially labeled ({pct:.0f}%)",
            "description": f"{len(partially_labeled)} workloads are missing some labels. Most commonly missing: {', '.join(f'{k} ({v})' for k, v in missing_summary.most_common(4))}.",
            "severity": "medium",
            "affected_count": len(partially_labeled),
            "affected_items": [p["hostname"] for p in partially_labeled[:20]],
            "remediation": "Complete label assignment for partially labeled workloads. Focus on role labels for micro-segmentation.",
        })

    # Finding: low full-label coverage
    fully_pct = fully_labeled / total * 100
    if fully_pct < 80:
        findings.append({
            "id": "lh-003",
            "title": f"Only {fully_pct:.0f}% of workloads are fully labeled",
            "description": f"Only {fully_labeled} of {total} workloads have all four required labels (app, env, role, loc). Full labeling is required for effective micro-segmentation.",
            "severity": "high" if fully_pct < 50 else "medium",
            "affected_count": total - fully_labeled,
            "affected_items": [],
            "remediation": "Prioritize full label coverage. Consider automated labeling via hostname patterns, CMDB integration, or AD sync.",
        })

    # Per-key coverage info
    for key in required_keys:
        pct = coverage[key] / total * 100
        if pct < 70:
            findings.append({
                "id": f"lh-{key[:3]}",
                "title": f"Low {key} label coverage: {pct:.0f}%",
                "description": f"Only {coverage[key]} of {total} workloads ({pct:.1f}%) have a {key} label assigned.",
                "severity": "medium" if pct < 50 else "low",
                "affected_count": total - coverage[key],
                "affected_items": [],
                "remediation": f"Assign {key} labels to remaining workloads.",
            })

    chart_data = {
        "label_coverage": {k: round(v / total * 100, 1) for k, v in coverage.items()},
        "fully_labeled_pct": round(fully_pct, 1),
        "label_status": {
            "fully_labeled": fully_labeled,
            "partially_labeled": len(partially_labeled),
            "unlabeled": len(unlabeled),
        },
    }

    return findings, chart_data


# ---------------------------------------------------------------------------
# Analysis Section 4: Environmental Separation
# ---------------------------------------------------------------------------

PROD_ENVS = {"production", "prod", "prd"}
NON_PROD_ENVS = {"development", "dev", "test", "tst", "staging", "stg", "qa", "uat", "sandbox", "sbx"}


def analyze_env_separation(traffic):
    findings = []
    env_matrix = defaultdict(lambda: {"allowed": 0, "blocked": 0, "total": 0, "services": Counter()})

    for flow in traffic:
        src = flow.get("src", {})
        dst = flow.get("dst", {})
        decision = flow.get("policy_decision", "unknown")
        num = flow.get("num_connections", 1)

        src_labels = endpoint_labels(src)
        dst_labels = endpoint_labels(dst)

        src_env = src_labels.get("env", "")
        dst_env = dst_labels.get("env", "")

        if not src_env or not dst_env:
            continue

        key = (src_env, dst_env)
        env_matrix[key]["total"] += num
        if decision == "allowed":
            env_matrix[key]["allowed"] += num
        elif decision in ("blocked", "potentially_blocked"):
            env_matrix[key]["blocked"] += num

        service = flow.get("service", {})
        if isinstance(service, dict):
            port = service.get("port", "?")
            proto_num = service.get("proto", "?")
            proto = {6: "tcp", 17: "udp"}.get(proto_num, str(proto_num))
            env_matrix[key]["services"][f"{port}/{proto}"] += num

    all_envs = sorted(set([k[0] for k in env_matrix] + [k[1] for k in env_matrix]))
    max_total = max((v["total"] for v in env_matrix.values()), default=1)

    heatmap = {
        "environments": all_envs,
        "cells": [],
    }

    for src_env in all_envs:
        for dst_env in all_envs:
            key = (src_env, dst_env)
            data = env_matrix.get(key, {"allowed": 0, "blocked": 0, "total": 0})
            intensity = data["total"] / max_total if max_total > 0 else 0
            heatmap["cells"].append({
                "src_env": src_env,
                "dst_env": dst_env,
                "total": data["total"],
                "allowed": data["allowed"],
                "blocked": data["blocked"],
                "intensity": round(intensity, 3),
                "is_cross_env": src_env != dst_env,
            })

    idx = 1
    for (src_env, dst_env), data in sorted(env_matrix.items(), key=lambda x: -x[1]["allowed"]):
        if src_env == dst_env:
            continue

        src_is_prod = src_env.lower() in PROD_ENVS
        dst_is_prod = dst_env.lower() in PROD_ENVS
        src_is_nonprod = src_env.lower() in NON_PROD_ENVS
        dst_is_nonprod = dst_env.lower() in NON_PROD_ENVS

        top_svcs = ", ".join(s for s, _ in data["services"].most_common(3))

        if (src_is_prod and dst_is_nonprod) or (src_is_nonprod and dst_is_prod):
            if data["allowed"] > 0:
                severity = "critical" if data["allowed"] > 100 else "high"
                findings.append({
                    "id": f"es-{idx:03d}",
                    "title": f"Production ↔ {dst_env if src_is_prod else src_env}: {data['allowed']:,} allowed flows",
                    "description": f"{data['allowed']:,} allowed connections between {src_env} and {dst_env}. Top services: {top_svcs}. Production environments should not communicate with non-production.",
                    "severity": severity,
                    "affected_count": data["allowed"],
                    "affected_items": [],
                    "remediation": f"Review and restrict traffic between {src_env} and {dst_env}. Implement environment isolation rules.",
                })
                idx += 1
        elif data["allowed"] > 500:
            findings.append({
                "id": f"es-{idx:03d}",
                "title": f"Cross-environment: {src_env} → {dst_env} ({data['allowed']:,} flows)",
                "description": f"{data['allowed']:,} allowed connections from {src_env} to {dst_env}. Top services: {top_svcs}.",
                "severity": "medium" if data["allowed"] > 5000 else "low",
                "affected_count": data["allowed"],
                "affected_items": [],
                "remediation": f"Review cross-environment rules between {src_env} and {dst_env}.",
            })
            idx += 1

    if not findings and all_envs:
        findings.append({
            "id": "es-000",
            "title": "No environmental boundary violations detected",
            "description": "No significant cross-environment traffic violations found.",
            "severity": "info",
            "affected_count": 0,
            "affected_items": [],
            "remediation": "Continue monitoring environment separation.",
        })

    chart_data = {"heatmap": heatmap}
    return findings, chart_data


# ---------------------------------------------------------------------------
# Analysis Section 5: Risky Services
# ---------------------------------------------------------------------------

def analyze_risky_services(traffic):
    findings = []
    risky_found = Counter()  # port -> connection count
    risky_details = defaultdict(lambda: {"src_envs": set(), "dst_envs": set(), "connections": 0})

    for flow in traffic:
        decision = flow.get("policy_decision", "")
        if decision not in ("allowed",):
            continue
        service = flow.get("service", {})
        if not isinstance(service, dict):
            continue
        port = service.get("port")
        if port and port in RISKY_SERVICES:
            num = flow.get("num_connections", 1)
            risky_found[port] += num

            src_labels = endpoint_labels(flow.get("src", {}))
            dst_labels = endpoint_labels(flow.get("dst", {}))
            risky_details[port]["connections"] += num
            if src_labels.get("env"):
                risky_details[port]["src_envs"].add(src_labels["env"])
            if dst_labels.get("env"):
                risky_details[port]["dst_envs"].add(dst_labels["env"])

    idx = 1
    for port, count in risky_found.most_common():
        svc_name, severity, desc = RISKY_SERVICES[port]
        detail = risky_details[port]
        envs = detail["src_envs"] | detail["dst_envs"]
        env_str = ", ".join(sorted(envs)[:5]) or "unknown"

        findings.append({
            "id": f"rs-{idx:03d}",
            "title": f"{svc_name} ({port}/tcp): {count:,} allowed connections",
            "description": f"{count:,} allowed connections using {svc_name} (port {port}). {desc}. Environments affected: {env_str}.",
            "severity": severity,
            "affected_count": count,
            "affected_items": [],
            "remediation": f"Review all {svc_name} usage. {desc}.",
        })
        idx += 1

    if not findings:
        findings.append({
            "id": "rs-000",
            "title": "No risky services detected in allowed traffic",
            "description": "No insecure or risky protocols found in allowed traffic flows.",
            "severity": "info",
            "affected_count": 0,
            "affected_items": [],
            "remediation": "Continue monitoring for risky service usage.",
        })

    chart_data = {
        "risky_services": [
            {"name": RISKY_SERVICES[p][0], "port": p, "connections": c}
            for p, c in risky_found.most_common(15)
        ],
    }
    return findings, chart_data


# ---------------------------------------------------------------------------
# Analysis Section 6: Policy Analysis
# ---------------------------------------------------------------------------

def analyze_policy(policy_data):
    findings = []
    rulesets = policy_data.get("rulesets", [])
    total_rules = 0
    disabled_rules = 0
    empty_rulesets = 0
    any_any_rules = 0
    broad_port_rules = 0

    for rs in rulesets:
        rules = rs.get("rules", [])
        if not rules:
            empty_rulesets += 1
            continue

        rs_name = rs.get("name", "(unnamed)")
        for rule in rules:
            total_rules += 1

            if not rule.get("enabled", True):
                disabled_rules += 1
                continue

            # Check for any-to-any
            providers = rule.get("providers", [])
            consumers = rule.get("consumers", [])
            services = rule.get("ingress_services", [])

            has_all_providers = any(p.get("actors") == "ams" for p in providers)
            has_all_consumers = any(c.get("actors") == "ams" for c in consumers)

            if has_all_providers and has_all_consumers:
                any_any_rules += 1

            # Check for broad port ranges
            for svc in services:
                if isinstance(svc, dict):
                    to_port = svc.get("to_port", 0)
                    port = svc.get("port", 0)
                    if to_port and port and (to_port - port) > 100:
                        broad_port_rules += 1
                        break

    # Finding: any-to-any rules
    if any_any_rules > 0:
        findings.append({
            "id": "pa-001",
            "title": f"{any_any_rules} any-to-any rules found",
            "description": f"{any_any_rules} rules allow all workloads to communicate with all workloads. This defeats the purpose of micro-segmentation.",
            "severity": "critical",
            "affected_count": any_any_rules,
            "affected_items": [],
            "remediation": "Replace any-to-any rules with scoped rules using app, env, and role labels.",
        })

    # Finding: broad port ranges
    if broad_port_rules > 0:
        findings.append({
            "id": "pa-002",
            "title": f"{broad_port_rules} rules with broad port ranges",
            "description": f"{broad_port_rules} rules specify port ranges exceeding 100 ports. Overly broad port ranges increase attack surface.",
            "severity": "high",
            "affected_count": broad_port_rules,
            "affected_items": [],
            "remediation": "Narrow port ranges to specific services needed. Use service definitions for clarity.",
        })

    # Finding: disabled rules
    if disabled_rules > 0:
        pct = disabled_rules / max(total_rules, 1) * 100
        findings.append({
            "id": "pa-003",
            "title": f"{disabled_rules} disabled rules ({pct:.0f}% of total)",
            "description": f"{disabled_rules} rules are disabled. These may be stale or left over from troubleshooting.",
            "severity": "low",
            "affected_count": disabled_rules,
            "affected_items": [],
            "remediation": "Review disabled rules. Delete if no longer needed or re-enable if required.",
        })

    # Finding: empty rulesets
    if empty_rulesets > 0:
        findings.append({
            "id": "pa-004",
            "title": f"{empty_rulesets} empty rulesets",
            "description": f"{empty_rulesets} rulesets have no rules defined. These add clutter without providing any policy.",
            "severity": "low",
            "affected_count": empty_rulesets,
            "affected_items": [],
            "remediation": "Clean up empty rulesets or populate them with appropriate rules.",
        })

    if not findings:
        findings.append({
            "id": "pa-000",
            "title": "Policy structure looks healthy",
            "description": f"{total_rules} rules across {len(rulesets)} rulesets. No overly permissive rules detected.",
            "severity": "info",
            "affected_count": 0,
            "affected_items": [],
            "remediation": "Continue monitoring policy quality.",
        })

    chart_data = {
        "policy_stats": {
            "total_rulesets": len(rulesets),
            "total_rules": total_rules,
            "disabled_rules": disabled_rules,
            "empty_rulesets": empty_rulesets,
            "any_any_rules": any_any_rules,
            "broad_port_rules": broad_port_rules,
        },
    }
    return findings, chart_data


# ---------------------------------------------------------------------------
# Analysis Section 7: Traffic Anomalies
# ---------------------------------------------------------------------------

def analyze_traffic_anomalies(traffic, workloads):
    findings = []
    blocked_by_pair = Counter()
    ip_only_flows = 0
    total_blocked = 0
    total_allowed = 0
    total_pot_blocked = 0

    workload_hrefs = {wl.get("href", "") for wl in workloads}

    for flow in traffic:
        decision = flow.get("policy_decision", "")
        num = flow.get("num_connections", 1)

        if decision == "allowed":
            total_allowed += num
        elif decision == "blocked":
            total_blocked += num
        elif decision == "potentially_blocked":
            total_pot_blocked += num

        if decision in ("blocked", "potentially_blocked"):
            src = flow.get("src", {})
            dst = flow.get("dst", {})
            src_name = src.get("workload", {}).get("hostname") or src.get("ip", "unknown")
            dst_name = dst.get("workload", {}).get("hostname") or dst.get("ip", "unknown")
            blocked_by_pair[(src_name, dst_name)] += num

        # IP-only flow detection (no workload associated)
        src = flow.get("src", {})
        dst = flow.get("dst", {})
        if not src.get("workload") and not dst.get("workload"):
            ip_only_flows += num

    # Finding: high blocked traffic
    if total_blocked > 1000:
        findings.append({
            "id": "ta-001",
            "title": f"{total_blocked:,} blocked connections in last {LOOKBACK_DAYS} days",
            "description": f"A total of {total_blocked:,} connections were blocked by policy. This may indicate misconfigured policy or legitimate traffic that needs rules.",
            "severity": "medium" if total_blocked < 10000 else "high",
            "affected_count": total_blocked,
            "affected_items": [f"{src} → {dst}: {c:,}" for (src, dst), c in blocked_by_pair.most_common(10)],
            "remediation": "Review top blocked traffic pairs. Create rules for legitimate traffic or investigate unauthorized communication.",
        })

    # Finding: potentially blocked
    if total_pot_blocked > 100:
        findings.append({
            "id": "ta-002",
            "title": f"{total_pot_blocked:,} potentially blocked connections",
            "description": f"{total_pot_blocked:,} connections were potentially blocked (would be blocked under full enforcement). These need rules before progressing enforcement.",
            "severity": "medium",
            "affected_count": total_pot_blocked,
            "affected_items": [],
            "remediation": "Create rules for legitimate potentially_blocked traffic before moving to full enforcement.",
        })

    # Finding: IP-only traffic
    if ip_only_flows > 500:
        findings.append({
            "id": "ta-003",
            "title": f"{ip_only_flows:,} flows from/to unmanaged IPs",
            "description": f"{ip_only_flows:,} traffic flows involve IP addresses not associated with any managed workload. This traffic cannot be controlled by workload-based policy.",
            "severity": "medium" if ip_only_flows > 5000 else "low",
            "affected_count": ip_only_flows,
            "affected_items": [],
            "remediation": "Create IP lists for known external sources. Investigate unknown IP traffic.",
        })

    # Finding: top blocked pairs
    top_pairs = blocked_by_pair.most_common(5)
    if top_pairs and top_pairs[0][1] > 500:
        findings.append({
            "id": "ta-004",
            "title": f"Top blocked pair: {top_pairs[0][0][0]} → {top_pairs[0][0][1]} ({top_pairs[0][1]:,} connections)",
            "description": f"The most blocked traffic pair has {top_pairs[0][1]:,} blocked connections. High-volume blocked traffic often indicates missing rules for legitimate application traffic.",
            "severity": "medium",
            "affected_count": top_pairs[0][1],
            "affected_items": [f"{s} → {d}: {c:,}" for (s, d), c in top_pairs],
            "remediation": "Investigate this traffic pair. If legitimate, create a scoped rule.",
        })

    if not findings:
        findings.append({
            "id": "ta-000",
            "title": "Traffic patterns appear normal",
            "description": "No significant traffic anomalies detected.",
            "severity": "info",
            "affected_count": 0,
            "affected_items": [],
            "remediation": "Continue monitoring traffic patterns.",
        })

    chart_data = {
        "traffic_summary": {
            "allowed": total_allowed,
            "blocked": total_blocked,
            "potentially_blocked": total_pot_blocked,
        },
        "top_blocked_pairs": [
            {"src": s, "dst": d, "connections": c}
            for (s, d), c in blocked_by_pair.most_common(10)
        ],
    }
    return findings, chart_data


# ---------------------------------------------------------------------------
# Analysis Section 8: Lateral Movement Surface
# ---------------------------------------------------------------------------

def analyze_lateral_movement(traffic):
    findings = []
    ssh_targets = Counter()  # dst hostname -> connection count
    rdp_targets = Counter()
    workload_connections = Counter()  # hostname -> unique peers

    peer_map = defaultdict(set)

    for flow in traffic:
        if flow.get("policy_decision") != "allowed":
            continue

        src = flow.get("src", {})
        dst = flow.get("dst", {})
        service = flow.get("service", {})
        num = flow.get("num_connections", 1)

        src_name = src.get("workload", {}).get("hostname", src.get("ip", ""))
        dst_name = dst.get("workload", {}).get("hostname", dst.get("ip", ""))

        if src_name and dst_name:
            peer_map[src_name].add(dst_name)
            peer_map[dst_name].add(src_name)

        port = service.get("port") if isinstance(service, dict) else None
        if port == 22:
            ssh_targets[dst_name] += num
        elif port == 3389:
            rdp_targets[dst_name] += num

    # SSH sprawl
    ssh_sources_count = len(ssh_targets)
    if ssh_sources_count > 10:
        findings.append({
            "id": "lm-001",
            "title": f"SSH accessible on {ssh_sources_count} workloads",
            "description": f"{ssh_sources_count} workloads accept SSH connections. Broad SSH access increases lateral movement risk.",
            "severity": "high" if ssh_sources_count > 50 else "medium",
            "affected_count": ssh_sources_count,
            "affected_items": [f"{h}: {c:,} connections" for h, c in ssh_targets.most_common(15)],
            "remediation": "Restrict SSH to jump hosts/bastion servers only. Implement SSH key-based authentication.",
        })

    # RDP sprawl
    rdp_count = len(rdp_targets)
    if rdp_count > 5:
        findings.append({
            "id": "lm-002",
            "title": f"RDP accessible on {rdp_count} workloads",
            "description": f"{rdp_count} workloads accept RDP connections. RDP is a frequent target for brute-force and lateral movement attacks.",
            "severity": "high" if rdp_count > 20 else "medium",
            "affected_count": rdp_count,
            "affected_items": [f"{h}: {c:,} connections" for h, c in rdp_targets.most_common(15)],
            "remediation": "Limit RDP access to jump hosts. Consider using a VPN or PAM solution instead.",
        })

    # Hub workloads (talking to many peers)
    hub_threshold = 20
    hubs = [(h, len(peers)) for h, peers in peer_map.items() if len(peers) >= hub_threshold]
    hubs.sort(key=lambda x: -x[1])

    if hubs:
        findings.append({
            "id": "lm-003",
            "title": f"{len(hubs)} workloads communicate with {hub_threshold}+ peers",
            "description": f"{len(hubs)} workloads communicate with {hub_threshold} or more unique peers. High connectivity workloads are prime lateral movement targets if compromised.",
            "severity": "medium",
            "affected_count": len(hubs),
            "affected_items": [f"{h}: {c} peers" for h, c in hubs[:15]],
            "remediation": "Review hub workloads. Ensure they are infrastructure services (monitoring, DNS, etc.) and not standard app servers with excessive connectivity.",
        })

    if not findings:
        findings.append({
            "id": "lm-000",
            "title": "Lateral movement surface is limited",
            "description": "No significant SSH/RDP sprawl or hub workloads detected.",
            "severity": "info",
            "affected_count": 0,
            "affected_items": [],
            "remediation": "Continue monitoring east-west traffic patterns.",
        })

    chart_data = {
        "ssh_targets": len(ssh_targets),
        "rdp_targets": len(rdp_targets),
        "hub_workloads": len(hubs) if hubs else 0,
        "avg_peers": round(sum(len(p) for p in peer_map.values()) / max(len(peer_map), 1), 1),
    }
    return findings, chart_data


# ---------------------------------------------------------------------------
# Analysis Section 9: Agent Health
# ---------------------------------------------------------------------------

def analyze_agent_health(workloads):
    findings = []
    offline = []
    stale_heartbeat = []
    agent_versions = Counter()
    online_count = 0
    now = datetime.now(timezone.utc)

    for wl in workloads:
        hostname = wl.get("hostname", "(unknown)")
        is_online = wl.get("online", False)

        if is_online:
            online_count += 1
        else:
            offline.append(hostname)

        agent = wl.get("agent", {})
        status = agent.get("status", {})
        last_hb = status.get("last_heartbeat_on", "")
        agent_ver = agent.get("active_pce_fqdn", status.get("agent_version", "unknown"))

        if isinstance(agent, dict) and agent.get("config"):
            ver = agent["config"].get("agent_version", "")
            if ver:
                agent_versions[ver] += 1

        if last_hb:
            try:
                hb_time = datetime.fromisoformat(last_hb.replace("Z", "+00:00"))
                age_hours = (now - hb_time).total_seconds() / 3600
                if age_hours > 24:
                    stale_heartbeat.append({"hostname": hostname, "hours_ago": round(age_hours)})
            except (ValueError, TypeError):
                pass

    total = len(workloads) or 1

    if offline:
        pct = len(offline) / total * 100
        findings.append({
            "id": "ah-001",
            "title": f"{len(offline)} workloads offline ({pct:.0f}%)",
            "description": f"{len(offline)} workloads are currently offline. Offline workloads cannot receive policy updates or report traffic.",
            "severity": "high" if pct > 20 else "medium" if pct > 5 else "low",
            "affected_count": len(offline),
            "affected_items": offline[:20],
            "remediation": "Investigate offline workloads. Check VEN agent status, network connectivity, and server health.",
        })

    if stale_heartbeat:
        findings.append({
            "id": "ah-002",
            "title": f"{len(stale_heartbeat)} workloads with stale heartbeats (>24h)",
            "description": f"{len(stale_heartbeat)} workloads haven't sent a heartbeat in over 24 hours. These agents may be malfunctioning.",
            "severity": "medium",
            "affected_count": len(stale_heartbeat),
            "affected_items": [f"{s['hostname']}: {s['hours_ago']}h ago" for s in sorted(stale_heartbeat, key=lambda x: -x["hours_ago"])[:15]],
            "remediation": "Check VEN agent status on these workloads. Restart agents if needed.",
        })

    if len(agent_versions) > 3:
        findings.append({
            "id": "ah-003",
            "title": f"{len(agent_versions)} different agent versions in use",
            "description": f"There are {len(agent_versions)} different VEN agent versions running. Version sprawl complicates management and may indicate missed updates.",
            "severity": "low",
            "affected_count": len(agent_versions),
            "affected_items": [f"v{v}: {c} workloads" for v, c in agent_versions.most_common(10)],
            "remediation": "Standardize on a single VEN agent version. Plan rolling upgrades.",
        })

    if not findings:
        findings.append({
            "id": "ah-000",
            "title": "Agent health is good",
            "description": f"All {online_count} agents are online and reporting.",
            "severity": "info",
            "affected_count": 0,
            "affected_items": [],
            "remediation": "Continue monitoring agent health.",
        })

    chart_data = {
        "online_offline": {"online": online_count, "offline": len(offline)},
        "stale_count": len(stale_heartbeat),
        "agent_versions": dict(agent_versions.most_common(10)),
    }
    return findings, chart_data


# ---------------------------------------------------------------------------
# Analysis Section 10: Compliance Mapping
# ---------------------------------------------------------------------------

def analyze_compliance(all_findings_by_category):
    """Map all findings to compliance frameworks using COMPLIANCE_MAP."""
    frameworks = defaultdict(lambda: defaultdict(lambda: {
        "control_id": "", "control_name": "", "status": "met",
        "related_findings": [], "gap_description": "",
    }))

    finding_prefix_map = {
        "enforcement_coverage": "ec",
        "os_lifecycle": "os",
        "label_hygiene": "lh",
        "env_separation": "es",
        "risky_services": "rs",
        "policy_analysis": "pa",
        "traffic_anomalies": "ta",
        "lateral_movement": "lm",
        "agent_health": "ah",
    }

    for cat_id, findings in all_findings_by_category.items():
        prefix = finding_prefix_map.get(cat_id, "")
        if not prefix or prefix not in COMPLIANCE_MAP:
            continue

        has_critical = any(f["severity"] == "critical" for f in findings if f["severity"] != "info")
        has_high = any(f["severity"] == "high" for f in findings if f["severity"] != "info")
        has_findings = any(f["severity"] not in ("info",) for f in findings)

        for framework, ctrl_id, ctrl_name in COMPLIANCE_MAP[prefix]:
            ctrl = frameworks[framework][ctrl_id]
            ctrl["control_id"] = ctrl_id
            ctrl["control_name"] = ctrl_name

            for f in findings:
                if f["severity"] != "info":
                    ctrl["related_findings"].append(f["id"])

            if has_critical:
                ctrl["status"] = "not_met"
                ctrl["gap_description"] = f"Critical findings in {CATEGORY_TITLES.get(cat_id, cat_id)}"
            elif has_high:
                if ctrl["status"] != "not_met":
                    ctrl["status"] = "partial"
                    ctrl["gap_description"] = f"High-severity findings in {CATEGORY_TITLES.get(cat_id, cat_id)}"
            elif has_findings:
                if ctrl["status"] == "met":
                    ctrl["status"] = "partial"
                    ctrl["gap_description"] = f"Minor findings in {CATEGORY_TITLES.get(cat_id, cat_id)}"

    # Build compliance findings
    findings = []
    compliance_result = {}

    for framework, controls in frameworks.items():
        met = sum(1 for c in controls.values() if c["status"] == "met")
        partial = sum(1 for c in controls.values() if c["status"] == "partial")
        not_met = sum(1 for c in controls.values() if c["status"] == "not_met")
        total = len(controls)

        compliance_result[framework] = {
            "controls": list(controls.values()),
            "summary": {"met": met, "partial": partial, "not_met": not_met, "total": total},
        }

        if not_met > 0:
            findings.append({
                "id": f"co-{framework[:3].lower()}",
                "title": f"{framework}: {not_met} controls not met",
                "description": f"{not_met} of {total} {framework} controls are not met due to critical findings. {partial} controls are partially met.",
                "severity": "high" if not_met > 3 else "medium",
                "affected_count": not_met,
                "affected_items": [f"{c['control_id']}: {c['control_name']}" for c in controls.values() if c["status"] == "not_met"],
                "remediation": f"Address critical findings to improve {framework} compliance posture.",
            })

    if not findings:
        findings.append({
            "id": "co-000",
            "title": "Compliance posture is satisfactory",
            "description": "All mapped compliance controls are met or partially met.",
            "severity": "info",
            "affected_count": 0,
            "affected_items": [],
            "remediation": "Continue monitoring compliance alignment.",
        })

    chart_data = {"compliance": compliance_result}
    return findings, chart_data


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def generate_report(pce, ai):
    """Run full security analysis and generate report."""
    start_time = time.time()

    data = collect_all_data(pce)

    # Run all analysis sections
    sections = {}
    all_findings_by_category = {}

    analysis_functions = {
        "enforcement_coverage": lambda: analyze_enforcement_coverage(data["workloads"]),
        "os_lifecycle": lambda: analyze_os_lifecycle(data["workloads"]),
        "label_hygiene": lambda: analyze_label_hygiene(data["workloads"]),
        "env_separation": lambda: analyze_env_separation(data["traffic"]),
        "risky_services": lambda: analyze_risky_services(data["traffic"]),
        "policy_analysis": lambda: analyze_policy(data["policy"]),
        "traffic_anomalies": lambda: analyze_traffic_anomalies(data["traffic"], data["workloads"]),
        "lateral_movement": lambda: analyze_lateral_movement(data["traffic"]),
        "agent_health": lambda: analyze_agent_health(data["workloads"]),
    }

    for cat_id, func in analysis_functions.items():
        try:
            findings, chart_data = func()
            score = calculate_category_score(findings)
            grade = score_to_grade(score)

            severity_counts = Counter(f["severity"] for f in findings)

            sections[cat_id] = {
                "id": cat_id,
                "title": CATEGORY_TITLES[cat_id],
                "icon": CATEGORY_ICONS[cat_id],
                "weight": CATEGORY_WEIGHTS[cat_id],
                "score": score,
                "grade": grade,
                "findings": findings,
                "severity_counts": dict(severity_counts),
                "chart_data": chart_data,
                "ai_narrative": None,
            }
            all_findings_by_category[cat_id] = findings

        except Exception as e:
            log.error("Analysis failed for %s: %s", cat_id, e, exc_info=True)
            sections[cat_id] = {
                "id": cat_id,
                "title": CATEGORY_TITLES[cat_id],
                "icon": CATEGORY_ICONS[cat_id],
                "weight": CATEGORY_WEIGHTS[cat_id],
                "score": 50,
                "grade": "?",
                "findings": [{"id": f"{cat_id}-err", "title": f"Analysis error: {e}", "severity": "info",
                              "description": str(e), "affected_count": 0, "affected_items": [], "remediation": "Check logs."}],
                "severity_counts": {},
                "chart_data": {},
                "ai_narrative": None,
            }
            all_findings_by_category[cat_id] = []

    # Compliance analysis (depends on other sections)
    try:
        comp_findings, comp_chart = analyze_compliance(all_findings_by_category)
        comp_score = calculate_category_score(comp_findings)
        comp_grade = score_to_grade(comp_score)
        sections["compliance"] = {
            "id": "compliance",
            "title": CATEGORY_TITLES["compliance"],
            "icon": CATEGORY_ICONS["compliance"],
            "weight": CATEGORY_WEIGHTS["compliance"],
            "score": comp_score,
            "grade": comp_grade,
            "findings": comp_findings,
            "severity_counts": dict(Counter(f["severity"] for f in comp_findings)),
            "chart_data": comp_chart,
            "ai_narrative": None,
        }
        all_findings_by_category["compliance"] = comp_findings
    except Exception as e:
        log.error("Compliance analysis failed: %s", e, exc_info=True)

    # Calculate scores
    category_scores = {cat_id: sec["score"] for cat_id, sec in sections.items()}
    overall_score = calculate_overall_score(category_scores)
    overall_grade = score_to_grade(overall_score)

    # Aggregate severity totals
    severity_totals = Counter()
    all_critical_high = []
    for cat_id, findings in all_findings_by_category.items():
        for f in findings:
            severity_totals[f["severity"]] += 1
            if f["severity"] in ("critical", "high"):
                all_critical_high.append(f)
    all_critical_high.sort(key=lambda x: (0 if x["severity"] == "critical" else 1, -x.get("affected_count", 0)))

    # AI narratives (if enabled)
    if ai and ai.is_enabled():
        log.info("Generating AI narratives...")
        for cat_id, sec in sections.items():
            if cat_id == "compliance":
                continue
            try:
                findings_summary = [
                    {"title": f["title"], "severity": f["severity"], "affected_count": f.get("affected_count", 0)}
                    for f in sec["findings"] if f["severity"] != "info"
                ]
                metrics = sec.get("chart_data", {})
                narrative = ai.analyze_section(cat_id, sec["title"], findings_summary, metrics, sec["score"], sec["grade"])
                if narrative:
                    sec["ai_narrative"] = narrative
            except Exception as e:
                log.error("AI narrative failed for %s: %s", cat_id, e)

        # Executive summary
        try:
            categories_summary = {
                cat_id: {"title": sec["title"], "score": sec["score"], "grade": sec["grade"]}
                for cat_id, sec in sections.items()
            }
            data_summary = {
                "total_workloads": len(data["workloads"]),
                "total_traffic_flows": len(data["traffic"]),
                "total_rulesets": len(data["policy"]["rulesets"]),
                "lookback_days": LOOKBACK_DAYS,
            }
            executive = ai.generate_executive_summary(
                overall_score, overall_grade, categories_summary,
                dict(severity_totals), all_critical_high[:10], data_summary,
            )
        except Exception as e:
            log.error("AI executive summary failed: %s", e)
            executive = None

        # Remediation roadmap
        try:
            roadmap = ai.generate_remediation_roadmap(overall_score, all_findings_by_category)
        except Exception as e:
            log.error("AI remediation roadmap failed: %s", e)
            roadmap = None
    else:
        executive = None
        roadmap = None

    # Build trend comparison
    trend = build_trend(overall_score, category_scores)

    # Data summary
    total_allowed = sum(1 for f in data["traffic"] if f.get("policy_decision") == "allowed")
    total_blocked = sum(1 for f in data["traffic"] if f.get("policy_decision") in ("blocked", "potentially_blocked"))

    report = {
        "report_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pce_host": os.environ.get("PCE_HOST", "unknown"),
        "scan_duration_seconds": round(time.time() - start_time, 1),
        "config": {
            "lookback_days": LOOKBACK_DAYS,
            "max_traffic_results": MAX_TRAFFIC_RESULTS,
            "process_sample_size": PROCESS_SAMPLE_SIZE,
            "ai_enabled": ai.is_enabled() if ai else False,
            "ai_provider": ai.provider if ai else "",
        },
        "overall_score": overall_score,
        "overall_grade": overall_grade,
        "data_summary": {
            "total_workloads": len(data["workloads"]),
            "total_managed": sum(1 for w in data["workloads"] if w.get("managed", True)),
            "total_traffic_flows": len(data["traffic"]),
            "total_allowed_flows": total_allowed,
            "total_blocked_flows": total_blocked,
            "total_rulesets": len(data["policy"]["rulesets"]),
            "total_rules": sum(len(rs.get("rules", [])) for rs in data["policy"]["rulesets"]),
            "total_labels": len(data["labels"]),
            "total_services": len(data["policy"]["services"]),
            "total_ip_lists": len(data["policy"]["ip_lists"]),
        },
        "executive_summary": executive,
        "sections": sections,
        "severity_totals": dict(severity_totals),
        "remediation_roadmap": roadmap,
        "trend": trend,
    }

    return report


# ---------------------------------------------------------------------------
# Report persistence
# ---------------------------------------------------------------------------

def save_report(report):
    """Save report to /data/reports/ and enforce retention."""
    report_dir = "/data/reports"
    os.makedirs(report_dir, exist_ok=True)

    ts = report["timestamp"].replace(":", "").replace("-", "").split(".")[0].replace("T", "_")
    filename = f"report_{ts}.json"
    filepath = os.path.join(report_dir, filename)

    with open(filepath, "w") as f:
        json.dump(report, f, default=str)
    log.info("Report saved: %s", filepath)

    # Enforce retention
    files = sorted(globmod.glob(os.path.join(report_dir, "report_*.json")))
    while len(files) > REPORT_RETENTION:
        old = files.pop(0)
        try:
            os.remove(old)
            log.info("Removed old report: %s", old)
        except OSError:
            pass


def load_latest_report():
    """Load the most recent report from disk."""
    report_dir = "/data/reports"
    files = sorted(globmod.glob(os.path.join(report_dir, "report_*.json")))
    if not files:
        return None
    try:
        with open(files[-1]) as f:
            return json.load(f)
    except Exception:
        return None


def load_report_list():
    """Return list of available historical reports."""
    report_dir = "/data/reports"
    files = sorted(globmod.glob(os.path.join(report_dir, "report_*.json")), reverse=True)
    result = []
    for fp in files:
        fname = os.path.basename(fp)
        try:
            with open(fp) as f:
                data = json.load(f)
            result.append({
                "filename": fname,
                "timestamp": data.get("timestamp", ""),
                "overall_score": data.get("overall_score", 0),
                "overall_grade": data.get("overall_grade", "?"),
            })
        except Exception:
            result.append({"filename": fname, "timestamp": "", "overall_score": 0, "overall_grade": "?"})
    return result


def load_report_by_timestamp(ts):
    """Load a specific historical report by timestamp fragment."""
    report_dir = "/data/reports"
    files = globmod.glob(os.path.join(report_dir, f"report_*{ts}*.json"))
    if not files:
        return None
    try:
        with open(files[0]) as f:
            return json.load(f)
    except Exception:
        return None


def build_trend(current_score, current_category_scores):
    """Compare with previous report if available."""
    report_dir = "/data/reports"
    files = sorted(globmod.glob(os.path.join(report_dir, "report_*.json")))
    if len(files) < 1:
        return None
    try:
        with open(files[-1]) as f:
            prev = json.load(f)
        prev_score = prev.get("overall_score", 0)
        prev_sections = prev.get("sections", {})
        category_deltas = {}
        for cat_id, score in current_category_scores.items():
            prev_cat = prev_sections.get(cat_id, {})
            category_deltas[cat_id] = score - prev_cat.get("score", score)
        return {
            "previous_score": prev_score,
            "score_delta": current_score - prev_score,
            "category_deltas": category_deltas,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Background poller
# ---------------------------------------------------------------------------

def poller_loop(pce, ai):
    # Load previous report on startup
    prev = load_latest_report()
    if prev:
        with state_lock:
            report_state["latest_report"] = prev
            report_state["last_scan"] = prev.get("timestamp")
        log.info("Loaded previous report from disk (score: %s)", prev.get("overall_score"))

    while True:
        # Check if scan requested
        do_scan = False
        with state_lock:
            if report_state["scan_requested"]:
                report_state["scan_requested"] = False
                do_scan = True

        if do_scan or report_state["last_scan"] is None:
            pass  # Always run
        else:
            time.sleep(30)
            # Check interval
            try:
                last = datetime.fromisoformat(report_state["last_scan"].replace("Z", "+00:00"))
                elapsed = (datetime.now(timezone.utc) - last).total_seconds()
                if elapsed < SCAN_INTERVAL:
                    continue
            except (ValueError, TypeError, AttributeError):
                pass

        try:
            with state_lock:
                report_state["scanning"] = True
                report_state["error"] = None

            log.info("Starting security scan...")
            report = generate_report(pce, ai)

            save_report(report)

            with state_lock:
                report_state["latest_report"] = report
                report_state["last_scan"] = report["timestamp"]
                report_state["scan_count"] += 1
                report_state["scanning"] = False

            log.info("Scan complete. Score: %s (%s). Duration: %.1fs",
                     report["overall_score"], report["overall_grade"], report["scan_duration_seconds"])

        except Exception as e:
            log.error("Scan failed: %s", e, exc_info=True)
            with state_lock:
                report_state["scanning"] = False
                report_state["error"] = str(e)

        time.sleep(60)


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Security Report</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>
tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}
</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#11111b}
::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.severity-critical{color:#f38ba8;background:rgba(243,139,168,0.1);border:1px solid rgba(243,139,168,0.3)}
.severity-high{color:#fab387;background:rgba(250,179,135,0.1);border:1px solid rgba(250,179,135,0.3)}
.severity-medium{color:#f9e2af;background:rgba(249,226,175,0.1);border:1px solid rgba(249,226,175,0.3)}
.severity-low{color:#a6e3a1;background:rgba(166,227,161,0.1);border:1px solid rgba(166,227,161,0.3)}
.severity-info{color:#89b4fa;background:rgba(137,180,250,0.1);border:1px solid rgba(137,180,250,0.3)}
.score-gauge{transition:stroke-dashoffset 1.5s ease-in-out}
.finding-detail{display:none}
.finding-row.expanded .finding-detail{display:table-row}
.section-content{max-height:0;overflow:hidden;transition:max-height 0.3s ease}
.section-content.open{max-height:none}
.cat-card{cursor:pointer;transition:transform 0.15s,box-shadow 0.15s}
.cat-card:hover{transform:translateY(-2px);box-shadow:0 4px 20px rgba(0,0,0,0.3)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.scanning{animation:pulse 2s infinite}
@media print{
  body{background:white!important;color:black!important;font-size:11px}
  .no-print{display:none!important}
  .bg-dark-800,.bg-dark-900{background:#f9f9f9!important;border:1px solid #ddd!important}
  .text-gray-400,.text-gray-500{color:#555!important}
  *{color:black!important;border-color:#ddd!important}
  .section-content{max-height:none!important}
  canvas{max-height:200px!important}
  .cat-card{break-inside:avoid}
}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-6">

<!-- Header -->
<div class="flex items-center justify-between mb-8">
  <div class="flex items-center gap-4">
    <div>
      <h1 class="text-2xl font-bold text-white flex items-center gap-2">
        <svg class="w-7 h-7 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
        AI Security Report
      </h1>
      <div class="flex items-center gap-2 mt-1">
        <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
        <span id="status-text" class="text-sm text-gray-400">Loading...</span>
      </div>
    </div>
  </div>
  <div class="flex items-center gap-3 no-print">
    <select id="history-select" class="bg-dark-800 text-sm border border-gray-600 rounded px-2 py-1.5 text-gray-300" onchange="loadHistorical(this.value)">
      <option value="">Latest Report</option>
    </select>
    <button onclick="triggerScan()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Scan Now</button>
    <button onclick="window.print()" class="bg-dark-700 hover:bg-dark-800 text-gray-300 px-4 py-1.5 rounded text-sm border border-gray-600">Export PDF</button>
  </div>
</div>

<!-- Score + Stats Row -->
<div class="grid grid-cols-1 lg:grid-cols-5 gap-6 mb-8">
  <!-- Score Gauge -->
  <div class="lg:col-span-2 bg-dark-800 rounded-xl border border-gray-700 p-6 flex flex-col items-center justify-center">
    <div class="relative" style="width:180px;height:180px">
      <svg viewBox="0 0 120 120" class="w-full h-full">
        <circle cx="60" cy="60" r="52" fill="none" stroke="#313244" stroke-width="8"/>
        <circle id="gauge-circle" cx="60" cy="60" r="52" fill="none" stroke="#89b4fa" stroke-width="8"
                stroke-linecap="round" stroke-dasharray="326.7" stroke-dashoffset="326.7"
                transform="rotate(-90 60 60)" class="score-gauge"/>
      </svg>
      <div class="absolute inset-0 flex flex-col items-center justify-center">
        <span id="gauge-score" class="text-4xl font-bold text-white">—</span>
        <span id="gauge-grade" class="text-lg font-semibold text-gray-400">—</span>
      </div>
    </div>
    <div id="gauge-label" class="text-sm text-gray-400 mt-2">Security Posture Score</div>
    <div id="gauge-trend" class="text-xs mt-1"></div>
  </div>

  <!-- Key Stats -->
  <div class="lg:col-span-3 grid grid-cols-2 gap-4">
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-workloads" class="text-3xl font-bold text-blue-400">—</div>
      <div class="text-sm text-gray-500 mt-1">Total Workloads</div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-managed" class="text-3xl font-bold text-green-400">—</div>
      <div class="text-sm text-gray-500 mt-1">Managed %</div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-flows" class="text-3xl font-bold text-purple-400">—</div>
      <div class="text-sm text-gray-500 mt-1">Traffic Flows</div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-findings" class="text-3xl font-bold text-yellow-400">—</div>
      <div class="text-sm text-gray-500 mt-1">Total Findings</div>
    </div>
  </div>
</div>

<!-- Executive Summary -->
<div id="executive-section" class="bg-dark-800 rounded-xl border border-gray-700 p-6 mb-8" style="display:none">
  <h2 class="text-lg font-semibold text-white mb-3 flex items-center gap-2">
    <svg class="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
    AI Executive Summary
  </h2>
  <p id="exec-narrative" class="text-gray-300 mb-4 leading-relaxed"></p>
  <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
    <div>
      <h3 class="text-sm font-semibold text-red-400 mb-2">Top Risks</h3>
      <ul id="exec-risks" class="text-sm text-gray-400 space-y-1"></ul>
    </div>
    <div>
      <h3 class="text-sm font-semibold text-green-400 mb-2">Positive Findings</h3>
      <ul id="exec-wins" class="text-sm text-gray-400 space-y-1"></ul>
    </div>
    <div>
      <h3 class="text-sm font-semibold text-blue-400 mb-2">Focus Areas</h3>
      <ul id="exec-focus" class="text-sm text-gray-400 space-y-1"></ul>
    </div>
  </div>
</div>

<!-- Category Score Cards -->
<div id="category-cards" class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-8"></div>

<!-- Charts Row -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Category Scores</h3>
    <div style="height:300px"><canvas id="chart-radar"></canvas></div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Finding Severity Distribution</h3>
    <div style="height:300px"><canvas id="chart-severity"></canvas></div>
  </div>
</div>

<!-- Filter Bar -->
<div class="flex items-center gap-3 mb-6 no-print">
  <span class="text-sm text-gray-500">Filter:</span>
  <button onclick="filterSeverity('all')" class="sev-btn px-3 py-1 rounded text-xs font-medium bg-dark-700 text-gray-300 border border-gray-600" data-sev="all">All</button>
  <button onclick="filterSeverity('critical')" class="sev-btn px-3 py-1 rounded text-xs font-medium severity-critical" data-sev="critical">Critical</button>
  <button onclick="filterSeverity('high')" class="sev-btn px-3 py-1 rounded text-xs font-medium severity-high" data-sev="high">High</button>
  <button onclick="filterSeverity('medium')" class="sev-btn px-3 py-1 rounded text-xs font-medium severity-medium" data-sev="medium">Medium</button>
  <button onclick="filterSeverity('low')" class="sev-btn px-3 py-1 rounded text-xs font-medium severity-low" data-sev="low">Low</button>
  <input id="search-input" type="text" placeholder="Search findings..." oninput="applyFilters()"
         class="ml-auto bg-dark-800 border border-gray-600 rounded px-3 py-1 text-sm text-gray-300 w-48">
</div>

<!-- Analysis Sections -->
<div id="sections-container"></div>

<!-- Remediation Roadmap -->
<div id="roadmap-section" class="bg-dark-800 rounded-xl border border-gray-700 p-6 mb-8" style="display:none">
  <h2 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
    <svg class="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>
    AI Remediation Roadmap
  </h2>
  <div id="roadmap-list"></div>
</div>

<!-- Footer -->
<div class="text-center text-xs text-gray-600 py-4 no-print">
  AI Security Report — Powered by Illumio Plugger
</div>

</div>

<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\\/plugins\\/[^/]+\\/ui/);return m?m[0]:''})();
let currentReport=null;
let sevFilter='all';
let chartRadar=null,chartSeverity=null;

function formatNum(n){
  if(n>=1e9)return(n/1e9).toFixed(1)+'B';
  if(n>=1e6)return(n/1e6).toFixed(1)+'M';
  if(n>=1e3)return(n/1e3).toFixed(1)+'K';
  return n.toLocaleString();
}

function timeAgo(ts){
  if(!ts)return '—';
  const d=(Date.now()-new Date(ts).getTime())/1000;
  if(d<60)return 'just now';
  if(d<3600)return Math.floor(d/60)+'m ago';
  if(d<86400)return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}

function gradeColor(grade){
  return{A:'#a6e3a1',B:'#94e2d5',C:'#f9e2af',D:'#fab387',F:'#f38ba8'}[grade]||'#6c7086';
}

function sevColor(sev){
  return{critical:'#f38ba8',high:'#fab387',medium:'#f9e2af',low:'#a6e3a1',info:'#89b4fa'}[sev]||'#6c7086';
}

function sevIcon(sev){
  const icons={
    critical:'<svg class="w-4 h-4 inline" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"/></svg>',
    high:'<svg class="w-4 h-4 inline" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"/></svg>',
    medium:'<svg class="w-4 h-4 inline" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"/></svg>',
    low:'<svg class="w-4 h-4 inline" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"/></svg>',
    info:'<svg class="w-4 h-4 inline" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"/></svg>',
  };
  return icons[sev]||icons.info;
}

// Render the full report
function renderAll(report){
  if(!report){
    document.getElementById('status-text').textContent='No report available. Click Scan Now.';
    return;
  }
  currentReport=report;

  // Status
  const dot=document.getElementById('status-dot');
  const txt=document.getElementById('status-text');
  dot.className='w-2.5 h-2.5 rounded-full bg-green-500';
  txt.textContent='Report: '+timeAgo(report.timestamp)+' | Score: '+report.overall_score+'/100 ('+report.overall_grade+') | Duration: '+report.scan_duration_seconds+'s';

  // Score gauge
  const circle=document.getElementById('gauge-circle');
  const pct=report.overall_score/100;
  const circumference=326.7;
  circle.style.strokeDashoffset=circumference*(1-pct);
  circle.style.stroke=gradeColor(report.overall_grade);
  document.getElementById('gauge-score').textContent=report.overall_score;
  document.getElementById('gauge-grade').textContent='Grade: '+report.overall_grade;
  document.getElementById('gauge-grade').style.color=gradeColor(report.overall_grade);

  // Trend
  const trendEl=document.getElementById('gauge-trend');
  if(report.trend&&report.trend.score_delta!==0){
    const d=report.trend.score_delta;
    const arrow=d>0?'↑':'↓';
    const color=d>0?'text-green-400':'text-red-400';
    trendEl.innerHTML='<span class="'+color+'">'+arrow+' '+Math.abs(d)+' from previous scan</span>';
  }else{
    trendEl.textContent='';
  }

  // Stats
  const ds=report.data_summary||{};
  document.getElementById('stat-workloads').textContent=formatNum(ds.total_workloads||0);
  const managedPct=ds.total_workloads?Math.round(ds.total_managed/ds.total_workloads*100):0;
  document.getElementById('stat-managed').textContent=managedPct+'%';
  document.getElementById('stat-flows').textContent=formatNum(ds.total_traffic_flows||0);
  const totalFindings=Object.values(report.severity_totals||{}).reduce((a,b)=>a+b,0);
  document.getElementById('stat-findings').textContent=formatNum(totalFindings);

  // Executive summary
  renderExecutive(report.executive_summary);

  // Category cards
  renderCategoryCards(report.sections);

  // Charts
  renderRadarChart(report.sections);
  renderSeverityChart(report.severity_totals);

  // Sections
  renderSections(report.sections);

  // Roadmap
  renderRoadmap(report.remediation_roadmap);
}

function renderExecutive(exec){
  const section=document.getElementById('executive-section');
  if(!exec||!exec.executive_narrative){section.style.display='none';return;}
  section.style.display='block';
  document.getElementById('exec-narrative').textContent=exec.executive_narrative;
  const render=(id,arr)=>{
    const el=document.getElementById(id);
    el.innerHTML=(arr||[]).map(t=>'<li>• '+t+'</li>').join('');
  };
  render('exec-risks',exec.top_3_risks);
  render('exec-wins',exec.top_3_wins);
  render('exec-focus',exec.recommended_focus_areas);
}

function renderCategoryCards(sections){
  const container=document.getElementById('category-cards');
  const order=['enforcement_coverage','os_lifecycle','label_hygiene','env_separation','risky_services','policy_analysis','traffic_anomalies','lateral_movement','agent_health','compliance'];
  let html='';
  for(const id of order){
    const sec=sections[id];
    if(!sec)continue;
    const gc=gradeColor(sec.grade);
    const findingCount=Object.entries(sec.severity_counts||{}).filter(([k])=>k!=='info').reduce((a,[,v])=>a+v,0);
    const trend=currentReport.trend?.category_deltas?.[id];
    let trendHtml='';
    if(trend&&trend!==0){
      const arrow=trend>0?'↑':'↓';
      const tc=trend>0?'text-green-400':'text-red-400';
      trendHtml='<span class="'+tc+' text-xs">'+arrow+Math.abs(trend)+'</span>';
    }
    html+=`<div class="cat-card bg-dark-800 rounded-xl border border-gray-700 p-4" onclick="scrollToSection('${id}')">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs text-gray-500 uppercase tracking-wide">${sec.title}</span>
        ${trendHtml}
      </div>
      <div class="flex items-center gap-3">
        <div class="relative" style="width:48px;height:48px">
          <svg viewBox="0 0 40 40" class="w-full h-full">
            <circle cx="20" cy="20" r="16" fill="none" stroke="#313244" stroke-width="3"/>
            <circle cx="20" cy="20" r="16" fill="none" stroke="${gc}" stroke-width="3"
                    stroke-dasharray="100.5" stroke-dashoffset="${100.5*(1-sec.score/100)}"
                    stroke-linecap="round" transform="rotate(-90 20 20)" class="score-gauge"/>
          </svg>
          <div class="absolute inset-0 flex items-center justify-center">
            <span class="text-xs font-bold" style="color:${gc}">${sec.grade}</span>
          </div>
        </div>
        <div>
          <div class="text-xl font-bold text-white">${sec.score}</div>
          <div class="text-xs text-gray-500">${findingCount} finding${findingCount!==1?'s':''}</div>
        </div>
      </div>
    </div>`;
  }
  container.innerHTML=html;
}

function renderRadarChart(sections){
  const order=['enforcement_coverage','os_lifecycle','label_hygiene','env_separation','risky_services','policy_analysis','traffic_anomalies','lateral_movement','agent_health','compliance'];
  const labels=order.map(id=>(sections[id]?.title||id).replace(/ & /,' & ').substring(0,18));
  const data=order.map(id=>sections[id]?.score||0);
  const ctx=document.getElementById('chart-radar').getContext('2d');
  if(chartRadar)chartRadar.destroy();
  chartRadar=new Chart(ctx,{
    type:'radar',
    data:{labels,datasets:[{label:'Score',data,backgroundColor:'rgba(137,180,250,0.2)',borderColor:'#89b4fa',pointBackgroundColor:'#89b4fa',pointBorderColor:'#89b4fa'}]},
    options:{responsive:true,maintainAspectRatio:false,scales:{r:{beginAtZero:true,max:100,ticks:{display:false},grid:{color:'rgba(69,71,90,0.4)'},pointLabels:{color:'#a6adc8',font:{size:10}}}},plugins:{legend:{display:false}}}
  });
}

function renderSeverityChart(totals){
  if(!totals)return;
  const labels=['Critical','High','Medium','Low','Info'];
  const keys=['critical','high','medium','low','info'];
  const data=keys.map(k=>totals[k]||0);
  const colors=['#f38ba8','#fab387','#f9e2af','#a6e3a1','#89b4fa'];
  const ctx=document.getElementById('chart-severity').getContext('2d');
  if(chartSeverity)chartSeverity.destroy();
  chartSeverity=new Chart(ctx,{
    type:'doughnut',
    data:{labels,datasets:[{data,backgroundColor:colors,borderWidth:0}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'60%',plugins:{legend:{position:'right',labels:{color:'#a6adc8',padding:12,font:{size:12}}}}}
  });
}

function renderSections(sections){
  const container=document.getElementById('sections-container');
  const order=['enforcement_coverage','os_lifecycle','label_hygiene','env_separation','risky_services','policy_analysis','traffic_anomalies','lateral_movement','agent_health','compliance'];
  let html='';
  for(const id of order){
    const sec=sections[id];
    if(!sec)continue;
    const gc=gradeColor(sec.grade);
    const sc=sec.severity_counts||{};
    const sevPills=['critical','high','medium','low'].filter(s=>sc[s]>0).map(s=>`<span class="severity-${s} px-2 py-0.5 rounded-full text-xs font-medium">${sc[s]} ${s}</span>`).join(' ');

    html+=`<div id="section-${id}" class="bg-dark-800 rounded-xl border border-gray-700 mb-6">
      <div class="p-5 cursor-pointer flex items-center justify-between" onclick="toggleSection('${id}')">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg flex items-center justify-center" style="background:${gc}22">
            <span class="text-sm font-bold" style="color:${gc}">${sec.score}</span>
          </div>
          <div>
            <h3 class="text-white font-semibold">${sec.title}</h3>
            <div class="flex items-center gap-2 mt-1">${sevPills}</div>
          </div>
        </div>
        <svg class="w-5 h-5 text-gray-500 section-chevron" id="chevron-${id}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
      </div>
      <div class="section-content" id="content-${id}">
        <div class="px-5 pb-5">`;

    // AI Narrative
    if(sec.ai_narrative&&sec.ai_narrative.narrative){
      html+=`<div class="bg-dark-900 rounded-lg border border-gray-700 p-4 mb-4">
        <div class="flex items-center gap-2 mb-2"><svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg><span class="text-sm font-semibold text-purple-400">AI Analysis</span></div>
        <p class="text-sm text-gray-300 leading-relaxed">${sec.ai_narrative.narrative}</p>`;
      if(sec.ai_narrative.top_recommendations&&sec.ai_narrative.top_recommendations.length){
        html+=`<div class="mt-3 text-xs text-gray-400"><strong>Recommendations:</strong><ul class="mt-1 space-y-1">${sec.ai_narrative.top_recommendations.map(r=>'<li>• '+r+'</li>').join('')}</ul></div>`;
      }
      html+=`</div>`;
    }

    // Section-specific chart
    html+=renderSectionChart(id,sec.chart_data);

    // Findings table
    html+=renderFindingsTable(sec.findings,id);

    html+=`</div></div></div>`;
  }
  container.innerHTML=html;

  // Render section charts after DOM is ready
  setTimeout(()=>{renderAllSectionCharts(sections)},100);
}

function renderSectionChart(id,chartData){
  if(!chartData)return'';
  if(id==='enforcement_coverage'){
    return`<div class="mb-4" style="height:200px"><canvas id="schart-${id}"></canvas></div>`;
  }
  if(id==='os_lifecycle'){
    return`<div class="mb-4" style="height:200px"><canvas id="schart-${id}"></canvas></div>`;
  }
  if(id==='label_hygiene'){
    return`<div class="mb-4" style="height:200px"><canvas id="schart-${id}"></canvas></div>`;
  }
  if(id==='env_separation'&&chartData.heatmap){
    return`<div class="mb-4" id="heatmap-container"></div>`;
  }
  if(id==='risky_services'&&chartData.risky_services&&chartData.risky_services.length){
    return`<div class="mb-4" style="height:200px"><canvas id="schart-${id}"></canvas></div>`;
  }
  if(id==='traffic_anomalies'){
    return`<div class="mb-4" style="height:200px"><canvas id="schart-${id}"></canvas></div>`;
  }
  return'';
}

function renderAllSectionCharts(sections){
  // Enforcement
  const ec=sections.enforcement_coverage?.chart_data?.enforcement_distribution;
  if(ec){
    const ctx=document.getElementById('schart-enforcement_coverage');
    if(ctx)new Chart(ctx.getContext('2d'),{type:'doughnut',data:{labels:Object.keys(ec),datasets:[{data:Object.values(ec),backgroundColor:['#6c7086','#89b4fa','#f9e2af','#a6e3a1'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,cutout:'55%',plugins:{legend:{position:'right',labels:{color:'#a6adc8',font:{size:11}}}}}});
  }
  // OS
  const os=sections.os_lifecycle?.chart_data?.os_distribution;
  if(os){
    const ctx=document.getElementById('schart-os_lifecycle');
    if(ctx){
      const keys=Object.keys(os).slice(0,10);
      const vals=keys.map(k=>os[k]);
      new Chart(ctx.getContext('2d'),{type:'bar',data:{labels:keys,datasets:[{label:'Workloads',data:vals,backgroundColor:'#89b4fa',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#6c7086'},grid:{color:'rgba(69,71,90,0.3)'}},y:{ticks:{color:'#a6adc8',font:{size:10}},grid:{display:false}}}}});
    }
  }
  // Label hygiene
  const lh=sections.label_hygiene?.chart_data?.label_coverage;
  if(lh){
    const ctx=document.getElementById('schart-label_hygiene');
    if(ctx){
      const keys=Object.keys(lh);
      const vals=keys.map(k=>lh[k]);
      const colors=vals.map(v=>v>=80?'#a6e3a1':v>=50?'#f9e2af':'#f38ba8');
      new Chart(ctx.getContext('2d'),{type:'bar',data:{labels:keys.map(k=>k.charAt(0).toUpperCase()+k.slice(1)),datasets:[{label:'Coverage %',data:vals,backgroundColor:colors,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#a6adc8'},grid:{display:false}},y:{max:100,ticks:{color:'#6c7086',callback:v=>v+'%'},grid:{color:'rgba(69,71,90,0.3)'}}}}});
    }
  }
  // Heatmap
  const hm=sections.env_separation?.chart_data?.heatmap;
  if(hm)renderHeatmap(hm);
  // Risky services
  const rs=sections.risky_services?.chart_data?.risky_services;
  if(rs&&rs.length){
    const ctx=document.getElementById('schart-risky_services');
    if(ctx){
      new Chart(ctx.getContext('2d'),{type:'bar',data:{labels:rs.map(s=>s.name+' ('+s.port+')'),datasets:[{label:'Connections',data:rs.map(s=>s.connections),backgroundColor:'#fab387',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#6c7086'},grid:{color:'rgba(69,71,90,0.3)'}},y:{ticks:{color:'#a6adc8',font:{size:10}},grid:{display:false}}}}});
    }
  }
  // Traffic anomalies
  const ta=sections.traffic_anomalies?.chart_data?.traffic_summary;
  if(ta){
    const ctx=document.getElementById('schart-traffic_anomalies');
    if(ctx){
      new Chart(ctx.getContext('2d'),{type:'doughnut',data:{labels:['Allowed','Blocked','Potentially Blocked'],datasets:[{data:[ta.allowed||0,ta.blocked||0,ta.potentially_blocked||0],backgroundColor:['#a6e3a1','#f38ba8','#fab387'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,cutout:'55%',plugins:{legend:{position:'right',labels:{color:'#a6adc8',font:{size:11}}}}}});
    }
  }
}

function renderHeatmap(hm){
  const container=document.getElementById('heatmap-container');
  if(!container||!hm.environments.length)return;
  const envs=hm.environments;
  const n=envs.length;
  let html=`<div style="display:grid;grid-template-columns:100px repeat(${n},1fr);gap:2px;max-width:100%;overflow-x:auto">`;
  html+='<div></div>';
  for(const env of envs)html+=`<div class="text-center text-xs text-gray-500 p-1 truncate" title="${env}">${env}</div>`;
  for(const srcEnv of envs){
    html+=`<div class="text-xs text-gray-400 p-1 text-right truncate" title="${srcEnv}">${srcEnv}</div>`;
    for(const dstEnv of envs){
      const cell=hm.cells.find(c=>c.src_env===srcEnv&&c.dst_env===dstEnv);
      const total=cell?cell.total:0;
      const intensity=cell?cell.intensity:0;
      let bg;
      if(srcEnv===dstEnv)bg=`rgba(137,180,250,${0.05+intensity*0.5})`;
      else if(intensity>0)bg=`rgba(243,139,168,${0.1+intensity*0.7})`;
      else bg='rgba(49,50,68,0.2)';
      html+=`<div style="background:${bg};padding:6px;text-align:center;border-radius:3px;font-size:11px;color:#cdd6f4;cursor:default" title="${srcEnv} → ${dstEnv}: ${total.toLocaleString()} flows">${total>0?formatNum(total):'—'}</div>`;
    }
  }
  html+='</div>';
  container.innerHTML=html;
}

function renderFindingsTable(findings,sectionId){
  if(!findings||!findings.length)return'<p class="text-sm text-gray-500">No findings.</p>';
  let html=`<div class="overflow-x-auto"><table class="w-full text-sm"><thead><tr class="text-left text-xs text-gray-500 uppercase border-b border-gray-700"><th class="px-3 py-2">Sev</th><th class="px-3 py-2">Finding</th><th class="px-3 py-2">Affected</th><th class="px-3 py-2">Remediation</th></tr></thead><tbody>`;
  for(let i=0;i<findings.length;i++){
    const f=findings[i];
    const vis=shouldShowFinding(f);
    html+=`<tr class="finding-row border-b border-gray-700/50 hover:bg-dark-900 cursor-pointer" data-severity="${f.severity}" style="display:${vis?'':'none'}" onclick="toggleFinding(this)">
      <td class="px-3 py-2.5"><span class="severity-${f.severity} px-2 py-0.5 rounded text-xs">${sevIcon(f.severity)} ${f.severity}</span></td>
      <td class="px-3 py-2.5 text-gray-300">${f.title}</td>
      <td class="px-3 py-2.5 text-gray-400">${f.affected_count>0?formatNum(f.affected_count):'—'}</td>
      <td class="px-3 py-2.5 text-gray-500 text-xs max-w-xs truncate">${f.remediation||''}</td>
    </tr>
    <tr class="finding-detail bg-dark-900 border-b border-gray-700/50" style="display:none">
      <td colspan="4" class="px-5 py-4">
        <div class="text-sm text-gray-300 mb-2">${f.description}</div>
        ${f.affected_items&&f.affected_items.length?'<div class="text-xs text-gray-500 mt-2"><strong>Affected items:</strong><ul class="mt-1 ml-4 list-disc">'+f.affected_items.map(item=>'<li>'+item+'</li>').join('')+'</ul></div>':''}
        <div class="text-xs text-gray-400 mt-2"><strong>Remediation:</strong> ${f.remediation}</div>
      </td>
    </tr>`;
  }
  html+='</tbody></table></div>';
  return html;
}

function shouldShowFinding(f){
  if(sevFilter!=='all'&&f.severity!==sevFilter)return false;
  const q=document.getElementById('search-input')?.value?.toLowerCase()||'';
  if(q&&!f.title.toLowerCase().includes(q)&&!(f.description||'').toLowerCase().includes(q))return false;
  return true;
}

function toggleFinding(row){
  const detail=row.nextElementSibling;
  if(detail&&detail.classList.contains('finding-detail')){
    detail.style.display=detail.style.display==='none'?'table-row':'none';
  }
}

function toggleSection(id){
  const content=document.getElementById('content-'+id);
  const chevron=document.getElementById('chevron-'+id);
  if(content.classList.contains('open')){
    content.classList.remove('open');
    chevron.style.transform='rotate(0deg)';
  }else{
    content.classList.add('open');
    chevron.style.transform='rotate(180deg)';
  }
}

function scrollToSection(id){
  const el=document.getElementById('section-'+id);
  if(el){
    el.scrollIntoView({behavior:'smooth',block:'start'});
    const content=document.getElementById('content-'+id);
    if(!content.classList.contains('open'))toggleSection(id);
  }
}

function filterSeverity(sev){
  sevFilter=sev;
  document.querySelectorAll('.sev-btn').forEach(b=>{
    b.style.opacity=b.dataset.sev===sev||sev==='all'?'1':'0.4';
  });
  applyFilters();
}

function applyFilters(){
  document.querySelectorAll('.finding-row').forEach(row=>{
    if(row.classList.contains('finding-detail'))return;
    const s=row.dataset.severity;
    const f=currentReport?findFindingByRow(row):null;
    const vis=shouldShowRowBySev(s);
    row.style.display=vis?'':'none';
    const detail=row.nextElementSibling;
    if(detail&&detail.classList.contains('finding-detail')&&!vis)detail.style.display='none';
  });
}

function shouldShowRowBySev(sev){
  if(sevFilter!=='all'&&sev!==sevFilter)return false;
  return true;
}

function renderRoadmap(roadmap){
  const section=document.getElementById('roadmap-section');
  if(!roadmap||!roadmap.length){section.style.display='none';return;}
  section.style.display='block';
  const list=document.getElementById('roadmap-list');
  let html='';
  for(let i=0;i<roadmap.length;i++){
    const item=roadmap[i];
    const impactColor={high:'text-red-400',medium:'text-yellow-400',low:'text-green-400'}[item.impact]||'text-gray-400';
    const effortColor={low:'text-green-400',medium:'text-yellow-400',high:'text-red-400'}[item.effort]||'text-gray-400';
    html+=`<div class="flex items-start gap-4 py-3 ${i>0?'border-t border-gray-700/50':''}">
      <div class="w-8 h-8 rounded-full bg-blue-600/20 text-blue-400 flex items-center justify-center text-sm font-bold flex-shrink-0">${item.priority||i+1}</div>
      <div class="flex-1">
        <div class="text-sm text-white font-medium">${item.action}</div>
        <div class="text-xs text-gray-500 mt-1">${item.rationale||''}</div>
        <div class="flex gap-3 mt-1">
          <span class="text-xs ${impactColor}">Impact: ${item.impact}</span>
          <span class="text-xs ${effortColor}">Effort: ${item.effort}</span>
          <span class="text-xs text-gray-500">${item.category||''}</span>
        </div>
      </div>
    </div>`;
  }
  list.innerHTML=html;
}

// API calls
async function fetchReport(){
  try{
    const resp=await fetch(BASE+'/api/report');
    const data=await resp.json();
    if(data.scanning){
      document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning';
      document.getElementById('status-text').textContent='Scanning in progress...';
      if(data.latest_report)renderAll(data.latest_report);
      return;
    }
    if(data.error){
      document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-red-500';
      document.getElementById('status-text').textContent='Error: '+data.error;
      return;
    }
    if(data.latest_report)renderAll(data.latest_report);
    else{
      document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-gray-500';
      document.getElementById('status-text').textContent='No report available yet. Click Scan Now to start.';
    }
  }catch(e){
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-red-500';
    document.getElementById('status-text').textContent='Connection error';
  }
}

async function fetchHistory(){
  try{
    const resp=await fetch(BASE+'/api/report/history');
    const data=await resp.json();
    const sel=document.getElementById('history-select');
    sel.innerHTML='<option value="">Latest Report</option>';
    for(const r of data){
      sel.innerHTML+=`<option value="${r.timestamp}">${new Date(r.timestamp).toLocaleString()} — ${r.overall_score}/100 (${r.overall_grade})</option>`;
    }
  }catch(e){}
}

async function loadHistorical(ts){
  if(!ts){fetchReport();return;}
  try{
    const resp=await fetch(BASE+'/api/report/'+encodeURIComponent(ts));
    const data=await resp.json();
    if(data)renderAll(data);
  }catch(e){}
}

async function triggerScan(){
  try{
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning';
    document.getElementById('status-text').textContent='Scan triggered...';
    await fetch(BASE+'/api/scan',{method:'POST'});
  }catch(e){}
}

// Init
fetchReport();
fetchHistory();
setInterval(fetchReport,30000);
setInterval(fetchHistory,120000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class ReportHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, "")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/" or path == "":
            self._send(200, DASHBOARD_HTML, "text/html")

        elif path == "/healthz":
            self._send(200, json.dumps({"status": "healthy"}))

        elif path == "/api/report":
            with state_lock:
                data = {
                    "scanning": report_state["scanning"],
                    "error": report_state["error"],
                    "last_scan": report_state["last_scan"],
                    "scan_count": report_state["scan_count"],
                    "latest_report": report_state["latest_report"],
                }
            self._send(200, json.dumps(data, default=str))

        elif path == "/api/report/history":
            history = load_report_list()
            self._send(200, json.dumps(history, default=str))

        elif path.startswith("/api/report/"):
            ts = path.split("/api/report/")[1]
            report = load_report_by_timestamp(ts)
            if report:
                self._send(200, json.dumps(report, default=str))
            else:
                self._send(404, json.dumps({"error": "Report not found"}))

        elif path == "/api/config":
            config = {
                "scan_interval": SCAN_INTERVAL,
                "lookback_days": LOOKBACK_DAYS,
                "max_traffic_results": MAX_TRAFFIC_RESULTS,
                "process_sample_size": PROCESS_SAMPLE_SIZE,
                "report_retention": REPORT_RETENTION,
                "ai": ai_instance.get_config() if ai_instance else {"enabled": False},
            }
            self._send(200, json.dumps(config))

        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/scan":
            with state_lock:
                if report_state["scanning"]:
                    self._send(409, json.dumps({"error": "Scan already in progress"}))
                    return
                report_state["scan_requested"] = True
            self._send(200, json.dumps({"status": "scan_requested"}))

        else:
            self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ai_instance = None


def main():
    global ai_instance

    log.info("AI Security Report starting...")
    log.info("Config: scan_interval=%ds, lookback=%dd, max_flows=%d, process_sample=%d",
             SCAN_INTERVAL, LOOKBACK_DAYS, MAX_TRAFFIC_RESULTS, PROCESS_SAMPLE_SIZE)

    pce = get_pce()
    ai_instance = AIAdvisor()

    # Start poller thread
    poller = threading.Thread(target=poller_loop, args=(pce, ai_instance), daemon=True)
    poller.start()

    # HTTP server
    server = HTTPServer(("0.0.0.0", HTTP_PORT), ReportHandler)
    log.info("Dashboard listening on http://0.0.0.0:%d", HTTP_PORT)

    def shutdown(sig, frame):
        log.info("Shutting down...")
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server.serve_forever()


if __name__ == "__main__":
    main()
