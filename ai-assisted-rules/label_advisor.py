"""
Label Advisor — Detect missing labels and suggest roles.

Uses two signals to suggest role labels for unlabeled workloads:
1. Traffic pattern analysis (high confidence) — what ports does the workload
   serve/consume? Receiving on 5432 → likely db, serving 443 → likely web
2. Hostname heuristics (low confidence) — pattern matching on hostname parts

Traffic patterns are the primary signal. Hostname is supplementary.
Customer environments have wildly different naming conventions, so
hostname detection is best-effort with low confidence.
"""

import logging
import re
from collections import Counter, defaultdict

log = logging.getLogger("label_advisor")

# Traffic-based role detection: port → likely role
# These are based on what ports the workload RECEIVES traffic on (is a provider)
PROVIDER_PORT_ROLES = {
    # Database
    5432: ("db", 0.9, "PostgreSQL"),
    3306: ("db", 0.9, "MySQL"),
    1433: ("db", 0.9, "MSSQL"),
    1521: ("db", 0.85, "Oracle"),
    27017: ("db", 0.85, "MongoDB"),
    6379: ("cache", 0.85, "Redis"),
    11211: ("cache", 0.85, "Memcached"),

    # Web
    80: ("web", 0.7, "HTTP"),
    443: ("web", 0.8, "HTTPS"),
    8080: ("web", 0.7, "HTTP-alt"),
    8443: ("web", 0.7, "HTTPS-alt"),

    # Application
    8070: ("processing", 0.7, "App server"),
    9090: ("processing", 0.6, "App/metrics"),

    # Infrastructure
    5666: ("monitoring", 0.9, "NRPE/Nagios"),
    161: ("monitoring", 0.8, "SNMP"),
    514: ("syslog", 0.9, "Syslog"),
    53: ("dns", 0.9, "DNS"),
    123: ("time", 0.85, "NTP"),
    389: ("dc", 0.9, "LDAP"),
    636: ("dc", 0.9, "LDAPS"),
    88: ("dc", 0.9, "Kerberos"),

    # Access
    22: ("jumpbox", 0.4, "SSH"),  # low confidence — many things serve SSH
    3389: ("jumpbox", 0.5, "RDP"),  # medium — could be any Windows
}

# Hostname patterns → role (with confidence)
# These are best-effort and should NOT be relied upon alone
HOSTNAME_PATTERNS = [
    # Pattern, role, confidence
    (r'\bweb\b', "web", 0.6),
    (r'\bnginx\b', "web", 0.7),
    (r'\bapache\b', "web", 0.7),
    (r'\bhttpd\b', "web", 0.7),
    (r'\biis\b', "web", 0.6),

    (r'\bdb\b', "db", 0.6),
    (r'\bsql\b', "db", 0.6),
    (r'\bpostgres\b', "db", 0.7),
    (r'\bmysql\b', "db", 0.7),
    (r'\bmongo\b', "db", 0.7),
    (r'\boracle\b', "db", 0.6),
    (r'\bmariadb\b', "db", 0.7),

    (r'\bproc\b', "processing", 0.5),
    (r'\bapp\b', "processing", 0.4),
    (r'\btomcat\b', "processing", 0.7),
    (r'\bjboss\b', "processing", 0.7),

    (r'\blb\b', "loadbalancer", 0.7),
    (r'\bhaproxy\b', "loadbalancer", 0.8),
    (r'\bf5\b', "loadbalancer", 0.6),
    (r'\bbalancer\b', "loadbalancer", 0.7),

    (r'\bcache\b', "cache", 0.7),
    (r'\bredis\b', "cache", 0.8),
    (r'\bmemcache\b', "cache", 0.8),

    (r'\bjump\b', "jumpbox", 0.7),
    (r'\bbastion\b', "jumpbox", 0.8),
    (r'\bjh\b', "jumpbox", 0.5),

    (r'\bnagios\b', "monitoring", 0.8),
    (r'\bzabbix\b', "monitoring", 0.8),
    (r'\bprometheus\b', "monitoring", 0.8),
    (r'\bgrafana\b', "monitoring", 0.7),
    (r'\bmonitor\b', "monitoring", 0.6),

    (r'\bsyslog\b', "syslog", 0.8),
    (r'\blog\b', "syslog", 0.4),

    (r'\bdns\b', "dns", 0.8),
    (r'\bad\b', "dc", 0.5),
    (r'\bdc\b', "dc", 0.5),
    (r'\bldap\b', "dc", 0.7),

    (r'\bgw\b', "gateway", 0.5),
    (r'\bgateway\b', "gateway", 0.7),
    (r'\bproxy\b', "gateway", 0.6),

    (r'\bfiler\b', "filer", 0.7),
    (r'\bnfs\b', "filer", 0.7),
    (r'\bnas\b', "filer", 0.6),
    (r'\bsamba\b', "filer", 0.7),

    (r'\bmail\b', "mailserver", 0.7),
    (r'\bsmtp\b', "mailserver", 0.8),
    (r'\bexchange\b', "mailserver", 0.6),
]


def suggest_role_from_hostname(hostname):
    """Suggest a role based on hostname pattern matching.

    Returns (role, confidence, reason) or (None, 0, "").
    Confidence is always reduced since hostname patterns are unreliable.
    """
    if not hostname:
        return None, 0, ""

    hostname_lower = hostname.lower()
    matches = []

    for pattern, role, confidence in HOSTNAME_PATTERNS:
        if re.search(pattern, hostname_lower):
            matches.append((role, confidence, f"hostname matches '{pattern}'"))

    if not matches:
        return None, 0, ""

    # Pick highest confidence match
    matches.sort(key=lambda x: -x[1])
    return matches[0]


def suggest_role_from_traffic(workload_href, traffic_flows, label_cache):
    """Suggest a role based on traffic patterns.

    Looks at what ports the workload RECEIVES traffic on (is a provider).
    Returns (role, confidence, reason) or (None, 0, "").
    """
    # Count ports this workload receives on
    provider_ports = Counter()

    for flow in traffic_flows:
        dst = flow.get("dst", {})
        dst_wl = dst.get("workload", {}) or {}
        dst_href = dst_wl.get("href", "")

        if dst_href == workload_href or (not dst_href and dst.get("ip", "") == workload_href):
            service = flow.get("service", {})
            if isinstance(service, dict):
                port = service.get("port")
                if port:
                    provider_ports[port] += flow.get("num_connections", 1)

    if not provider_ports:
        return None, 0, ""

    # Score each possible role based on ports
    role_scores = defaultdict(lambda: {"confidence": 0, "reasons": []})

    for port, count in provider_ports.most_common(10):
        if port in PROVIDER_PORT_ROLES:
            role, conf, desc = PROVIDER_PORT_ROLES[port]
            # Boost confidence if many connections on this port
            if count > 1000:
                conf = min(conf + 0.05, 0.95)
            role_scores[role]["confidence"] = max(role_scores[role]["confidence"], conf)
            role_scores[role]["reasons"].append(f"receives {desc} ({port}/tcp, {count:,} connections)")

    if not role_scores:
        return None, 0, ""

    # Pick highest confidence role
    best_role = max(role_scores.items(), key=lambda x: x[1]["confidence"])
    role = best_role[0]
    data = best_role[1]
    return role, data["confidence"], "; ".join(data["reasons"])


def analyze_label_gaps(pce, label_cache, traffic_flows=None):
    """Analyze all workloads for missing labels and suggest roles.

    Returns a list of gap entries, each containing:
    - workload info (hostname, href, ip, existing labels)
    - what's missing (role, app, env)
    - role suggestion with confidence and reasoning
    """
    try:
        resp = pce.get("/workloads", params={"max_results": 5000})
        workloads = resp.json() if resp.status_code == 200 else []
    except Exception as e:
        log.error("Failed to fetch workloads: %s", e)
        return [], {}

    # Resolve labels
    gaps = []
    summary = {
        "total_workloads": len(workloads),
        "missing_role": 0,
        "missing_app": 0,
        "missing_env": 0,
        "fully_labeled": 0,
        "suggestions_made": 0,
        "by_app_env": defaultdict(lambda: {"total": 0, "missing_role": 0, "workloads": []}),
    }

    for wl in workloads:
        hostname = wl.get("hostname", "")
        href = wl.get("href", "")
        interfaces = wl.get("interfaces", [])
        ip = interfaces[0].get("address", "") if interfaces else ""

        # Resolve labels
        wl_labels = {}
        for lbl in wl.get("labels", []):
            if isinstance(lbl, dict) and lbl.get("href") in label_cache:
                cached = label_cache[lbl["href"]]
                wl_labels[cached["key"]] = {"value": cached["value"], "href": lbl["href"]}

        has_role = "role" in wl_labels
        has_app = "app" in wl_labels
        has_env = "env" in wl_labels

        app_val = wl_labels.get("app", {}).get("value", "")
        env_val = wl_labels.get("env", {}).get("value", "")
        role_val = wl_labels.get("role", {}).get("value", "")
        app_env = f"{app_val}|{env_val}" if app_val and env_val else ""

        missing = []
        if not has_role:
            missing.append("role")
            summary["missing_role"] += 1
        if not has_app:
            missing.append("app")
            summary["missing_app"] += 1
        if not has_env:
            missing.append("env")
            summary["missing_env"] += 1

        if not missing:
            summary["fully_labeled"] += 1
            if app_env:
                summary["by_app_env"][app_env]["total"] += 1
            continue

        # Track by app|env
        if app_env:
            summary["by_app_env"][app_env]["total"] += 1
            if "role" in missing:
                summary["by_app_env"][app_env]["missing_role"] += 1

        # Only suggest roles for workloads that have app+env but missing role
        role_suggestion = None
        if "role" in missing and has_app and has_env:
            # Try traffic-based first (higher confidence)
            traffic_role, traffic_conf, traffic_reason = None, 0, ""
            if traffic_flows:
                traffic_role, traffic_conf, traffic_reason = suggest_role_from_traffic(
                    href, traffic_flows, label_cache)

            # Try hostname-based
            hostname_role, hostname_conf, hostname_reason = suggest_role_from_hostname(hostname)

            # Combine signals
            if traffic_role and hostname_role and traffic_role == hostname_role:
                # Both agree — high confidence
                role_suggestion = {
                    "role": traffic_role,
                    "confidence": min(traffic_conf + 0.1, 0.95),
                    "reason": f"Traffic: {traffic_reason}. Hostname: {hostname_reason}",
                    "source": "traffic+hostname",
                }
            elif traffic_role and traffic_conf > 0.5:
                # Traffic signal strong enough alone
                role_suggestion = {
                    "role": traffic_role,
                    "confidence": traffic_conf,
                    "reason": traffic_reason,
                    "source": "traffic",
                }
            elif hostname_role and hostname_conf > 0.5:
                # Hostname signal (lower confidence)
                role_suggestion = {
                    "role": hostname_role,
                    "confidence": hostname_conf * 0.8,  # discount hostname-only
                    "reason": hostname_reason,
                    "source": "hostname",
                }

            if role_suggestion:
                summary["suggestions_made"] += 1

        gaps.append({
            "hostname": hostname or "(unnamed)",
            "href": href,
            "ip": ip,
            "app": app_val,
            "env": env_val,
            "role": role_val,
            "app_env": app_env,
            "missing": missing,
            "labels": {k: v["value"] for k, v in wl_labels.items()},
            "suggestion": role_suggestion,
        })

        if app_env and "role" in missing:
            summary["by_app_env"][app_env]["workloads"].append({
                "hostname": hostname,
                "suggestion": role_suggestion,
            })

    # Convert defaultdicts
    summary["by_app_env"] = dict(summary["by_app_env"])
    for k, v in summary["by_app_env"].items():
        v["workloads"] = v.get("workloads", [])

    # Sort gaps: missing role first, then by app_env
    gaps.sort(key=lambda x: (0 if "role" in x["missing"] else 1, x.get("app_env", ""), x["hostname"]))

    log.info("Label gaps: %d workloads, %d missing role, %d suggestions made",
             len(workloads), summary["missing_role"], summary["suggestions_made"])

    return gaps, summary
