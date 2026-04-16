#!/usr/bin/env python3
"""
stale-rules-checker — Find blocked traffic and unused rules.

Queries PCE for:
1. Traffic that was blocked/potentially blocked in the last 24h
2. Active rules that had zero matching traffic in the last 24h
3. Groups everything by app|env tuples for segmentation visibility

Serves a web dashboard and writes JSON reports.
"""

import json
import logging
import os
import signal
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

from illumio import PolicyComputeEngine
from illumio.explorer import TrafficQuery

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("ai_assisted_rules")

state_lock = threading.Lock()
report_state = {
    "last_check": None,
    "check_count": 0,
    "error": None,
    # Blocked traffic grouped by app|env
    "blocked_pairs": [],       # [{src_group, dst_group, services, total_connections, flows}]
    "blocked_summary": {},     # total blocked connections, unique pairs, etc.
    # Stale rules (active rules with no traffic)
    "stale_rules": [],         # [{ruleset, rule, scopes, services, reason}]
    "suggested_rules": [],     # high-volume blocked pairs
    "auto_rules": [],          # PCE-ready rule JSON for intra-app|env
    "inter_rules": [],         # cross app|env suggestions
    "stale_summary": {},
    # Label cache
    "label_count": 0,
}

label_cache = {}  # href -> {"key": "...", "value": "..."}


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


def fetch_labels(pce):
    global label_cache
    try:
        resp = pce.get("/labels")
        if resp.status_code == 200:
            for lbl in resp.json():
                href = lbl.get("href", "")
                if href:
                    label_cache[href] = {"key": lbl.get("key", ""), "value": lbl.get("value", "")}
            log.info("Loaded %d labels", len(label_cache))
    except Exception as e:
        log.warning("Failed to fetch labels: %s", e)


def resolve_label(href):
    """Resolve a label href to key=value."""
    if href in label_cache:
        c = label_cache[href]
        return c["key"], c["value"]
    return None, None


def endpoint_labels(endpoint):
    """Extract full label map {key: value} from a flow endpoint."""
    if not isinstance(endpoint, dict):
        return {}

    labels = endpoint.get("labels", [])
    if not labels:
        wl = endpoint.get("workload", {}) or {}
        labels = wl.get("labels", [])

    if not labels:
        return {}

    label_map = {}
    for lbl in labels if isinstance(labels, list) else []:
        if isinstance(lbl, dict):
            href = lbl.get("href", "")
            if href:
                key, val = resolve_label(href)
                if key:
                    label_map[key] = val
            elif lbl.get("key") and lbl.get("value"):
                label_map[lbl["key"]] = lbl["value"]

    return label_map


def endpoint_to_group(endpoint):
    """Extract app|env from a flow endpoint."""
    lm = endpoint_labels(endpoint)
    app = lm.get("app", "")
    env = lm.get("env", "")
    if app or env:
        return f"{app}|{env}" if app and env else (app or env)
    return None


def endpoint_role(endpoint):
    """Extract role label from a flow endpoint."""
    return endpoint_labels(endpoint).get("role", "")


def endpoint_name(endpoint):
    """Get hostname or IP from endpoint."""
    if not isinstance(endpoint, dict):
        return "unknown"
    return (endpoint.get("workload", {}) or {}).get("hostname", "") or endpoint.get("ip", "unknown")


def analyze_traffic(pce):
    """Query blocked traffic and build analysis."""
    lookback = int(os.environ.get("LOOKBACK_HOURS", "24"))
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback)

    log.info("Querying blocked traffic (last %dh)...", lookback)

    # Query blocked/potentially blocked traffic
    query = TrafficQuery.build(
        start_date=start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_date=end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        policy_decisions=["blocked", "potentially_blocked"],
        max_results=int(os.environ.get("MAX_RESULTS", "10000")),
    )

    raw_flows = pce.get_traffic_flows_async(
        query_name="plugger-stale-rules",
        traffic_query=query,
    )

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

    log.info("Got %d blocked flows", len(flows))

    # Group blocked traffic by app|env pairs AND capture role-level detail
    pair_data = defaultdict(lambda: {"connections": 0, "services": Counter(), "hosts": set(), "decision": Counter(), "role_pairs": Counter()})

    for flow in flows:
        src = flow.get("src", {})
        dst = flow.get("dst", {})
        service = flow.get("service", {})
        num = flow.get("num_connections", 1)
        decision = flow.get("policy_decision", "blocked")

        src_group = endpoint_to_group(src) or endpoint_name(src)
        dst_group = endpoint_to_group(dst) or endpoint_name(dst)
        src_role = endpoint_role(src) or "unknown"
        dst_role = endpoint_role(dst) or "unknown"

        port = service.get("port", "?") if isinstance(service, dict) else "?"
        proto = service.get("proto", "?") if isinstance(service, dict) else "?"
        svc = f"{port}/{proto}"

        key = (src_group, dst_group)
        pair_data[key]["connections"] += num
        pair_data[key]["services"][svc] += num
        pair_data[key]["decision"][decision] += num
        pair_data[key]["hosts"].add(endpoint_name(src))
        pair_data[key]["hosts"].add(endpoint_name(dst))
        # Track role-to-role communication with services
        role_key = (src_role, dst_role, svc)
        pair_data[key]["role_pairs"][role_key] += num

    # Sort by connections
    blocked_pairs = []
    for (src_g, dst_g), data in sorted(pair_data.items(), key=lambda x: -x[1]["connections"]):
        # Build role tier data: {(src_role, dst_role): {services: Counter, connections: int}}
        role_tiers = defaultdict(lambda: {"services": Counter(), "connections": 0})
        for (sr, dr, svc), count in data["role_pairs"].items():
            role_tiers[(sr, dr)]["services"][svc] += count
            role_tiers[(sr, dr)]["connections"] += count

        role_tier_list = []
        for (sr, dr), rd in sorted(role_tiers.items(), key=lambda x: -x[1]["connections"]):
            role_tier_list.append({
                "src_role": sr,
                "dst_role": dr,
                "services": rd["services"].most_common(10),
                "connections": rd["connections"],
            })

        blocked_pairs.append({
            "src_group": src_g,
            "dst_group": dst_g,
            "total_connections": data["connections"],
            "services": data["services"].most_common(10),
            "decisions": dict(data["decision"]),
            "host_count": len(data["hosts"]),
            "role_tiers": role_tier_list,
        })

    total_blocked = sum(d["connections"] for d in pair_data.values())
    unique_pairs = len(pair_data)

    return blocked_pairs, {
        "total_blocked_connections": total_blocked,
        "unique_pairs": unique_pairs,
        "total_flows": len(flows),
        "lookback_hours": lookback,
    }


def find_stale_rules(pce, blocked_pairs):
    """Find active rules that might be stale or missing."""
    log.info("Checking active rulesets...")

    stale = []
    try:
        resp = pce.get("/sec_policy/active/rule_sets")
        rulesets = resp.json() if resp.status_code == 200 else []

        for rs in rulesets:
            if not isinstance(rs, dict):
                continue
            rs_name = rs.get("name", "")
            rules = rs.get("rules", [])
            enabled = rs.get("enabled", True)

            if not enabled:
                stale.append({
                    "ruleset": rs_name,
                    "rule_count": len(rules),
                    "enabled": False,
                    "reason": "Ruleset is disabled",
                    "severity": "info",
                })
                continue

            if not rules:
                stale.append({
                    "ruleset": rs_name,
                    "rule_count": 0,
                    "enabled": True,
                    "reason": "Ruleset has no rules",
                    "severity": "warning",
                })

            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                if not rule.get("enabled", True):
                    stale.append({
                        "ruleset": rs_name,
                        "rule": rule.get("href", ""),
                        "enabled": False,
                        "reason": "Rule is disabled within active ruleset",
                        "severity": "info",
                    })

    except Exception as e:
        log.warning("Failed to fetch rulesets: %s", e)

    # Check for blocked pairs that suggest missing rules
    suggested_rules = []
    for pair in blocked_pairs[:20]:  # top 20 blocked pairs
        if pair["total_connections"] > 100:
            suggested_rules.append({
                "src": pair["src_group"],
                "dst": pair["dst_group"],
                "services": [s[0] for s in pair["services"][:5]],
                "connections": pair["total_connections"],
                "reason": f"High-volume blocked traffic ({pair['total_connections']:,} connections) — may need a rule",
                "severity": "high",
            })

    # Build auto-suggest rules for intra-app|env blocked traffic
    auto_rules = build_auto_suggestions(pce, blocked_pairs)

    return stale, suggested_rules, auto_rules, {
        "stale_rulesets": len([s for s in stale if "Ruleset" in s.get("reason", "")]),
        "disabled_rules": len([s for s in stale if "disabled" in s.get("reason", "").lower()]),
        "suggested_rules": len(suggested_rules),
        "auto_rules": len(auto_rules),
    }


# Proto number to name mapping
PROTO_MAP = {"6": "tcp", "17": "udp"}


# Services flagged as risky/insecure — go to "FOR REVIEW" ruleset
RISKY_PORTS = {
    20: "FTP data",
    21: "FTP control",
    23: "Telnet",
    69: "TFTP",
    135: "MS-RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS/SMB",
    445: "SMB",
    1433: None,  # MSSQL — allowed but flagged in some contexts
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-HTTPS",
}

# Ports that are always risky regardless of context
ALWAYS_RISKY = {20, 21, 23, 69, 135, 137, 138, 139, 5900}


def is_risky_service(port, proto_name):
    """Check if a service should be flagged for review."""
    if port in ALWAYS_RISKY:
        return True, RISKY_PORTS.get(port, "insecure protocol")
    if port == 3389 and proto_name == "tcp":
        return True, "RDP — review lateral movement risk"
    if port == 445 and proto_name == "tcp":
        return True, "SMB — review ransomware risk"
    return False, ""


def build_auto_suggestions(pce, blocked_pairs):
    """Build tiered policy suggestions for same app|env blocked pairs.

    Three security tiers:
    - LOW:  All workloads → all workloads, all services (intra-scope open)
    - MED:  Role → Role, all services (tier-based, respects app architecture)
    - HIGH: Role → Role, only observed services (full micro-segmentation)

    Risky services (FTP, telnet, RDP, SMB, etc.) are split into a separate
    "FOR REVIEW" ruleset regardless of tier.
    """
    value_to_href = {}
    for href, info in label_cache.items():
        value_to_href[(info["key"], info["value"])] = href

    # Fetch existing services
    svc_by_port = {}
    try:
        resp = pce.get("/sec_policy/active/services")
        if resp.status_code == 200:
            for svc in resp.json():
                if isinstance(svc, dict):
                    for sp in svc.get("service_ports", []):
                        if isinstance(sp, dict):
                            port = sp.get("port")
                            proto = sp.get("proto")
                            if port and proto:
                                svc_by_port[(port, proto)] = {
                                    "href": svc.get("href", ""),
                                    "name": svc.get("name", ""),
                                }
    except Exception:
        pass

    auto_rules = []

    for pair in blocked_pairs:
        src_g = pair["src_group"]
        dst_g = pair["dst_group"]

        if src_g != dst_g:
            continue
        if pair["total_connections"] < 10:
            continue

        parts = src_g.split("|")
        if len(parts) != 2:
            continue
        app_val, env_val = parts[0], parts[1]

        app_href = value_to_href.get(("app", app_val), "")
        env_href = value_to_href.get(("env", env_val), "")
        if not app_href or not env_href:
            continue

        scope_labels = [
            {"label": {"href": app_href}, "exclusion": False},
            {"label": {"href": env_href}, "exclusion": False},
        ]

        # Classify all services as clean or risky
        all_services = []
        clean_services = []
        risky_services = []

        for svc_str, count in pair["services"]:
            try:
                port_s, proto_s = svc_str.split("/")
                port = int(port_s)
                proto = int(proto_s)
                proto_name = PROTO_MAP.get(str(proto), str(proto))
                existing = svc_by_port.get((port, proto))

                svc_entry = {
                    "port": port,
                    "proto": proto_name,
                    "connections": count,
                }
                if existing:
                    svc_entry["href"] = existing["href"]
                    svc_entry["name"] = existing["name"]

                risky, reason = is_risky_service(port, proto_name)
                if risky:
                    svc_entry["risky"] = True
                    svc_entry["risk_reason"] = reason
                    risky_services.append(svc_entry)
                else:
                    clean_services.append(svc_entry)
                all_services.append(svc_entry)
            except (ValueError, IndexError):
                continue

        if not all_services:
            continue

        # Build role tier data for medium/high security
        role_tiers = pair.get("role_tiers", [])

        # Helper to build ingress_services list for PCE
        def build_ingress(svcs):
            result = []
            for s in svcs:
                if s.get("href"):
                    result.append({"href": s["href"]})
                else:
                    pn = 6 if s["proto"] == "tcp" else 17 if s["proto"] == "udp" else int(s["proto"])
                    result.append({"port": s["port"], "proto": pn})
            return result

        # ===== LOW SECURITY: All workloads → all workloads, all clean services =====
        low_rules = [{
            "enabled": True,
            "providers": [{"actors": "ams"}],
            "consumers": [{"actors": "ams"}],
            "ingress_services": build_ingress(clean_services) if clean_services else build_ingress(all_services),
            "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]},
        }]
        low_ruleset = {
            "name": f"plugger-auto | {app_val} | {env_val}",
            "description": "AI Suggested: intra-scope rule (low security)",
            "enabled": True,
            "scopes": [scope_labels],
            "rules": low_rules,
        }

        # ===== MEDIUM SECURITY: Role → Role, all services per tier =====
        med_rules = []
        if role_tiers:
            seen_pairs = set()
            for tier in role_tiers:
                sr, dr = tier["src_role"], tier["dst_role"]
                if sr == "unknown" or dr == "unknown":
                    continue
                pair_key = (sr, dr)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                sr_href = value_to_href.get(("role", sr), "")
                dr_href = value_to_href.get(("role", dr), "")
                if not sr_href or not dr_href:
                    continue

                # Collect clean services for this role pair
                tier_svcs = []
                for svc_str, count in tier["services"]:
                    try:
                        p, pr = svc_str.split("/")
                        port, proto = int(p), int(pr)
                        pn = PROTO_MAP.get(str(proto), str(proto))
                        risky, _ = is_risky_service(port, pn)
                        if not risky:
                            existing = svc_by_port.get((port, proto))
                            entry = {"port": port, "proto": pn, "connections": count}
                            if existing:
                                entry["href"] = existing["href"]
                            tier_svcs.append(entry)
                    except (ValueError, IndexError):
                        continue

                if not tier_svcs:
                    continue

                med_rules.append({
                    "enabled": True,
                    "providers": [{"label": {"href": dr_href}}],
                    "consumers": [{"label": {"href": sr_href}}],
                    "ingress_services": build_ingress(tier_svcs),
                    "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]},
                })

        if not med_rules:
            med_rules = low_rules  # fallback if no role data

        med_ruleset = {
            "name": f"plugger-auto | {app_val} | {env_val} | tiered",
            "description": "AI Suggested: role-tiered rules (medium security)",
            "enabled": True,
            "scopes": [scope_labels],
            "rules": med_rules,
        }

        # ===== HIGH SECURITY: Role → Role, only observed services =====
        high_rules = []
        if role_tiers:
            seen_pairs = set()
            for tier in role_tiers:
                sr, dr = tier["src_role"], tier["dst_role"]
                if sr == "unknown" or dr == "unknown":
                    continue
                pair_key = (sr, dr)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                sr_href = value_to_href.get(("role", sr), "")
                dr_href = value_to_href.get(("role", dr), "")
                if not sr_href or not dr_href:
                    continue

                # Only observed clean services for this specific role pair
                tier_svcs = []
                for svc_str, count in tier["services"]:
                    try:
                        p, pr = svc_str.split("/")
                        port, proto = int(p), int(pr)
                        pn = PROTO_MAP.get(str(proto), str(proto))
                        risky, _ = is_risky_service(port, pn)
                        if not risky:
                            existing = svc_by_port.get((port, proto))
                            entry = {"port": port, "proto": pn, "connections": count}
                            if existing:
                                entry["href"] = existing["href"]
                            tier_svcs.append(entry)
                    except (ValueError, IndexError):
                        continue

                if not tier_svcs:
                    continue

                high_rules.append({
                    "enabled": True,
                    "providers": [{"label": {"href": dr_href}}],
                    "consumers": [{"label": {"href": sr_href}}],
                    "ingress_services": build_ingress(tier_svcs),
                    "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]},
                })

        if not high_rules:
            high_rules = med_rules  # fallback

        high_ruleset = {
            "name": f"plugger-auto | {app_val} | {env_val} | strict",
            "description": "AI Suggested: strict role+service rules (high security)",
            "enabled": True,
            "scopes": [scope_labels],
            "rules": high_rules,
        }

        # ===== REVIEW RULESET: risky services only =====
        review_ruleset = None
        if risky_services:
            review_rules = [{
                "enabled": True,
                "providers": [{"actors": "ams"}],
                "consumers": [{"actors": "ams"}],
                "ingress_services": build_ingress(risky_services),
                "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]},
            }]
            review_ruleset = {
                "name": f"plugger-review | {app_val} | {env_val} | FOR REVIEW",
                "description": "AI Suggested: FLAGGED — contains insecure/risky protocols. Review before provisioning.",
                "enabled": True,
                "scopes": [scope_labels],
                "rules": review_rules,
            }

        auto_rules.append({
            "app_env": src_g,
            "app": app_val,
            "env": env_val,
            "app_href": app_href,
            "env_href": env_href,
            "services": all_services,
            "clean_services": clean_services,
            "risky_services": risky_services,
            "role_tiers": role_tiers,
            "total_connections": pair["total_connections"],
            "host_count": pair["host_count"],
            # Three tier rulesets
            "tiers": {
                "low": low_ruleset,
                "medium": med_ruleset,
                "high": high_ruleset,
            },
            "review_ruleset": review_ruleset,
            # Default to medium for the provision button
            "ruleset_json": med_ruleset,
            "rule_json": med_rules[0] if med_rules else low_rules[0],
        })

    auto_rules.sort(key=lambda x: -x["total_connections"])
    return auto_rules


def build_inter_scope_suggestions(pce, blocked_pairs):
    """Build policy suggestions for cross app|env blocked traffic.

    Three levels:
    - Level 1: App A ↔ App B (all clean services) — broadest
    - Level 2: App A ↔ App B (only observed services)
    - Level 3: Role@A → Role@B (only observed services) — strictest

    Cross-env traffic always flagged FOR REVIEW.
    """
    value_to_href = {}
    for href, info in label_cache.items():
        value_to_href[(info["key"], info["value"])] = href

    svc_by_port = {}
    try:
        resp = pce.get("/sec_policy/active/services")
        if resp.status_code == 200:
            for svc in resp.json():
                if isinstance(svc, dict):
                    for sp in svc.get("service_ports", []):
                        if isinstance(sp, dict):
                            port = sp.get("port")
                            proto = sp.get("proto")
                            if port and proto:
                                svc_by_port[(port, proto)] = {"href": svc.get("href", ""), "name": svc.get("name", "")}
    except Exception:
        pass

    def build_ingress(svcs):
        result = []
        for s in svcs:
            if s.get("href"):
                result.append({"href": s["href"]})
            else:
                pn = 6 if s["proto"] == "tcp" else 17 if s["proto"] == "udp" else int(s["proto"])
                result.append({"port": s["port"], "proto": pn})
        return result

    inter_rules = []

    for pair in blocked_pairs:
        src_g = pair["src_group"]
        dst_g = pair["dst_group"]

        # Only inter-scope pairs
        if src_g == dst_g:
            continue
        if "|" not in src_g or "|" not in dst_g:
            continue
        if pair["total_connections"] < 50:
            continue

        src_parts = src_g.split("|")
        dst_parts = dst_g.split("|")
        if len(src_parts) != 2 or len(dst_parts) != 2:
            continue

        src_app, src_env = src_parts
        dst_app, dst_env = dst_parts

        # Resolve hrefs
        src_app_href = value_to_href.get(("app", src_app), "")
        src_env_href = value_to_href.get(("env", src_env), "")
        dst_app_href = value_to_href.get(("app", dst_app), "")
        dst_env_href = value_to_href.get(("env", dst_env), "")

        if not all([src_app_href, src_env_href, dst_app_href, dst_env_href]):
            continue

        # Classify risk
        cross_env = src_env != dst_env
        risk_class = "cross-env" if cross_env else "cross-app"
        if cross_env:
            risk_level = "high"
            risk_reason = f"Cross-environment traffic ({src_env} → {dst_env})"
        else:
            risk_level = "medium"
            risk_reason = f"Cross-application traffic in {src_env}"

        # Build services
        all_services = []
        clean_services = []
        risky_services = []
        for svc_str, count in pair["services"]:
            try:
                p, pr = svc_str.split("/")
                port, proto = int(p), int(pr)
                proto_name = PROTO_MAP.get(str(proto), str(proto))
                existing = svc_by_port.get((port, proto))
                entry = {"port": port, "proto": proto_name, "connections": count}
                if existing:
                    entry["href"] = existing["href"]
                    entry["name"] = existing["name"]
                risky, reason = is_risky_service(port, proto_name)
                if risky:
                    entry["risky"] = True
                    entry["risk_reason"] = reason
                    risky_services.append(entry)
                else:
                    clean_services.append(entry)
                all_services.append(entry)
            except (ValueError, IndexError):
                continue

        if not all_services:
            continue

        # Consumer scope (source app|env)
        consumer_scope = [
            {"label": {"href": src_app_href}, "exclusion": False},
            {"label": {"href": src_env_href}, "exclusion": False},
        ]
        # Provider scope (destination app|env)
        provider_scope = [
            {"label": {"href": dst_app_href}, "exclusion": False},
            {"label": {"href": dst_env_href}, "exclusion": False},
        ]

        # ===== LEVEL 1: App A → App B, all clean services =====
        level1_ruleset = {
            "name": f"plugger-auto | {src_app} ({src_env}) → {dst_app} ({dst_env})",
            "description": f"AI Suggested: cross-scope rule (level 1 — app-to-app, all clean services)",
            "enabled": True,
            "scopes": [consumer_scope],  # scoped to consumer side
            "rules": [{
                "enabled": True,
                "consumers": [{"actors": "ams"}],
                "providers": [{"label": {"href": dst_app_href}}, {"label": {"href": dst_env_href}}],
                "ingress_services": build_ingress(clean_services) if clean_services else build_ingress(all_services),
                "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]},
            }],
        }

        # ===== LEVEL 2: App A → App B, observed services only =====
        level2_ruleset = {
            "name": f"plugger-auto | {src_app} ({src_env}) → {dst_app} ({dst_env}) | services",
            "description": f"AI Suggested: cross-scope rule (level 2 — observed services only)",
            "enabled": True,
            "scopes": [consumer_scope],
            "rules": [{
                "enabled": True,
                "consumers": [{"actors": "ams"}],
                "providers": [{"label": {"href": dst_app_href}}, {"label": {"href": dst_env_href}}],
                "ingress_services": build_ingress(clean_services),
                "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]},
            }],
        }

        # ===== LEVEL 3: Role@A → Role@B, observed services =====
        role_tiers = pair.get("role_tiers", [])
        level3_rules = []
        if role_tiers:
            seen = set()
            for tier in role_tiers:
                sr, dr = tier["src_role"], tier["dst_role"]
                if sr == "unknown" or dr == "unknown":
                    continue
                if (sr, dr) in seen:
                    continue
                seen.add((sr, dr))

                sr_href = value_to_href.get(("role", sr), "")
                dr_href = value_to_href.get(("role", dr), "")
                if not sr_href or not dr_href:
                    continue

                tier_svcs = []
                for svc_str, count in tier["services"]:
                    try:
                        p, pr = svc_str.split("/")
                        port, proto = int(p), int(pr)
                        pn = PROTO_MAP.get(str(proto), str(proto))
                        risky, _ = is_risky_service(port, pn)
                        if not risky:
                            existing = svc_by_port.get((port, proto))
                            entry = {"port": port, "proto": pn, "connections": count}
                            if existing:
                                entry["href"] = existing["href"]
                            tier_svcs.append(entry)
                    except (ValueError, IndexError):
                        continue

                if not tier_svcs:
                    continue

                level3_rules.append({
                    "enabled": True,
                    "consumers": [{"label": {"href": sr_href}}],
                    "providers": [{"label": {"href": dr_href}}, {"label": {"href": dst_app_href}}, {"label": {"href": dst_env_href}}],
                    "ingress_services": build_ingress(tier_svcs),
                    "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]},
                })

        level3_ruleset = {
            "name": f"plugger-auto | {src_app} ({src_env}) → {dst_app} ({dst_env}) | strict",
            "description": f"AI Suggested: cross-scope rule (level 3 — role-to-role, observed services)",
            "enabled": True,
            "scopes": [consumer_scope],
            "rules": level3_rules if level3_rules else level2_ruleset["rules"],
        }

        # Review ruleset for risky services
        review_ruleset = None
        if risky_services:
            review_ruleset = {
                "name": f"plugger-review | {src_app} ({src_env}) → {dst_app} ({dst_env}) | FOR REVIEW",
                "description": f"AI Suggested: FLAGGED cross-scope — contains insecure protocols. {risk_reason}.",
                "enabled": True,
                "scopes": [consumer_scope],
                "rules": [{
                    "enabled": True,
                    "consumers": [{"actors": "ams"}],
                    "providers": [{"label": {"href": dst_app_href}}, {"label": {"href": dst_env_href}}],
                    "ingress_services": build_ingress(risky_services),
                    "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]},
                }],
            }

        # Cross-env always gets an extra review flag
        if cross_env and not review_ruleset:
            review_ruleset = {
                "name": f"plugger-review | {src_app} ({src_env}) → {dst_app} ({dst_env}) | CROSS-ENV REVIEW",
                "description": f"AI Suggested: CROSS-ENVIRONMENT traffic. {risk_reason}. Requires explicit approval.",
                "enabled": True,
                "scopes": [consumer_scope],
                "rules": level1_ruleset["rules"],
            }

        inter_rules.append({
            "src_group": src_g,
            "dst_group": dst_g,
            "src_app": src_app,
            "src_env": src_env,
            "dst_app": dst_app,
            "dst_env": dst_env,
            "risk_class": risk_class,
            "risk_level": risk_level,
            "risk_reason": risk_reason,
            "cross_env": cross_env,
            "services": all_services,
            "clean_services": clean_services,
            "risky_services": risky_services,
            "role_tiers": role_tiers,
            "total_connections": pair["total_connections"],
            "host_count": pair["host_count"],
            "tiers": {
                "level1": level1_ruleset,
                "level2": level2_ruleset,
                "level3": level3_ruleset,
            },
            "review_ruleset": review_ruleset,
            "ruleset_json": level2_ruleset,  # default
        })

    inter_rules.sort(key=lambda x: (-1 if x["cross_env"] else 0, -x["total_connections"]))
    return inter_rules


def run_check(pce):
    """Full analysis cycle."""
    if not label_cache:
        fetch_labels(pce)

    try:
        blocked_pairs, blocked_summary = analyze_traffic(pce)
        stale_rules, suggested_rules, auto_rules, stale_summary = find_stale_rules(pce, blocked_pairs)
        inter_rules = build_inter_scope_suggestions(pce, blocked_pairs)

        with state_lock:
            report_state["last_check"] = datetime.now(timezone.utc).isoformat()
            report_state["check_count"] += 1
            report_state["blocked_pairs"] = blocked_pairs
            report_state["blocked_summary"] = blocked_summary
            report_state["stale_rules"] = stale_rules
            report_state["suggested_rules"] = suggested_rules
            report_state["auto_rules"] = auto_rules
            report_state["inter_rules"] = inter_rules
            report_state["stale_summary"] = stale_summary
            report_state["label_count"] = len(label_cache)
            report_state["error"] = None

        log.info("Check #%d: %d blocked pairs (%d connections), %d intra-rules, %d inter-rules, %d stale",
                 report_state["check_count"], len(blocked_pairs),
                 blocked_summary["total_blocked_connections"],
                 len(auto_rules), len(inter_rules), len(stale_rules))

    except Exception as e:
        log.exception("Analysis failed")
        with state_lock:
            report_state["error"] = str(e)


def poller_loop(pce):
    interval = int(os.environ.get("POLL_INTERVAL", "300"))
    while True:
        run_check(pce)
        time.sleep(interval)


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Assisted Rules</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>
tailwind.config = { darkMode: 'class', theme: { extend: { colors: { dark: { 700: '#313244', 800: '#1e1e2e', 900: '#11111b' } } } } }
</script>
<style>
@keyframes fadeIn { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:translateY(0); } }
.fade-in { animation: fadeIn 0.3s ease-out; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #1e1e2e; }
::-webkit-scrollbar-thumb { background: #585b70; border-radius: 3px; }
.tab-active { border-bottom: 2px solid #93c5fd; color: #93c5fd; }
.tab-inactive { border-bottom: 2px solid transparent; color: #6b7280; }
.tab-inactive:hover { color: #9ca3af; }
</style>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen dark">
<div class="max-w-[1400px] mx-auto px-6 py-8">

    <div class="flex items-center justify-between mb-8 fade-in">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <svg class="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/>
                </svg>
                AI Assisted Rules
            </h1>
            <p class="text-gray-500 mt-1">AI-powered policy advisor for Illumio PCE</p>
        </div>
        <div class="flex items-center gap-3">
            <div id="status-dot" class="w-3 h-3 rounded-full bg-gray-600"></div>
            <span id="status-text" class="text-sm text-gray-400">Loading...</span>
        </div>
    </div>

    <!-- Stats -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8" id="stats"></div>

    <!-- Tabs -->
    <div class="flex gap-6 border-b border-gray-700 mb-6">
        <button onclick="showTab('auto')" id="tab-auto" class="pb-3 text-sm font-medium tab-active cursor-pointer">Intra-Scope</button>
        <button onclick="showTab('inter')" id="tab-inter" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Cross-Scope</button>
        <button onclick="showTab('blocked')" id="tab-blocked" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Blocked Traffic</button>
        <button onclick="showTab('chart')" id="tab-chart" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Charts</button>
        <button onclick="showTab('suggested')" id="tab-suggested" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">All Suggestions</button>
        <button onclick="showTab('stale')" id="tab-stale" class="pb-3 text-sm font-medium tab-inactive cursor-pointer">Stale Rules</button>
    </div>

    <div id="panel-auto"></div>
    <div id="panel-inter" style="display:none;"></div>
    <div id="panel-blocked" style="display:none;"></div>
    <div id="panel-suggested" style="display:none;"></div>
    <div id="panel-stale" style="display:none;"></div>
    <div id="panel-chart" style="display:none;">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="bg-dark-800 rounded-xl border border-gray-700 p-6"><h2 class="text-lg font-semibold text-white mb-4">Top Blocked Pairs</h2><div style="height:350px;"><canvas id="chart-blocked"></canvas></div></div>
            <div class="bg-dark-800 rounded-xl border border-gray-700 p-6"><h2 class="text-lg font-semibold text-white mb-4">Blocked Services</h2><div style="height:350px;"><canvas id="chart-services"></canvas></div></div>
        </div>
    </div>

    <div class="text-center text-xs text-gray-600 mt-8">
        <span id="footer"></span> &middot; <a id="api-link" href="/api/report" class="text-blue-500 hover:text-blue-400">JSON API</a>
    </div>
</div>

<script>
const BASE = (() => { const m = window.location.pathname.match(/^(\/plugins\/[^/]+\/ui)/); return m ? m[1] : ''; })();
const tabs = ['auto','inter','blocked','chart','suggested','stale'];
let chartBlocked, chartServices;

function showTab(name) {
    tabs.forEach(t => {
        document.getElementById('panel-'+t).style.display = t===name?'block':'none';
        document.getElementById('tab-'+t).className = 'pb-3 text-sm font-medium cursor-pointer '+(t===name?'tab-active':'tab-inactive');
    });
}

function formatNum(n) {
    if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
    if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
    return n.toLocaleString();
}

function initCharts() {
    const barOpts = {
        responsive:true, maintainAspectRatio:false, indexAxis:'y',
        plugins: { legend:{display:false}, tooltip:{backgroundColor:'#1e1e2e',borderColor:'#313244',borderWidth:1,titleColor:'#cdd6f4',bodyColor:'#a6adc8',padding:12,cornerRadius:8} },
        scales: { x:{grid:{color:'#31324422'},ticks:{color:'#6b7280',callback:v=>formatNum(v)}}, y:{grid:{display:false},ticks:{color:'#a6adc8',font:{size:11,family:'monospace'}}} }
    };
    chartBlocked = new Chart(document.getElementById('chart-blocked'), {
        type:'bar', data:{labels:[],datasets:[{data:[],backgroundColor:'#ef444444',borderColor:'#ef4444',borderWidth:1,borderRadius:4}]}, options:barOpts
    });
    chartServices = new Chart(document.getElementById('chart-services'), {
        type:'bar', data:{labels:[],datasets:[{data:[],backgroundColor:'#f9731644',borderColor:'#f97316',borderWidth:1,borderRadius:4}]}, options:barOpts
    });
}

function severityColor(s) { return s==='high'?'red':s==='warning'?'yellow':'blue'; }

function update(data) {
    const bs = data.blocked_summary || {};
    const ss = data.stale_summary || {};

    // Stats
    document.getElementById('stats').innerHTML = `
        <div class="bg-dark-800 rounded-xl border border-red-900/30 p-5 fade-in"><div class="text-3xl font-bold text-red-400">${formatNum(bs.total_blocked_connections||0)}</div><div class="text-xs text-gray-500 mt-1">Blocked Connections</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in"><div class="text-3xl font-bold text-orange-400">${bs.unique_pairs||0}</div><div class="text-xs text-gray-500 mt-1">Blocked App|Env Pairs</div></div>
        <div class="bg-dark-800 rounded-xl border border-emerald-900/30 p-5 fade-in"><div class="text-3xl font-bold text-emerald-400">${(data.auto_rules||[]).length}</div><div class="text-xs text-gray-500 mt-1">AI Suggested Rules</div></div>
        <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in"><div class="text-3xl font-bold text-gray-400">${(data.stale_rules||[]).length}</div><div class="text-xs text-gray-500 mt-1">Stale/Disabled Rules</div></div>
    `;

    // Status
    if (data.error) {
        document.getElementById('status-dot').className='w-3 h-3 rounded-full bg-red-500';
        document.getElementById('status-text').textContent='Error';
    } else {
        document.getElementById('status-dot').className='w-3 h-3 rounded-full bg-green-500 animate-pulse';
        document.getElementById('status-text').textContent='Live';
    }

    // Blocked pairs table
    const pairs = data.blocked_pairs || [];
    document.getElementById('panel-blocked').innerHTML = pairs.length ? `
        <div class="bg-dark-800 rounded-xl border border-gray-700 overflow-hidden">
            <table class="w-full text-sm">
                <thead><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
                    <th class="px-4 py-3">Source (app|env)</th><th class="px-4 py-3">Destination (app|env)</th>
                    <th class="px-4 py-3">Services</th><th class="px-4 py-3 text-right">Connections</th><th class="px-4 py-3 text-right">Hosts</th>
                </tr></thead>
                <tbody>${pairs.map(p => `
                    <tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
                        <td class="px-4 py-2.5"><code class="text-xs bg-red-900/20 text-red-300 px-1.5 py-0.5 rounded">${p.src_group}</code></td>
                        <td class="px-4 py-2.5"><code class="text-xs bg-orange-900/20 text-orange-300 px-1.5 py-0.5 rounded">${p.dst_group}</code></td>
                        <td class="px-4 py-2.5"><span class="text-xs text-gray-400">${p.services.map(s=>s[0]).join(', ')}</span></td>
                        <td class="px-4 py-2.5 text-right font-mono text-red-400">${formatNum(p.total_connections)}</td>
                        <td class="px-4 py-2.5 text-right text-gray-500">${p.host_count}</td>
                    </tr>
                `).join('')}</tbody>
            </table>
        </div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">No Blocked Traffic</div><div class="text-gray-500 mt-2">No blocked or potentially blocked flows in the last '+bs.lookback_hours+'h.</div></div>';

    // Suggested rules
    const suggested = data.suggested_rules || [];
    document.getElementById('panel-suggested').innerHTML = suggested.length ? `
        <div class="space-y-3">${suggested.map(s => `
            <div class="bg-dark-800 rounded-xl border border-${severityColor(s.severity)}-900/30 p-4">
                <div class="flex items-center gap-3 mb-2">
                    <span class="px-2 py-0.5 rounded text-xs font-medium bg-${severityColor(s.severity)}-900/50 text-${severityColor(s.severity)}-400">${s.severity}</span>
                    <span class="text-white font-medium"><code>${s.src}</code> → <code>${s.dst}</code></span>
                    <span class="text-gray-500 text-xs ml-auto">${formatNum(s.connections)} connections</span>
                </div>
                <div class="text-sm text-gray-400">${s.reason}</div>
                <div class="flex gap-1 mt-2">${s.services.map(svc => `<span class="text-xs bg-dark-700 text-gray-400 px-1.5 py-0.5 rounded">${svc}</span>`).join('')}</div>
            </div>
        `).join('')}</div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">No Suggestions</div><div class="text-gray-500 mt-2">No high-volume blocked traffic patterns detected.</div></div>';

    // AI Suggested rules (intra app|env)
    const autoRules = data.auto_rules || [];
    const analyses = data.ai_analyses || {};
    const aiEnabled = data.ai_config && data.ai_config.enabled;
    document.getElementById('panel-auto').innerHTML = autoRules.length ? `
        <div class="flex items-center justify-between mb-4">
            <div class="flex items-center gap-2">
                <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
                <h2 class="text-lg font-semibold text-white">AI Suggested Rules</h2>
                ${aiEnabled ? `<span class="text-xs bg-emerald-900/40 text-emerald-400 px-2 py-0.5 rounded">AI: ${data.ai_config.provider} / ${data.ai_config.model}</span>` : '<span class="text-xs bg-gray-700 text-gray-400 px-2 py-0.5 rounded">AI not configured</span>'}
            </div>
            ${aiEnabled ? `<button onclick="analyzeAll()" class="px-3 py-1.5 text-xs rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition-colors">Analyze All with AI</button>` : ''}
        </div>
        <div class="space-y-4">${autoRules.map((r, i) => {
            const a = analyses[String(i)] || {};
            const hasAI = a.recommendation;
            const provisioned = a.provisioned;
            const recColor = a.recommendation === 'approve' ? 'emerald' : a.recommendation === 'reject' ? 'red' : 'yellow';
            const riskColor = a.risk_level === 'low' ? 'emerald' : a.risk_level === 'high' ? 'red' : 'yellow';
            return `
            <div class="bg-dark-800 rounded-xl border ${hasAI ? (a.recommendation === 'approve' ? 'border-emerald-900/50' : a.recommendation === 'reject' ? 'border-red-900/50' : 'border-yellow-900/50') : 'border-gray-700'} p-5" id="rule-card-${i}">
                <div class="flex items-center justify-between mb-3">
                    <div class="flex items-center gap-3">
                        <span class="px-2.5 py-1 rounded-lg text-sm font-semibold bg-emerald-900/40 text-emerald-400">${r.app_env}</span>
                        <span class="text-gray-400 text-sm">Intra-scope rule</span>
                        ${hasAI ? `<span class="px-2 py-0.5 rounded text-xs font-medium bg-${recColor}-900/50 text-${recColor}-400">AI: ${a.recommendation.toUpperCase()}</span>` : ''}
                        ${hasAI ? `<span class="px-2 py-0.5 rounded text-xs bg-${riskColor}-900/30 text-${riskColor}-400">Risk: ${a.risk_level}</span>` : ''}
                        ${provisioned && provisioned.success ? '<span class="px-2 py-0.5 rounded text-xs bg-blue-900/50 text-blue-400">Provisioned to Draft</span>' : ''}
                    </div>
                    <div class="flex items-center gap-3 text-xs text-gray-500">
                        <span>${formatNum(r.total_connections)} blocked</span>
                        <span>${r.host_count} hosts</span>
                        ${hasAI && a.confidence ? `<span>Confidence: ${Math.round(a.confidence * 100)}%</span>` : ''}
                    </div>
                </div>
                <div class="flex flex-wrap gap-1.5 mb-2">
                    ${(r.clean_services||r.services).map(s => `<span class="text-xs px-2 py-0.5 rounded ${s.name ? 'bg-blue-900/30 text-blue-300' : 'bg-dark-700 text-gray-400'}">${s.name || s.port+'/'+s.proto} <span class="text-gray-500">(${formatNum(s.connections)})</span></span>`).join('')}
                </div>
                ${(r.risky_services||[]).length ? `<div class="flex flex-wrap gap-1.5 mb-3">
                    <span class="text-xs text-red-400 font-medium">Flagged:</span>
                    ${r.risky_services.map(s => `<span class="text-xs px-2 py-0.5 rounded bg-red-900/30 text-red-400" title="${s.risk_reason||''}">${s.name || s.port+'/'+s.proto} ⚠</span>`).join('')}
                </div>` : ''}
                ${(r.role_tiers||[]).length > 1 ? `<div class="mb-3 text-xs text-gray-500">
                    Role tiers: ${r.role_tiers.filter(t=>t.src_role!=='unknown').slice(0,5).map(t => `<span class="text-gray-400">${t.src_role}→${t.dst_role}</span>`).join(', ')}
                </div>` : ''}
                ${hasAI ? `
                <div class="bg-dark-700/30 rounded-lg p-3 mb-3 border-l-2 border-${recColor}-500">
                    <div class="text-sm text-gray-300 mb-1">${a.reasoning}</div>
                    ${a.suggested_modifications ? `<div class="text-xs text-${recColor}-400 mt-1">Suggestion: ${a.suggested_modifications}</div>` : ''}
                </div>` : ''}
                <div class="flex items-center gap-2 flex-wrap">
                    ${aiEnabled && !hasAI ? `<button onclick="analyzeRule(${i})" id="ai-btn-${i}" class="px-3 py-1.5 text-xs rounded-lg bg-emerald-700 hover:bg-emerald-600 text-white transition-colors flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
                        AI Analyze</button>` : ''}
                    ${!provisioned || !provisioned.success ? `
                        <span class="text-xs text-gray-500 ml-1">Provision:</span>
                        <button onclick="provisionTier(${i},'low')" class="px-2 py-1 text-xs rounded bg-green-800 hover:bg-green-700 text-green-200 transition-colors" title="All workloads ↔ All workloads, all clean services">Low</button>
                        <button onclick="provisionTier(${i},'medium')" class="px-2 py-1 text-xs rounded bg-blue-800 hover:bg-blue-700 text-blue-200 transition-colors" title="Role → Role, all services per tier">Medium</button>
                        <button onclick="provisionTier(${i},'high')" class="px-2 py-1 text-xs rounded bg-purple-800 hover:bg-purple-700 text-purple-200 transition-colors" title="Role → Role, only observed services">High</button>
                    ` : `<span class="text-xs text-blue-400">✓ Provisioned</span>`}
                    ${(r.risky_services||[]).length && (!provisioned || !provisioned.success) ? `<button onclick="provisionTier(${i},'review')" class="px-2 py-1 text-xs rounded bg-red-900 hover:bg-red-800 text-red-200 transition-colors" title="Provision risky services as FOR REVIEW">+ Review</button>` : ''}
                    <button onclick="toggleJSON(${i})" class="px-2 py-1 text-xs rounded bg-dark-700 text-gray-400 hover:bg-dark-700/80 transition-colors">JSON</button>
                </div>
                <div id="json-${i}" style="display:none;" class="mt-3">
                    <div class="flex gap-2 mb-2">
                        <button onclick="showTierJSON(${i},'low')" class="text-xs text-green-400 hover:text-green-300">Low</button>
                        <button onclick="showTierJSON(${i},'medium')" class="text-xs text-blue-400 hover:text-blue-300">Medium</button>
                        <button onclick="showTierJSON(${i},'high')" class="text-xs text-purple-400 hover:text-purple-300">High</button>
                        ${r.review_ruleset ? `<button onclick="showTierJSON(${i},'review')" class="text-xs text-red-400 hover:text-red-300">Review</button>` : ''}
                    </div>
                    <div class="bg-dark-900 rounded-lg p-3 overflow-x-auto">
                        <pre id="json-pre-${i}" class="text-xs text-gray-300 font-mono whitespace-pre">${JSON.stringify(r.tiers?.medium || r.ruleset_json, null, 2)}</pre>
                    </div>
                </div>
                ${provisioned && !provisioned.success ? `<div class="mt-2 text-xs text-red-400">Error: ${provisioned.error}</div>` : ''}
            </div>`;
        }).join('')}</div>
        <div class="mt-4 p-4 bg-dark-800 rounded-xl border border-gray-700">
            <p class="text-xs text-gray-500">AI Suggested rules allow workloads within the same app|env scope to communicate on observed blocked ports. "Provision to Draft" creates the ruleset in PCE draft policy — you must still provision from the PCE to activate.</p>
        </div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">No AI Suggestions</div><div class="text-gray-500 mt-2">No intra-app|env blocked traffic detected.</div></div>';

    // Cross-scope rules
    const interRules = data.inter_rules || [];
    const interAnalyses = data.ai_analyses || {};
    document.getElementById('panel-inter').innerHTML = interRules.length ? `
        <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold text-white">Cross-Scope Traffic (${interRules.length} pairs)</h2>
            <div class="flex gap-2 text-xs">
                <span class="px-2 py-0.5 rounded bg-yellow-900/30 text-yellow-400">${interRules.filter(r=>!r.cross_env).length} same-env</span>
                <span class="px-2 py-0.5 rounded bg-red-900/30 text-red-400">${interRules.filter(r=>r.cross_env).length} cross-env</span>
            </div>
        </div>
        <div class="space-y-3">${interRules.map((r, i) => {
            const idx = 'inter_'+i;
            const a = interAnalyses[idx] || {};
            const hasAI = a.recommendation;
            const provisioned = a.provisioned;
            const envColor = r.cross_env ? 'red' : 'yellow';
            const recColor = a.recommendation === 'approve' ? 'emerald' : a.recommendation === 'reject' ? 'red' : 'yellow';
            return `
            <div class="bg-dark-800 rounded-xl border border-${envColor}-900/30 p-4">
                <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-2 flex-wrap">
                        <code class="text-xs bg-${envColor}-900/20 text-${envColor}-300 px-1.5 py-0.5 rounded">${r.src_group}</code>
                        <span class="text-gray-500">→</span>
                        <code class="text-xs bg-${envColor}-900/20 text-${envColor}-300 px-1.5 py-0.5 rounded">${r.dst_group}</code>
                        <span class="px-1.5 py-0.5 rounded text-xs bg-${envColor}-900/40 text-${envColor}-400">${r.risk_class}</span>
                        ${hasAI ? `<span class="px-1.5 py-0.5 rounded text-xs bg-${recColor}-900/50 text-${recColor}-400">AI: ${a.recommendation}</span>` : ''}
                        ${provisioned && provisioned.success ? '<span class="px-1.5 py-0.5 rounded text-xs bg-blue-900/50 text-blue-400">Provisioned</span>' : ''}
                    </div>
                    <span class="text-xs text-gray-500">${formatNum(r.total_connections)} conns, ${r.host_count} hosts</span>
                </div>
                <div class="flex flex-wrap gap-1 mb-2">
                    ${(r.clean_services||[]).map(s => `<span class="text-xs px-1.5 py-0.5 rounded bg-dark-700 text-gray-400">${s.name||s.port+'/'+s.proto}</span>`).join('')}
                    ${(r.risky_services||[]).map(s => `<span class="text-xs px-1.5 py-0.5 rounded bg-red-900/30 text-red-400">${s.name||s.port+'/'+s.proto} ⚠</span>`).join('')}
                </div>
                ${r.risk_reason ? `<div class="text-xs text-${envColor}-400 mb-2">${r.risk_reason}</div>` : ''}
                ${hasAI ? `<div class="bg-dark-700/30 rounded p-2 mb-2 border-l-2 border-${recColor}-500 text-sm text-gray-300">${a.reasoning}${a.suggested_modifications ? '<br><span class=text-xs>'+a.suggested_modifications+'</span>' : ''}</div>` : ''}
                <div class="flex items-center gap-2 flex-wrap">
                    ${aiEnabled && !hasAI ? `<button onclick="analyzeInter(${i})" class="px-2 py-1 text-xs rounded bg-emerald-700 hover:bg-emerald-600 text-white transition-colors">AI Analyze</button>` : ''}
                    ${!provisioned || !provisioned.success ? `
                        <span class="text-xs text-gray-500">Provision:</span>
                        <button onclick="provisionInter(${i},'level1')" class="px-2 py-1 text-xs rounded bg-green-800 hover:bg-green-700 text-green-200" title="App A ↔ App B, all clean services">L1: Apps</button>
                        <button onclick="provisionInter(${i},'level2')" class="px-2 py-1 text-xs rounded bg-blue-800 hover:bg-blue-700 text-blue-200" title="App A ↔ App B, observed services">L2: Services</button>
                        <button onclick="provisionInter(${i},'level3')" class="px-2 py-1 text-xs rounded bg-purple-800 hover:bg-purple-700 text-purple-200" title="Role → Role, observed services">L3: Roles</button>
                    ` : ''}
                    ${r.review_ruleset && (!provisioned || !provisioned.success) ? `<button onclick="provisionInter(${i},'review')" class="px-2 py-1 text-xs rounded bg-red-900 hover:bg-red-800 text-red-200">+ Review</button>` : ''}
                </div>
            </div>`;
        }).join('')}</div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">No Cross-Scope Traffic</div><div class="text-gray-500 mt-2">No blocked traffic between different applications detected.</div></div>';

    // Stale rules
    const stale = data.stale_rules || [];
    document.getElementById('panel-stale').innerHTML = stale.length ? `
        <div class="space-y-2">${stale.map(s => `
            <div class="bg-dark-800 rounded-xl border border-gray-700 p-4 flex items-center gap-3">
                <span class="px-2 py-0.5 rounded text-xs font-medium bg-${severityColor(s.severity)}-900/50 text-${severityColor(s.severity)}-400">${s.severity}</span>
                <span class="text-white font-medium">${s.ruleset}</span>
                <span class="text-sm text-gray-400">${s.reason}</span>
            </div>
        `).join('')}</div>
    ` : '<div class="bg-dark-800 rounded-xl border border-green-900/30 p-12 text-center"><div class="text-xl font-semibold text-green-400">All Rules Active</div><div class="text-gray-500 mt-2">No disabled or empty rulesets found.</div></div>';

    // Charts
    const topPairs = pairs.slice(0, 10);
    chartBlocked.data.labels = topPairs.map(p => p.src_group + ' → ' + p.dst_group);
    chartBlocked.data.datasets[0].data = topPairs.map(p => p.total_connections);
    chartBlocked.update('none');

    const svcCounter = {};
    pairs.forEach(p => p.services.forEach(([svc, count]) => { svcCounter[svc] = (svcCounter[svc]||0) + count; }));
    const topSvcs = Object.entries(svcCounter).sort((a,b) => b[1]-a[1]).slice(0, 10);
    chartServices.data.labels = topSvcs.map(s => s[0]);
    chartServices.data.datasets[0].data = topSvcs.map(s => s[1]);
    chartServices.update('none');

    document.getElementById('footer').textContent = `Check #${data.check_count} · ${data.last_check ? new Date(data.last_check).toLocaleTimeString() : 'never'} · ${data.label_count} labels cached`;
}

async function fetchData() {
    try { const d = await (await fetch(BASE + '/api/report')).json(); window._lastData = d; update(d); } catch(e) { console.error(e); }
}

function toggleJSON(i) {
    const el = document.getElementById('json-'+i);
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

async function analyzeRule(index) {
    const btn = document.getElementById('ai-btn-'+index);
    if (btn) { btn.textContent = 'Analyzing...'; btn.disabled = true; }
    try {
        const resp = await fetch(BASE + '/api/ai/analyze', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({index: index})
        });
        const result = await resp.json();
        if (result.error) { alert('AI Error: ' + result.error); return; }
        await fetchData(); // refresh to show result
    } catch(e) { alert('AI request failed: ' + e); }
    finally { if (btn) { btn.textContent = 'AI Analyze'; btn.disabled = false; } }
}

async function analyzeAll() {
    const rules = (window._lastData || {}).auto_rules || [];
    for (let i = 0; i < rules.length; i++) {
        const a = (window._lastData.ai_analyses || {})[String(i)];
        if (!a || !a.recommendation) {
            await analyzeRule(i);
            await new Promise(r => setTimeout(r, 500)); // small delay between calls
        }
    }
}

function showTierJSON(index, tier) {
    const r = (window._lastData || {}).auto_rules[index];
    if (!r) return;
    const data = tier === 'review' ? r.review_ruleset : (r.tiers || {})[tier] || r.ruleset_json;
    document.getElementById('json-pre-'+index).textContent = JSON.stringify(data, null, 2);
}

async function provisionTier(index, tier) {
    const tierNames = {low:'Low Security',medium:'Medium Security',high:'High Security',review:'FOR REVIEW'};
    if (!confirm(`Provision ${tierNames[tier]||tier} rule to PCE draft?`)) return;
    try {
        const resp = await fetch(BASE + '/api/provision/' + index + '/' + tier, {
            method: 'POST', headers: {'Content-Type':'application/json'}
        });
        const result = await resp.json();
        if (result.success) {
            alert('Provisioned to draft: ' + result.name);
        } else {
            alert('Provision failed: ' + result.error);
        }
        await fetchData();
    } catch(e) { alert('Provision failed: ' + e); }
}

async function provisionRule(index) {
    const btn = document.getElementById('prov-btn-'+index);
    if (!confirm('Provision this AI Suggested rule to PCE draft policy?')) return;
    if (btn) { btn.textContent = 'Provisioning...'; btn.disabled = true; }
    try {
        const resp = await fetch(BASE + '/api/provision/' + index, {
            method: 'POST', headers: {'Content-Type':'application/json'}
        });
        const result = await resp.json();
        if (result.success) {
            alert('Provisioned to draft: ' + result.name);
        } else {
            alert('Provision failed: ' + result.error);
        }
        await fetchData();
    } catch(e) { alert('Provision failed: ' + e); }
    finally { if (btn) { btn.textContent = 'Provision to Draft'; btn.disabled = false; } }
}

async function analyzeInter(index) {
    try {
        const resp = await fetch(BASE + '/api/ai/analyze', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({index: index, scope: 'inter'})
        });
        const result = await resp.json();
        if (result.error) { alert('AI Error: ' + result.error); return; }
        await fetchData();
    } catch(e) { alert('AI failed: ' + e); }
}

async function provisionInter(index, tier) {
    const tierNames = {level1:'Level 1 (App→App)',level2:'Level 2 (Services)',level3:'Level 3 (Roles)',review:'FOR REVIEW'};
    if (!confirm(`Provision ${tierNames[tier]||tier} cross-scope rule to PCE draft?`)) return;
    try {
        const resp = await fetch(BASE + '/api/provision/inter/' + index + '/' + tier, {
            method: 'POST', headers: {'Content-Type':'application/json'}
        });
        const result = await resp.json();
        if (result.success) alert('Provisioned: ' + result.name);
        else alert('Failed: ' + result.error);
        await fetchData();
    } catch(e) { alert('Failed: ' + e); }
}

initCharts();
document.getElementById('api-link').href = BASE + '/api/report';
fetchData();
setInterval(fetchData, 30000);
</script>
</body></html>"""


# ============================================================
# AI Advisor + Provisioning
# ============================================================

ai_advisor = None
pce_client = None
ai_analyses = {}  # index -> analysis result


def provision_rule(pce, ruleset_json):
    """Provision a ruleset to PCE draft policy."""
    try:
        # POST to create draft ruleset
        resp = pce.post("/sec_policy/draft/rule_sets", json=ruleset_json)
        if resp.status_code in (200, 201):
            result = resp.json()
            href = result.get("href", "")
            log.info("Provisioned ruleset to draft: %s", href)
            return {"success": True, "href": href, "name": ruleset_json.get("name", "")}
        else:
            error = resp.text[:200]
            log.error("Provision failed: HTTP %d: %s", resp.status_code, error)
            return {"success": False, "error": f"HTTP {resp.status_code}: {error}"}
    except Exception as e:
        log.error("Provision error: %s", e)
        return {"success": False, "error": str(e)}


class ReportHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "healthy"})
        elif self.path == "/api/report":
            with state_lock:
                data = dict(report_state)
            data["ai_analyses"] = ai_analyses
            data["ai_config"] = ai_advisor.get_config() if ai_advisor else {"enabled": False}
            self.send_json(200, data)
        elif self.path == "/api/ai/config":
            self.send_json(200, ai_advisor.get_config() if ai_advisor else {"enabled": False})
        elif self.path == "/":
            body = DASHBOARD_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if self.path == "/api/ai/analyze":
            self.handle_ai_analyze(body)
        elif self.path.startswith("/api/provision/"):
            self.handle_provision(body)
        else:
            self.send_error(404)

    def handle_ai_analyze(self, body):
        """AI-analyze a specific rule by index. Supports scope=inter for cross-scope."""
        try:
            req = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_json(400, {"error": "Invalid JSON"})
            return

        index = req.get("index", -1)
        scope = req.get("scope", "intra")

        with state_lock:
            if scope == "inter":
                rules_list = report_state.get("inter_rules", [])
            else:
                rules_list = report_state.get("auto_rules", [])

        if index < 0 or index >= len(rules_list):
            self.send_json(400, {"error": f"Invalid index {index}"})
            return

        if not ai_advisor or not ai_advisor.is_enabled():
            self.send_json(400, {"error": "AI not configured. Set AI_PROVIDER and AI_API_KEY environment variables."})
            return

        rule = rules_list[index]
        lookback = report_state.get("blocked_summary", {}).get("lookback_hours", 24)

        name = rule.get("app_env", rule.get("src_group", "?"))
        log.info("AI analyzing (%s): %s (%d connections)", scope, name, rule["total_connections"])
        result = ai_advisor.analyze(rule, lookback_hours=lookback)
        key = f"inter_{index}" if scope == "inter" else str(index)
        ai_analyses[key] = result

        self.send_json(200, result)

    def handle_provision(self, body):
        """Provision a rule to PCE draft. Supports intra and inter scope."""
        # Parse path: /api/provision/{index}/{tier} or /api/provision/inter/{index}/{tier}
        path_parts = self.path.rstrip("/").split("/")
        # /api/provision/inter/{index}/{tier} or /api/provision/{index}/{tier}
        is_inter = "inter" in path_parts

        try:
            if is_inter:
                # /api/provision/inter/{index}/{tier}
                idx_pos = path_parts.index("inter") + 1
                index = int(path_parts[idx_pos])
                tier = path_parts[idx_pos + 1] if len(path_parts) > idx_pos + 1 else "level2"
            else:
                index = int(path_parts[3])
                tier = path_parts[4] if len(path_parts) > 4 else "medium"
        except (ValueError, IndexError):
            self.send_json(400, {"error": "Invalid path"})
            return

        with state_lock:
            if is_inter:
                auto_rules = report_state.get("inter_rules", [])
            else:
                auto_rules = report_state.get("auto_rules", [])

        if index < 0 or index >= len(auto_rules):
            self.send_json(400, {"error": f"Invalid index {index}"})
            return

        rule = auto_rules[index]
        results = []

        if tier == "review":
            # Provision only the review ruleset
            review_rs = rule.get("review_ruleset")
            if not review_rs:
                self.send_json(400, {"error": "No risky services to review"})
                return
            log.info("Provisioning FOR REVIEW: %s", review_rs.get("name", ""))
            results.append(provision_rule(pce_client, review_rs))
        else:
            # Provision the selected tier
            tiers = rule.get("tiers", {})
            ruleset_json = tiers.get(tier, rule.get("ruleset_json", {}))
            if not ruleset_json:
                self.send_json(400, {"error": f"No ruleset for tier '{tier}'"})
                return
            log.info("Provisioning %s tier: %s", tier, ruleset_json.get("name", ""))
            results.append(provision_rule(pce_client, ruleset_json))

            # Also provision review ruleset if it exists and tier != low
            if tier != "low" and rule.get("review_ruleset"):
                review_rs = rule["review_ruleset"]
                log.info("Provisioning FOR REVIEW: %s", review_rs.get("name", ""))
                results.append(provision_rule(pce_client, review_rs))

        # Store provision status
        key = f"inter_{index}" if is_inter else str(index)
        if key not in ai_analyses:
            ai_analyses[key] = {}
        ai_analyses[key]["provisioned"] = results[0]
        if len(results) > 1:
            ai_analyses[key]["review_provisioned"] = results[1]

        result = results[0]

        self.send_json(200, result)

    def send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    global ai_advisor, pce_client

    log.info("Starting AI Assisted Rules...")
    port = int(os.environ.get("HTTP_PORT", "8080"))

    pce_client = get_pce()
    log.info("Connected to PCE: %s", pce_client.base_url)

    # Initialize AI advisor
    from ai_advisor import AIAdvisor
    ai_advisor = AIAdvisor()

    poller = threading.Thread(target=poller_loop, args=(pce_client,), daemon=True)
    poller.start()
    run_check(pce_client)

    server = HTTPServer(("0.0.0.0", port), ReportHandler)
    log.info("Dashboard on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
