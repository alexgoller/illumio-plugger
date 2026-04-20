#!/usr/bin/env python3
"""
Policy Resolver — Resolve Illumio label-based policy into IP-level firewall rules.

Takes abstract Illumio policy (rulesets scoped by labels, rules with label-based
providers/consumers) and resolves every rule to concrete:
  source IPs × destination IPs × port/protocol

Output is a flat list of firewall-style rules suitable for implementation on
network firewalls, ACLs, or security groups.
"""

import json
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from illumio import PolicyComputeEngine

# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("policy-resolver")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "600"))
RESOLVE_DRAFT = os.environ.get("RESOLVE_DRAFT", "false").lower() == "true"
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
report_state = {
    "last_resolve": None,
    "resolve_count": 0,
    "resolving": False,
    "error": None,
    "resolve_requested": False,
    "resolved_rules": [],
    "summary": {},
    "rulesets_resolved": 0,
    "rules_resolved": 0,
    "total_ip_rules": 0,
    "policy_scope": "active",
}

label_cache = {}     # href -> {key, value}
ip_list_cache = {}   # href -> {name, ip_ranges: [{from_ip, to_ip, exclusion},...], fqdns: [...]}
service_cache = {}   # href -> {name, port, proto, to_port}
workload_cache = []  # full workload list
label_group_cache = {}  # href -> {name, key, labels: [{href},...], sub_groups: [{href},...]}


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


def fetch_all_data(pce):
    """Fetch labels, workloads, IP lists, services, and policy."""
    global label_cache, ip_list_cache, service_cache, workload_cache

    # Labels
    try:
        resp = pce.get("/labels")
        labels = resp.json() if resp.status_code == 200 else []
        label_cache = {}
        for lbl in labels:
            label_cache[lbl.get("href", "")] = {"key": lbl.get("key", ""), "value": lbl.get("value", "")}
        log.info("Fetched %d labels", len(labels))
    except Exception as e:
        log.error("Failed to fetch labels: %s", e)

    # Workloads
    try:
        resp = pce.get("/workloads", params={"max_results": 10000})
        workload_cache = resp.json() if resp.status_code == 200 else []
        log.info("Fetched %d workloads", len(workload_cache))
    except Exception as e:
        log.error("Failed to fetch workloads: %s", e)
        workload_cache = []

    # Label Groups
    scope = "draft" if RESOLVE_DRAFT else "active"
    try:
        resp = pce.get(f"/sec_policy/{scope}/label_groups")
        lgs = resp.json() if resp.status_code == 200 else []
        global label_group_cache
        label_group_cache = {}
        for lg in lgs:
            href = lg.get("href", "")
            label_group_cache[href] = {
                "name": lg.get("name", ""),
                "key": lg.get("key", ""),
                "labels": lg.get("labels", []),
                "sub_groups": lg.get("sub_groups", []),
            }
        log.info("Fetched %d label groups", len(lgs))
    except Exception as e:
        log.error("Failed to fetch label groups: %s", e)

    # IP Lists
    try:
        resp = pce.get(f"/sec_policy/{scope}/ip_lists")
        ip_lists = resp.json() if resp.status_code == 200 else []
        ip_list_cache = {}
        for ipl in ip_lists:
            href = ipl.get("href", "")
            ranges = []
            for r in ipl.get("ip_ranges", []):
                ranges.append({
                    "from_ip": r.get("from_ip", ""),
                    "to_ip": r.get("to_ip", ""),
                    "exclusion": r.get("exclusion", False),
                    "description": r.get("description", ""),
                })
            fqdns = [f.get("fqdn", "") for f in ipl.get("fqdns", [])]
            ip_list_cache[href] = {
                "name": ipl.get("name", ""),
                "href": href,
                "ip_ranges": ranges,
                "fqdns": fqdns,
            }
        log.info("Fetched %d IP lists", len(ip_lists))
    except Exception as e:
        log.error("Failed to fetch IP lists: %s", e)

    # Services
    try:
        resp = pce.get(f"/sec_policy/{scope}/services")
        services = resp.json() if resp.status_code == 200 else []
        service_cache = {}
        for svc in services:
            href = svc.get("href", "")
            ports = []
            for sp in svc.get("service_ports", []):
                ports.append({
                    "port": sp.get("port", -1),
                    "to_port": sp.get("to_port", 0),
                    "proto": sp.get("proto", 6),
                })
            service_cache[href] = {
                "name": svc.get("name", ""),
                "href": href,
                "ports": ports,
            }
        log.info("Fetched %d services", len(services))
    except Exception as e:
        log.error("Failed to fetch services: %s", e)

    # Rulesets
    try:
        resp = pce.get(f"/sec_policy/{scope}/rule_sets", params={"max_results": 5000})
        rulesets = resp.json() if resp.status_code == 200 else []
        log.info("Fetched %d rulesets from %s policy", len(rulesets), scope)
        return rulesets
    except Exception as e:
        log.error("Failed to fetch rulesets: %s", e)
        return []


# ---------------------------------------------------------------------------
# Workload matching
# ---------------------------------------------------------------------------

def get_workload_labels(wl):
    """Return {key: value} dict of a workload's labels."""
    labels = {}
    for lbl in wl.get("labels", []):
        href = lbl.get("href", "")
        resolved = label_cache.get(href, {})
        if resolved:
            labels[resolved["key"]] = resolved["value"]
    return labels


def get_workload_ips(wl):
    """Return list of IP addresses for a workload."""
    ips = []
    for iface in wl.get("interfaces", []):
        addr = iface.get("address", "")
        if addr:
            ips.append(addr)
    return ips


def workloads_matching_labels(label_constraints):
    """
    Find all workloads matching a set of label constraints.
    label_constraints: list of {key, value} dicts — all must match (AND).
    Returns list of workloads.
    """
    if not label_constraints:
        return []

    matching = []
    for wl in workload_cache:
        wl_labels = get_workload_labels(wl)
        all_match = True
        for constraint in label_constraints:
            key = constraint.get("key", "")
            value = constraint.get("value", "")
            if wl_labels.get(key) != value:
                all_match = False
                break
        if all_match:
            matching.append(wl)
    return matching


def resolve_scope_labels(scope_entry):
    """
    Resolve a ruleset scope entry to label constraints.
    scope_entry: list of {label: {href: ...}, exclusion: bool}
    Returns list of {key, value} for matching.
    """
    constraints = []
    for item in scope_entry:
        lbl_href = ""
        if isinstance(item, dict):
            lbl = item.get("label", {})
            if isinstance(lbl, dict):
                lbl_href = lbl.get("href", "")
            excl = item.get("exclusion", False)
            if excl:
                continue  # Skip exclusions for now
        resolved = label_cache.get(lbl_href, {})
        if resolved:
            constraints.append({"key": resolved["key"], "value": resolved["value"]})
    return constraints


# ---------------------------------------------------------------------------
# Actor resolution
# ---------------------------------------------------------------------------

def expand_label_group(lg_href, visited=None):
    """Recursively expand a label group to all member label hrefs."""
    if visited is None:
        visited = set()
    if lg_href in visited:
        return []
    visited.add(lg_href)

    lg = label_group_cache.get(lg_href)
    if not lg:
        return []

    hrefs = []
    for lbl in lg.get("labels", []):
        href = lbl.get("href", "")
        if href:
            hrefs.append(href)

    for sub in lg.get("sub_groups", []):
        sub_href = sub.get("href", "")
        if sub_href:
            hrefs.extend(expand_label_group(sub_href, visited))

    return hrefs


def resolve_actors(actors, scope_constraints=None):
    """
    Resolve a providers or consumers list into IP endpoints.

    Each actor can be:
      - {"actors": "ams"} → all workloads (or scoped workloads)
      - {"label": {"href": "..."}} → workloads matching this label
      - {"ip_list": {"href": "..."}} → IP list entries
      - {"workload": {"href": "..."}} → specific workload

    Returns: {
        "ips": ["10.0.0.1", "10.0.0.2", ...],
        "ip_lists": [{"name": ..., "ip_ranges": [...], "fqdns": [...]}],
        "labels_desc": "app=web AND env=prod",
        "type": "workloads" | "ip_list" | "all" | "mixed"
    }
    """
    all_ips = []
    all_ip_lists = []
    label_parts = []
    actor_type = "workloads"

    for actor in actors:
        if not isinstance(actor, dict):
            continue

        # All workloads
        if actor.get("actors") == "ams":
            actor_type = "all"
            if scope_constraints:
                # "All workloads" within scope → resolve scope labels to workloads
                matching = workloads_matching_labels(scope_constraints)
                for wl in matching:
                    all_ips.extend(get_workload_ips(wl))
                label_parts.append("All workloads in scope")
            else:
                # Global "all workloads"
                for wl in workload_cache:
                    all_ips.extend(get_workload_ips(wl))
                label_parts.append("All workloads")

        # Label-based
        elif "label" in actor:
            lbl = actor["label"]
            lbl_href = lbl.get("href", "") if isinstance(lbl, dict) else ""
            resolved = label_cache.get(lbl_href, {})
            if resolved:
                # Combine this label with scope constraints
                constraints = list(scope_constraints or [])
                constraints.append({"key": resolved["key"], "value": resolved["value"]})
                matching = workloads_matching_labels(constraints)
                for wl in matching:
                    all_ips.extend(get_workload_ips(wl))
                label_parts.append(f"{resolved['key']}={resolved['value']}")

        # IP List
        elif "ip_list" in actor:
            actor_type = "ip_list"
            ipl_href = actor["ip_list"].get("href", "")
            ipl = ip_list_cache.get(ipl_href)
            if ipl:
                all_ip_lists.append(ipl)
                # Flatten IP ranges to individual entries for display
                for r in ipl.get("ip_ranges", []):
                    if r.get("from_ip") and not r.get("exclusion"):
                        entry = r["from_ip"]
                        if r.get("to_ip") and r["to_ip"] != r["from_ip"]:
                            entry += f"-{r['to_ip']}"
                        all_ips.append(entry)
                for fqdn in ipl.get("fqdns", []):
                    all_ips.append(fqdn)
                label_parts.append(f"IP List: {ipl['name']}")

        # Label group
        elif "label_group" in actor:
            lg_href = actor["label_group"].get("href", "") if isinstance(actor["label_group"], dict) else ""
            lg = label_group_cache.get(lg_href)
            if lg:
                # Expand label group to all member labels, then find workloads matching any
                member_labels = expand_label_group(lg_href)
                for lbl_href in member_labels:
                    resolved_lbl = label_cache.get(lbl_href, {})
                    if resolved_lbl:
                        constraints = list(scope_constraints or [])
                        constraints.append({"key": resolved_lbl["key"], "value": resolved_lbl["value"]})
                        matching = workloads_matching_labels(constraints)
                        for wl in matching:
                            all_ips.extend(get_workload_ips(wl))
                label_parts.append(f"Label Group: {lg['name']}")

        # Specific workload
        elif "workload" in actor:
            wl_href = actor["workload"].get("href", "")
            for wl in workload_cache:
                if wl.get("href") == wl_href:
                    all_ips.extend(get_workload_ips(wl))
                    label_parts.append(f"Workload: {wl.get('hostname', wl_href)}")
                    break

    # Deduplicate
    seen = set()
    unique_ips = []
    for ip in all_ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    if all_ip_lists and unique_ips:
        actor_type = "mixed"

    return {
        "ips": unique_ips,
        "ip_lists": all_ip_lists,
        "labels_desc": " AND ".join(label_parts) if label_parts else "(none)",
        "type": actor_type,
        "count": len(unique_ips),
    }


# ---------------------------------------------------------------------------
# Service resolution
# ---------------------------------------------------------------------------

def resolve_services(ingress_services):
    """
    Resolve ingress_services list to port/protocol entries.
    Each entry can be:
      - {"href": "..."} → reference to a service definition
      - {"port": N, "proto": N} → inline port/proto
      - {"port": N, "to_port": N, "proto": N} → port range
    """
    resolved = []

    for svc in ingress_services:
        if not isinstance(svc, dict):
            continue

        # Service reference
        if "href" in svc and "port" not in svc:
            href = svc["href"]
            cached = service_cache.get(href)
            if cached:
                for sp in cached.get("ports", []):
                    proto_num = sp.get("proto", 6)
                    proto = {6: "tcp", 17: "udp"}.get(proto_num, str(proto_num))
                    port = sp.get("port", -1)
                    to_port = sp.get("to_port", 0)

                    entry = {
                        "port": port,
                        "to_port": to_port if to_port and to_port != port else None,
                        "protocol": proto,
                        "service_name": cached["name"],
                    }
                    resolved.append(entry)
            else:
                resolved.append({"port": "?", "protocol": "?", "service_name": href})

        # Inline port/proto
        elif "port" in svc:
            proto_num = svc.get("proto", 6)
            proto = {6: "tcp", 17: "udp"}.get(proto_num, str(proto_num))
            port = svc.get("port", -1)
            to_port = svc.get("to_port", 0)

            entry = {
                "port": port,
                "to_port": to_port if to_port and to_port != port else None,
                "protocol": proto,
                "service_name": "",
            }
            resolved.append(entry)

    if not resolved:
        resolved.append({"port": "all", "protocol": "all", "service_name": "All Services"})

    return resolved


def format_service(svc):
    """Format a service entry as a readable string."""
    port = svc.get("port", "?")
    proto = svc.get("protocol", "?")
    to_port = svc.get("to_port")
    name = svc.get("service_name", "")

    if port == "all":
        return "all"
    if port == -1:
        return f"all/{proto}"

    port_str = str(port)
    if to_port:
        port_str = f"{port}-{to_port}"

    if name:
        return f"{name} ({port_str}/{proto})"
    return f"{port_str}/{proto}"


# ---------------------------------------------------------------------------
# Policy resolution
# ---------------------------------------------------------------------------

def _resolve_rule(rule, rs_name, rs_href, scope_desc, scope_constraints, rule_type):
    """Resolve a single rule (allow or deny) into a resolved entry."""
    providers = rule.get("providers", [])
    consumers = rule.get("consumers", [])
    ingress_services = rule.get("ingress_services", [])
    unscoped_consumers = rule.get("unscoped_consumers", False)

    provider_result = resolve_actors(providers, scope_constraints)

    consumer_scope = None if unscoped_consumers else scope_constraints
    consumer_result = resolve_actors(consumers, consumer_scope)

    services = resolve_services(ingress_services)
    services_desc = [format_service(s) for s in services]

    # For deny rules, check override flag
    action = rule_type
    if rule_type == "deny" and rule.get("override", False):
        action = "override-deny"

    # Sort order: override-deny=0, allow=1, deny=2
    sort_order = {"override-deny": 0, "allow": 1, "deny": 2}.get(action, 1)

    return {
        "ruleset": rs_name,
        "ruleset_href": rs_href,
        "ruleset_scope": scope_desc,
        "action": action,
        "sort_order": sort_order,
        "consumers": {
            "description": consumer_result["labels_desc"],
            "type": consumer_result["type"],
            "ips": consumer_result["ips"],
            "ip_count": consumer_result["count"],
            "ip_lists": [
                {"name": ipl["name"], "ranges": ipl["ip_ranges"], "fqdns": ipl["fqdns"]}
                for ipl in consumer_result["ip_lists"]
            ],
            "unscoped": unscoped_consumers,
        },
        "providers": {
            "description": provider_result["labels_desc"],
            "type": provider_result["type"],
            "ips": provider_result["ips"],
            "ip_count": provider_result["count"],
            "ip_lists": [
                {"name": ipl["name"], "ranges": ipl["ip_ranges"], "fqdns": ipl["fqdns"]}
                for ipl in provider_result["ip_lists"]
            ],
        },
        "services": services,
        "services_display": services_desc,
    }


def resolve_policy(rulesets):
    """Resolve all rulesets into flat IP-level firewall rules.

    Rules are ordered: Override Deny → Allow → Deny
    """
    resolved_rules = []
    total_rulesets = 0
    total_rules = 0
    total_deny_rules = 0

    for rs in rulesets:
        if not rs.get("enabled", True):
            continue

        rs_name = rs.get("name", "(unnamed)")
        rs_href = rs.get("href", "")
        scopes = rs.get("scopes", [[]])

        scope_constraints = []
        scope_desc_parts = []
        if scopes and scopes[0]:
            scope_constraints = resolve_scope_labels(scopes[0])
            for c in scope_constraints:
                scope_desc_parts.append(f"{c['key']}={c['value']}")
        scope_desc = " AND ".join(scope_desc_parts) if scope_desc_parts else "(global)"

        allow_rules = rs.get("rules", [])
        deny_rules = rs.get("deny_rules", [])

        if not allow_rules and not deny_rules:
            continue

        total_rulesets += 1

        # Process allow rules
        for rule in allow_rules:
            if not rule.get("enabled", True):
                continue
            total_rules += 1
            resolved = _resolve_rule(rule, rs_name, rs_href, scope_desc, scope_constraints, "allow")
            resolved_rules.append(resolved)

        # Process deny rules (override and regular)
        for rule in deny_rules:
            if not rule.get("enabled", True):
                continue
            total_deny_rules += 1
            resolved = _resolve_rule(rule, rs_name, rs_href, scope_desc, scope_constraints, "deny")
            resolved_rules.append(resolved)

    # Sort: override-deny first, then allow, then deny
    resolved_rules.sort(key=lambda r: r["sort_order"])

    # Build summary
    total_ips_src = sum(r["consumers"]["ip_count"] for r in resolved_rules)
    total_ips_dst = sum(r["providers"]["ip_count"] for r in resolved_rules)
    action_counts = defaultdict(int)
    for r in resolved_rules:
        action_counts[r["action"]] += 1

    summary = {
        "rulesets_resolved": total_rulesets,
        "rules_resolved": total_rules,
        "deny_rules_resolved": total_deny_rules,
        "total_resolved_entries": len(resolved_rules),
        "total_source_ips": total_ips_src,
        "total_destination_ips": total_ips_dst,
        "action_counts": dict(action_counts),
        "policy_scope": "draft" if RESOLVE_DRAFT else "active",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return resolved_rules, summary


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_firewall_format(resolved_rules):
    """
    Export as a flat firewall rule table.
    Each entry = one source IP group → one dest IP group → one service.
    """
    firewall_rules = []
    idx = 1

    for rule in resolved_rules:
        for svc in rule["services"]:
            entry = {
                "id": idx,
                "ruleset": rule["ruleset"],
                "scope": rule["ruleset_scope"],
                "source_label": rule["consumers"]["description"],
                "source_ips": rule["consumers"]["ips"],
                "source_ip_count": rule["consumers"]["ip_count"],
                "destination_label": rule["providers"]["description"],
                "destination_ips": rule["providers"]["ips"],
                "destination_ip_count": rule["providers"]["ip_count"],
                "port": svc.get("port", "all"),
                "to_port": svc.get("to_port"),
                "protocol": svc.get("protocol", "any"),
                "service_name": svc.get("service_name", ""),
                "action": {"allow": "permit", "deny": "deny", "override-deny": "override-deny"}.get(rule.get("action", "allow"), "permit"),
            }

            # Include IP list info
            if rule["consumers"]["ip_lists"]:
                entry["source_ip_lists"] = [ipl["name"] for ipl in rule["consumers"]["ip_lists"]]
            if rule["providers"]["ip_lists"]:
                entry["destination_ip_lists"] = [ipl["name"] for ipl in rule["providers"]["ip_lists"]]

            firewall_rules.append(entry)
            idx += 1

    return firewall_rules


def save_export(firewall_rules, summary):
    """Save JSON export to /data."""
    try:
        os.makedirs("/data", exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        export = {
            "export_version": "1.0",
            "generated": summary.get("timestamp", ""),
            "pce_host": os.environ.get("PCE_HOST", ""),
            "policy_scope": summary.get("policy_scope", "active"),
            "summary": summary,
            "firewall_rules": firewall_rules,
        }
        path = f"/data/policy_resolved_{ts}.json"
        with open(path, "w") as f:
            json.dump(export, f, indent=2)
        log.info("Export saved: %s", path)
    except Exception as e:
        log.error("Failed to save export: %s", e)


# ---------------------------------------------------------------------------
# Background poller
# ---------------------------------------------------------------------------

def poller_loop(pce):
    while True:
        do_resolve = False
        with state_lock:
            if report_state["resolve_requested"]:
                report_state["resolve_requested"] = False
                do_resolve = True

        if do_resolve or report_state["last_resolve"] is None:
            pass
        else:
            time.sleep(30)
            try:
                last = datetime.fromisoformat(report_state["last_resolve"].replace("Z", "+00:00"))
                elapsed = (datetime.now(timezone.utc) - last).total_seconds()
                if elapsed < POLL_INTERVAL:
                    continue
            except (ValueError, TypeError, AttributeError):
                pass

        try:
            with state_lock:
                report_state["resolving"] = True
                report_state["error"] = None

            log.info("Resolving policy...")
            rulesets = fetch_all_data(pce)
            resolved_rules, summary = resolve_policy(rulesets)
            firewall_rules = export_firewall_format(resolved_rules)
            save_export(firewall_rules, summary)

            with state_lock:
                report_state["resolved_rules"] = resolved_rules
                report_state["firewall_rules"] = firewall_rules
                report_state["summary"] = summary
                report_state["last_resolve"] = summary["timestamp"]
                report_state["resolve_count"] += 1
                report_state["resolving"] = False
                report_state["policy_scope"] = summary["policy_scope"]

            log.info("Resolved %d rulesets → %d rules → %d firewall entries",
                     summary["rulesets_resolved"], summary["rules_resolved"], len(firewall_rules))

        except Exception as e:
            log.error("Resolution failed: %s", e, exc_info=True)
            with state_lock:
                report_state["resolving"] = False
                report_state["error"] = str(e)

        time.sleep(60)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Policy Resolver</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}
</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#11111b}::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.tab-btn{cursor:pointer;padding:0.5rem 1rem;font-size:0.875rem;border-bottom:2px solid transparent;color:#a6adc8;transition:all 0.15s}
.tab-btn:hover{color:#cdd6f4}.tab-btn.active{color:#89b4fa;border-color:#89b4fa}
.ip-tag{display:inline-block;font-family:monospace;font-size:0.75rem;background:#313244;color:#a6e3a1;padding:2px 6px;border-radius:3px;margin:1px}
.svc-tag{display:inline-block;font-size:0.75rem;background:rgba(137,180,250,0.15);color:#93c5fd;padding:2px 8px;border-radius:3px;margin:1px;border:1px solid rgba(137,180,250,0.2)}
.rule-row{cursor:pointer;transition:background 0.1s}.rule-row:hover{background:rgba(69,71,90,0.4)}
.detail-row{display:none;background:#181825}.rule-row.expanded+.detail-row{display:table-row}
pre.json-block{background:#11111b;border:1px solid #313244;border-radius:0.5rem;padding:1rem;overflow-x:auto;font-size:0.8rem;color:#a6e3a1;line-height:1.5;white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}.scanning{animation:pulse 2s infinite}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-[90rem] mx-auto px-4 py-6">

<!-- Header -->
<div class="flex items-center justify-between mb-8">
  <div>
    <h1 class="text-2xl font-bold text-white flex items-center gap-2">
      <svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/></svg>
      Policy Resolver
    </h1>
    <div class="flex items-center gap-2 mt-1">
      <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
      <span id="status-text" class="text-sm text-gray-400">Loading...</span>
    </div>
  </div>
  <div class="flex items-center gap-3">
    <span id="scope-badge" class="text-xs px-3 py-1 rounded-full bg-green-500/15 text-green-300 border border-green-500/30 font-medium">active</span>
    <button onclick="triggerResolve()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Resolve Now</button>
    <button onclick="downloadJSON()" class="bg-dark-700 hover:bg-dark-800 text-gray-300 px-4 py-1.5 rounded text-sm border border-gray-600">Export JSON</button>
  </div>
</div>

<!-- Stats -->
<div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-rulesets" class="text-3xl font-bold text-blue-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Rulesets</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-rules" class="text-3xl font-bold text-purple-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Rules</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-fw-rules" class="text-3xl font-bold text-green-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Firewall Entries</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-src-ips" class="text-3xl font-bold text-yellow-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Source IPs</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-dst-ips" class="text-3xl font-bold text-cyan-400">—</div>
    <div class="text-sm text-gray-400 mt-1">Dest IPs</div>
  </div>
</div>

<!-- Tabs -->
<div class="flex gap-1 border-b border-gray-700 mb-6">
  <button class="tab-btn active" onclick="showTab(this,'firewall')">Firewall Rules</button>
  <button class="tab-btn" onclick="showTab(this,'resolved')">By Ruleset</button>
  <button class="tab-btn" onclick="showTab(this,'json')">JSON Export</button>
</div>

<!-- Tab: Firewall Rules (flat table) -->
<div id="tab-firewall" class="tab-content">
  <div class="bg-dark-800 rounded-xl border border-gray-700">
    <div class="p-4 border-b border-gray-700 flex items-center gap-3">
      <input id="fw-search" type="text" placeholder="Search by IP, port, ruleset, label..." oninput="renderFirewall()"
             class="bg-dark-900 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-300 w-72">
      <span id="fw-count" class="text-xs text-gray-500"></span>
      <button onclick="copyFirewallTable()" class="ml-auto text-xs bg-dark-700 hover:bg-dark-900 text-gray-300 px-3 py-1.5 rounded border border-gray-600">Copy Table</button>
    </div>
    <div class="overflow-x-auto max-h-[600px] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-dark-800 z-10">
          <tr class="text-left text-xs text-gray-400 uppercase">
            <th class="px-3 py-3 w-8">#</th>
            <th class="px-3 py-3">Ruleset</th>
            <th class="px-3 py-3">Source</th>
            <th class="px-3 py-3">Source IPs</th>
            <th class="px-3 py-3">Destination</th>
            <th class="px-3 py-3">Dest IPs</th>
            <th class="px-3 py-3">Service</th>
            <th class="px-3 py-3">Action</th>
          </tr>
        </thead>
        <tbody id="fw-table"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Tab: By Ruleset -->
<div id="tab-resolved" class="tab-content hidden">
  <div id="ruleset-list" class="space-y-4"></div>
</div>

<!-- Tab: JSON -->
<div id="tab-json" class="tab-content hidden">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div class="flex items-center justify-between mb-3">
      <span class="text-sm text-gray-400">Full JSON export — copy-paste ready for firewall teams</span>
      <button onclick="copyJSON()" class="text-xs bg-dark-700 hover:bg-dark-900 text-gray-300 px-3 py-1.5 rounded border border-gray-600">Copy JSON</button>
    </div>
    <pre class="json-block" id="json-output">Loading...</pre>
  </div>
</div>

</div>

<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\/plugins\/[^/]+\/ui/);return m?m[0]:''})();
let currentData=null;

function formatNum(n){if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toLocaleString()}
function actionBadge(a){
  if(a==='override-deny')return'<span class="text-xs bg-red-500/20 text-red-300 rounded px-2 py-0.5 border border-red-500/30 font-semibold">OVERRIDE DENY</span>';
  if(a==='deny')return'<span class="text-xs bg-orange-500/20 text-orange-300 rounded px-2 py-0.5 border border-orange-500/30">deny</span>';
  return'<span class="text-xs bg-green-500/15 text-green-300 rounded px-2 py-0.5 border border-green-500/30">permit</span>';
}
function timeAgo(ts){if(!ts)return'—';const d=(Date.now()-new Date(ts).getTime())/1000;if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago'}

function showTab(btn,id){
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+id).classList.remove('hidden');
  btn.classList.add('active');
}

function update(d){
  currentData=d;
  const dot=document.getElementById('status-dot');
  const txt=document.getElementById('status-text');
  if(d.resolving){dot.className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning';txt.textContent='Resolving policy...';}
  else if(d.error){dot.className='w-2.5 h-2.5 rounded-full bg-red-500';txt.textContent='Error: '+d.error;}
  else if(d.last_resolve){dot.className='w-2.5 h-2.5 rounded-full bg-green-500';txt.textContent='Last resolved: '+timeAgo(d.last_resolve)+' | '+d.resolve_count+' runs';}
  else{dot.className='w-2.5 h-2.5 rounded-full bg-gray-500';txt.textContent='Not resolved yet. Click Resolve Now.';}

  document.getElementById('scope-badge').textContent=d.policy_scope||'active';

  const s=d.summary||{};
  document.getElementById('stat-rulesets').textContent=formatNum(s.rulesets_resolved||0);
  document.getElementById('stat-rules').textContent=formatNum(s.rules_resolved||0);
  document.getElementById('stat-fw-rules').textContent=formatNum((d.firewall_rules||[]).length);
  document.getElementById('stat-src-ips').textContent=formatNum(s.total_source_ips||0);
  document.getElementById('stat-dst-ips').textContent=formatNum(s.total_destination_ips||0);

  renderFirewall();
  renderRulesets();
  renderJSON();
}

function renderFirewall(){
  if(!currentData||!currentData.firewall_rules)return;
  const q=(document.getElementById('fw-search').value||'').toLowerCase();
  const rules=currentData.firewall_rules;
  const filtered=q?rules.filter(r=>{
    const searchStr=(r.ruleset+' '+r.source_label+' '+r.destination_label+' '+r.source_ips.join(' ')+' '+r.destination_ips.join(' ')+' '+r.port+' '+r.protocol+' '+(r.service_name||'')).toLowerCase();
    return searchStr.includes(q);
  }):rules;

  document.getElementById('fw-count').textContent=filtered.length+' of '+rules.length+' entries';

  const tbody=document.getElementById('fw-table');
  let html='';
  for(const r of filtered.slice(0,500)){
    const srcIPs=r.source_ips.slice(0,5).map(ip=>`<span class="ip-tag">${ip}</span>`).join('')+(r.source_ip_count>5?`<span class="text-xs text-gray-500 ml-1">+${r.source_ip_count-5} more</span>`:'');
    const dstIPs=r.destination_ips.slice(0,5).map(ip=>`<span class="ip-tag">${ip}</span>`).join('')+(r.destination_ip_count>5?`<span class="text-xs text-gray-500 ml-1">+${r.destination_ip_count-5} more</span>`:'');
    const portStr=r.to_port?`${r.port}-${r.to_port}`:r.port;
    const svcDisplay=r.service_name?`${r.service_name} (${portStr}/${r.protocol})`:`${portStr}/${r.protocol}`;

    html+=`<tr class="rule-row border-b border-gray-700/50" onclick="toggleRow(this)">
      <td class="px-3 py-2.5 text-gray-500 text-xs">${r.id}</td>
      <td class="px-3 py-2.5 text-gray-300 text-xs">${r.ruleset}</td>
      <td class="px-3 py-2.5 text-gray-400 text-xs max-w-[200px] truncate" title="${r.source_label}">${r.source_label}</td>
      <td class="px-3 py-2.5">${srcIPs||'<span class="text-gray-600">—</span>'}</td>
      <td class="px-3 py-2.5 text-gray-400 text-xs max-w-[200px] truncate" title="${r.destination_label}">${r.destination_label}</td>
      <td class="px-3 py-2.5">${dstIPs||'<span class="text-gray-600">—</span>'}</td>
      <td class="px-3 py-2.5"><span class="svc-tag">${svcDisplay}</span></td>
      <td class="px-3 py-2.5">${actionBadge(r.action)}</td>
    </tr>
    <tr class="detail-row border-b border-gray-700/50">
      <td colspan="8" class="p-4">
        <div class="grid grid-cols-2 gap-4 text-xs">
          <div>
            <div class="text-gray-400 font-semibold mb-1">All Source IPs (${r.source_ip_count})</div>
            <div class="max-h-32 overflow-y-auto">${r.source_ips.map(ip=>`<span class="ip-tag">${ip}</span>`).join('')||'—'}</div>
          </div>
          <div>
            <div class="text-gray-400 font-semibold mb-1">All Destination IPs (${r.destination_ip_count})</div>
            <div class="max-h-32 overflow-y-auto">${r.destination_ips.map(ip=>`<span class="ip-tag">${ip}</span>`).join('')||'—'}</div>
          </div>
        </div>
      </td>
    </tr>`;
  }
  tbody.innerHTML=html||'<tr><td colspan="8" class="px-4 py-8 text-center text-gray-500">No firewall rules resolved yet</td></tr>';
}

function toggleRow(tr){tr.classList.toggle('expanded')}

function renderRulesets(){
  if(!currentData||!currentData.resolved_rules)return;
  const container=document.getElementById('ruleset-list');
  const byRuleset={};
  for(const r of currentData.resolved_rules){
    if(!byRuleset[r.ruleset])byRuleset[r.ruleset]={scope:r.ruleset_scope,rules:[]};
    byRuleset[r.ruleset].rules.push(r);
  }

  let html='';
  for(const[name,data]of Object.entries(byRuleset)){
    html+=`<div class="bg-dark-800 rounded-xl border border-gray-700">
      <div class="px-5 py-4 border-b border-gray-700">
        <h3 class="text-white font-semibold">${name}</h3>
        <div class="text-xs text-gray-400 mt-1">Scope: ${data.scope} | ${data.rules.length} rule(s)</div>
      </div>
      <div class="overflow-x-auto"><table class="w-full text-sm">
      <thead><tr class="text-left text-xs text-gray-400 uppercase">
        <th class="px-4 py-2">Consumer</th><th class="px-4 py-2">IPs</th>
        <th class="px-4 py-2">Provider</th><th class="px-4 py-2">IPs</th>
        <th class="px-4 py-2">Services</th>
      </tr></thead><tbody>`;
    for(const r of data.rules){
      html+=`<tr class="border-b border-gray-700/50">
        <td class="px-4 py-2 text-gray-300 text-xs">${r.consumers.description}${r.consumers.unscoped?' <span class="text-amber-400">(unscoped)</span>':''}</td>
        <td class="px-4 py-2 text-xs">${r.consumers.ip_count} IPs</td>
        <td class="px-4 py-2 text-gray-300 text-xs">${r.providers.description}</td>
        <td class="px-4 py-2 text-xs">${r.providers.ip_count} IPs</td>
        <td class="px-4 py-2">${r.services_display.map(s=>`<span class="svc-tag">${s}</span>`).join('')}</td>
      </tr>`;
    }
    html+=`</tbody></table></div></div>`;
  }
  container.innerHTML=html||'<p class="text-gray-500 text-center py-8">No rulesets resolved yet</p>';
}

function renderJSON(){
  if(!currentData||!currentData.firewall_rules)return;
  const exportData={
    export_version:"1.0",
    generated:currentData.summary?.timestamp||'',
    pce_host:currentData.summary?.pce_host||'',
    policy_scope:currentData.policy_scope||'active',
    summary:currentData.summary||{},
    firewall_rules:currentData.firewall_rules,
  };
  document.getElementById('json-output').textContent=JSON.stringify(exportData,null,2);
}

function copyJSON(){
  const text=document.getElementById('json-output').textContent;
  navigator.clipboard.writeText(text).then(()=>alert('JSON copied to clipboard'));
}

function copyFirewallTable(){
  if(!currentData||!currentData.firewall_rules)return;
  const lines=['#\tAction\tRuleset\tSource Label\tSource IPs\tDest Label\tDest IPs\tPort\tProtocol\tService'];
  for(const r of currentData.firewall_rules){
    const portStr=r.to_port?r.port+'-'+r.to_port:r.port;
    lines.push([r.id,r.action,r.ruleset,r.source_label,r.source_ips.join(';'),r.destination_label,r.destination_ips.join(';'),portStr,r.protocol,r.service_name||''].join('\t'));
  }
  navigator.clipboard.writeText(lines.join('\n')).then(()=>alert('Table copied (TSV) — paste into Excel or Google Sheets'));
}

function downloadJSON(){
  if(!currentData||!currentData.firewall_rules)return;
  const exportData={export_version:"1.0",generated:currentData.summary?.timestamp||'',policy_scope:currentData.policy_scope||'active',summary:currentData.summary||{},firewall_rules:currentData.firewall_rules};
  const blob=new Blob([JSON.stringify(exportData,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download='policy_resolved.json';a.click();
  URL.revokeObjectURL(url);
}

async function fetchData(){
  try{
    const resp=await fetch(BASE+'/api/resolved');
    const d=await resp.json();
    update(d);
  }catch(e){
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-red-500';
    document.getElementById('status-text').textContent='Connection error';
  }
}

async function triggerResolve(){
  try{
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning';
    document.getElementById('status-text').textContent='Resolving...';
    await fetch(BASE+'/api/resolve',{method:'POST'});
  }catch(e){}
}

fetchData();
setInterval(fetchData,30000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class ResolverHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path == "/" or path == "":
            self._send(200, DASHBOARD_HTML, "text/html")
        elif path == "/healthz":
            self._send(200, json.dumps({"status": "healthy"}))
        elif path == "/api/resolved":
            with state_lock:
                self._send(200, json.dumps(report_state, default=str))
        elif path == "/api/config":
            self._send(200, json.dumps({
                "poll_interval": POLL_INTERVAL,
                "resolve_draft": RESOLVE_DRAFT,
                "policy_scope": "draft" if RESOLVE_DRAFT else "active",
            }))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        if path == "/api/resolve":
            with state_lock:
                if report_state["resolving"]:
                    self._send(409, json.dumps({"error": "Already resolving"}))
                    return
                report_state["resolve_requested"] = True
            self._send(200, json.dumps({"status": "resolve_requested"}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("Policy Resolver starting...")
    log.info("Config: interval=%ds, scope=%s", POLL_INTERVAL, "draft" if RESOLVE_DRAFT else "active")

    pce = get_pce()

    poller = threading.Thread(target=poller_loop, args=(pce,), daemon=True)
    poller.start()

    server = HTTPServer(("0.0.0.0", HTTP_PORT), ResolverHandler)
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
