#!/usr/bin/env python3
"""
Application Dependency Intelligence — transforms PCE traffic flow data into
dependency intelligence for BCM, compliance, resiliency, and change impact
analysis.

This is NOT a traffic visualizer (Illumio Illumination already does that).
This plugin fills the gap for dependency analysis beyond policy writing:
blast radius, SPOF detection, circular dependencies, cross-environment
compliance, change impact, and infrastructure hub analysis.
"""

import csv
import io
import json
import logging
import os
import signal
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from illumio import PolicyComputeEngine
from illumio.explorer import TrafficQuery

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("app-dependency-intel")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
app_state = {
    "last_scan": None,
    "scan_count": 0,
    "scanning": False,
    "error": None,
    "scan_requested": False,
    # Core data
    "dependencies": [],
    "applications": {},
    # Analysis results
    "spof": [],
    "cycles": [],
    "cross_env": [],
    "infrastructure_hubs": [],
    # Metadata
    "workload_count": 0,
    "flow_count": 0,
    "scan_duration": 0,
}

label_cache = {}  # href -> {key, value}
workload_index = {}  # hostname -> app_env key; ip -> app_env key

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCAN_INTERVAL = max(300, int(os.environ.get("SCAN_INTERVAL", "3600")))
LOOKBACK_DAYS = int(os.environ.get("LOOKBACK_DAYS", "30"))
MAX_FLOWS = int(os.environ.get("MAX_FLOWS", "200000"))
HUB_THRESHOLD = int(os.environ.get("HUB_THRESHOLD", "4"))
SPOF_THRESHOLD = int(os.environ.get("SPOF_THRESHOLD", "1"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

PROD_ENVS = {"production", "prod", "prd"}
NON_PROD_ENVS = {"development", "dev", "test", "tst", "staging", "stg", "qa", "uat", "sandbox", "sbx"}

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
        log.info("Cached %d labels", len(cache))
        return labels
    except Exception as e:
        log.error("Failed to fetch labels: %s", e)
        return []


def resolve_label(href):
    return label_cache.get(href, {})


def workload_labels(wl):
    """Extract label dict {key: value} from a workload dict."""
    labels = {}
    for lbl in wl.get("labels", []):
        href = lbl.get("href", "")
        resolved = resolve_label(href)
        if resolved:
            labels[resolved["key"]] = resolved["value"]
    return labels


def endpoint_labels(ep):
    """Extract label dict {key: value} from a traffic flow endpoint."""
    labels = {}
    wl = ep.get("workload", {}) if isinstance(ep, dict) else {}
    if not isinstance(wl, dict):
        wl = {}
    for lbl in wl.get("labels", []):
        href = lbl.get("href", "")
        resolved = resolve_label(href)
        if resolved:
            labels[resolved["key"]] = resolved["value"]
    return labels


def make_app_env_key(labels):
    """Build an 'app|env' key from label dict. Returns '' if app is missing."""
    app = labels.get("app", "")
    env = labels.get("env", "unknown")
    if not app:
        return ""
    return f"{app}|{env}"


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
            policy_decisions=["allowed"],
            max_results=MAX_FLOWS,
        )
        raw_flows = pce.get_traffic_flows_async(
            query_name="plugger-app-dependency-intel",
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


# ---------------------------------------------------------------------------
# Dependency Builder
# ---------------------------------------------------------------------------

def build_dependencies(workloads, flows):
    """
    Transform flows into dependency objects.
    Groups flows by consumer app|env -> provider app|env,
    aggregates services, classifies, calculates strength.
    """
    global workload_index

    # Build workload index: hostname/IP -> app_env key, and count per app_env
    wl_app_env_map = {}  # hostname -> app_env
    wl_ip_map = {}  # ip -> app_env
    app_env_workloads = defaultdict(set)  # app_env -> set of hostnames
    app_env_roles = defaultdict(set)  # app_env -> set of role values

    for wl in workloads:
        labels = workload_labels(wl)
        key = make_app_env_key(labels)
        if not key:
            continue
        hostname = wl.get("hostname", "")
        if hostname:
            wl_app_env_map[hostname] = key
            app_env_workloads[key].add(hostname)
        role = labels.get("role", "")
        if role:
            app_env_roles[key].add(role)
        # Map IPs
        for iface in wl.get("interfaces", []):
            ip = iface.get("address", "")
            if ip:
                wl_ip_map[ip] = key

    workload_index = {**wl_app_env_map, **wl_ip_map}

    # Group flows into dependency edges
    # Key: (consumer_app_env, provider_app_env) -> aggregated data
    dep_agg = defaultdict(lambda: {
        "services": Counter(),
        "total_connections": 0,
        "first_seen": None,
        "last_seen": None,
        "consumer_workloads": set(),
        "provider_workloads": set(),
    })

    for flow in flows:
        src = flow.get("src", {})
        dst = flow.get("dst", {})

        src_labels = endpoint_labels(src)
        dst_labels = endpoint_labels(dst)

        consumer_key = make_app_env_key(src_labels)
        provider_key = make_app_env_key(dst_labels)

        if not consumer_key or not provider_key:
            continue
        if consumer_key == provider_key:
            continue  # intra-application traffic, skip

        edge = (consumer_key, provider_key)
        agg = dep_agg[edge]

        # Service info
        service = flow.get("service", {})
        if isinstance(service, dict):
            port = service.get("port", 0)
            proto_num = service.get("proto", 6)
            proto = {6: "tcp", 17: "udp"}.get(proto_num, str(proto_num))
            if port:
                svc_name = service.get("process_name", "")
                svc_label = f"{port}/{proto}"
                agg["services"][svc_label] += 1

        num = flow.get("num_connections", 1)
        agg["total_connections"] += num

        # Timestamps
        ts_str = flow.get("timestamp_range", {})
        if isinstance(ts_str, dict):
            first = ts_str.get("first_detected", "")
            last = ts_str.get("last_detected", "")
        else:
            first = ""
            last = ""
        if first:
            if agg["first_seen"] is None or first < agg["first_seen"]:
                agg["first_seen"] = first
        if last:
            if agg["last_seen"] is None or last > agg["last_seen"]:
                agg["last_seen"] = last

        # Track workload hostnames
        src_host = ""
        src_wl = src.get("workload", {})
        if isinstance(src_wl, dict):
            src_host = src_wl.get("hostname", "")
        if src_host:
            agg["consumer_workloads"].add(src_host)

        dst_host = ""
        dst_wl = dst.get("workload", {})
        if isinstance(dst_wl, dict):
            dst_host = dst_wl.get("hostname", "")
        if dst_host:
            agg["provider_workloads"].add(dst_host)

    # Build dependency list
    dependencies = []
    consumer_count_per_provider = Counter()  # provider_key -> number of unique consumers

    for (consumer_key, provider_key), agg in dep_agg.items():
        consumer_count_per_provider[provider_key] += 1

        consumer_app, consumer_env = consumer_key.split("|", 1)
        provider_app, provider_env = provider_key.split("|", 1)

        total_conn = agg["total_connections"]

        # Strength classification
        if total_conn > 1000:
            strength = "strong"
        elif total_conn >= 100:
            strength = "moderate"
        else:
            strength = "weak"

        # Cross-env / cross-app flags
        cross_env = consumer_env.lower() != provider_env.lower()
        cross_app = consumer_app.lower() != provider_app.lower()

        # Services list
        services = []
        for svc_label, count in agg["services"].most_common(20):
            parts = svc_label.split("/")
            port_str = parts[0] if parts else "0"
            proto = parts[1] if len(parts) > 1 else "tcp"
            try:
                port_num = int(port_str)
            except ValueError:
                port_num = 0
            services.append({
                "port": port_num,
                "proto": proto,
                "label": svc_label,
                "connection_count": count,
            })

        dep = {
            "consumer": {"app": consumer_app, "env": consumer_env, "key": consumer_key},
            "provider": {"app": provider_app, "env": provider_env, "key": provider_key},
            "services": services,
            "strength": strength,
            "connection_volume": total_conn,
            "first_seen": agg["first_seen"] or "",
            "last_seen": agg["last_seen"] or "",
            "consumer_workload_count": len(agg["consumer_workloads"]),
            "provider_workload_count": len(agg["provider_workloads"]),
            "cross_environment": cross_env,
            "cross_application": cross_app,
            "infrastructure": False,  # set later
        }
        dependencies.append(dep)

    # Mark infrastructure dependencies (provider has many consumers)
    for dep in dependencies:
        pk = dep["provider"]["key"]
        if consumer_count_per_provider.get(pk, 0) >= HUB_THRESHOLD:
            dep["infrastructure"] = True

    return dependencies, app_env_workloads, app_env_roles, consumer_count_per_provider


# ---------------------------------------------------------------------------
# Application Node Builder
# ---------------------------------------------------------------------------

def build_applications(dependencies, app_env_workloads, app_env_roles, consumer_count_per_provider):
    """Build application graph nodes from dependencies."""
    apps = {}

    # Collect all app_env keys from dependencies
    all_keys = set()
    depends_on = defaultdict(set)
    depended_by = defaultdict(set)

    for dep in dependencies:
        ck = dep["consumer"]["key"]
        pk = dep["provider"]["key"]
        all_keys.add(ck)
        all_keys.add(pk)
        depends_on[ck].add(pk)
        depended_by[pk].add(ck)

    # Also add app_env keys from workloads that might not appear in deps
    for key in app_env_workloads:
        all_keys.add(key)

    for key in sorted(all_keys):
        parts = key.split("|", 1)
        app_name = parts[0]
        env_name = parts[1] if len(parts) > 1 else "unknown"

        wl_count = len(app_env_workloads.get(key, set()))
        roles = sorted(app_env_roles.get(key, set()))
        consumer_cnt = consumer_count_per_provider.get(key, 0)
        is_infra = consumer_cnt >= HUB_THRESHOLD

        apps[key] = {
            "key": key,
            "app": app_name,
            "env": env_name,
            "workload_count": wl_count,
            "roles": roles,
            "depends_on": sorted(depends_on.get(key, set())),
            "depended_by": sorted(depended_by.get(key, set())),
            "dependency_count_outbound": len(depends_on.get(key, set())),
            "dependency_count_inbound": len(depended_by.get(key, set())),
            "is_infrastructure": is_infra,
            "consumer_count": consumer_cnt,
        }

    return apps


# ---------------------------------------------------------------------------
# Analysis: Blast Radius
# ---------------------------------------------------------------------------

def analyze_blast_radius(target_key, applications):
    """
    Given a target app|env, find all directly and transitively dependent apps.
    Returns the full dependency chain with depth.
    """
    if target_key not in applications:
        return {"error": f"Application '{target_key}' not found"}

    target = applications[target_key]
    directly_affected = list(target.get("depended_by", []))

    # BFS for transitive dependencies
    visited = set()
    visited.add(target_key)
    queue = [(dk, 1) for dk in directly_affected]
    transitive = []
    chain = []
    max_depth = 0

    while queue:
        current, depth = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        if current not in directly_affected:
            transitive.append(current)
        chain.append({"app_env": current, "depth": depth})
        max_depth = max(max_depth, depth)

        app_node = applications.get(current, {})
        for dep in app_node.get("depended_by", []):
            if dep not in visited:
                queue.append((dep, depth + 1))

    total_workloads = 0
    for ae in visited:
        if ae != target_key:
            total_workloads += applications.get(ae, {}).get("workload_count", 0)

    return {
        "target": target_key,
        "target_app": target.get("app", ""),
        "target_env": target.get("env", ""),
        "directly_affected": directly_affected,
        "transitively_affected": transitive,
        "total_affected_applications": len(visited) - 1,
        "total_affected_workloads": total_workloads,
        "max_depth": max_depth,
        "chain": chain,
    }


# ---------------------------------------------------------------------------
# Analysis: SPOF Detection
# ---------------------------------------------------------------------------

def analyze_spof(dependencies, applications):
    """
    Find provider app|env+role combos where provider_workload_count <= SPOF_THRESHOLD
    but consumer_count is high.
    """
    spofs = []

    # Group by provider key
    provider_stats = defaultdict(lambda: {
        "provider_workloads": set(),
        "consumer_keys": set(),
        "services": [],
    })

    for dep in dependencies:
        pk = dep["provider"]["key"]
        provider_stats[pk]["consumer_keys"].add(dep["consumer"]["key"])
        for svc in dep.get("services", []):
            provider_stats[pk]["services"].append(svc.get("label", ""))

    for pk, stats in provider_stats.items():
        app_node = applications.get(pk, {})
        wl_count = app_node.get("workload_count", 0)
        consumer_count = len(stats["consumer_keys"])

        if wl_count <= SPOF_THRESHOLD and consumer_count >= 2:
            if consumer_count >= 5:
                risk = "critical"
            elif consumer_count >= 3:
                risk = "high"
            else:
                risk = "medium"

            parts = pk.split("|", 1)
            spofs.append({
                "provider": {
                    "app": parts[0],
                    "env": parts[1] if len(parts) > 1 else "unknown",
                    "key": pk,
                    "roles": app_node.get("roles", []),
                },
                "workload_count": wl_count,
                "consumer_count": consumer_count,
                "consumers": sorted(stats["consumer_keys"]),
                "services": sorted(set(stats["services"]))[:10],
                "risk": risk,
            })

    spofs.sort(key=lambda s: (-s["consumer_count"], s["risk"]))
    return spofs


# ---------------------------------------------------------------------------
# Analysis: Circular Dependency Detection
# ---------------------------------------------------------------------------

def analyze_cycles(applications):
    """DFS cycle detection on the dependency graph. Return all cycles found."""
    graph = {}
    for key, app_node in applications.items():
        graph[key] = app_node.get("depends_on", [])

    cycles = []
    visited = set()
    rec_stack = set()

    def dfs(node, path):
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                dfs(neighbor, path)
            elif neighbor in rec_stack:
                # Found a cycle: extract it
                cycle_start = path.index(neighbor)
                cycle = path[cycle_start:] + [neighbor]
                # Normalize: start from the lexicographically smallest node
                # to avoid reporting the same cycle multiple times
                min_idx = cycle[:-1].index(min(cycle[:-1]))
                normalized = cycle[min_idx:-1] + cycle[:min_idx] + [cycle[min_idx]]
                # Check if we already have this cycle
                norm_tuple = tuple(normalized)
                if norm_tuple not in seen_cycles:
                    seen_cycles.add(norm_tuple)
                    cycles.append({
                        "path": normalized,
                        "length": len(normalized) - 1,
                        "risk": "Circular dependency may cause cascading failures",
                    })

        path.pop()
        rec_stack.discard(node)

    seen_cycles = set()
    for node in graph:
        if node not in visited:
            dfs(node, [])

    return cycles


# ---------------------------------------------------------------------------
# Analysis: Cross-Environment
# ---------------------------------------------------------------------------

def analyze_cross_env(dependencies):
    """Filter dependencies where consumer env != provider env."""
    violations = []

    for dep in dependencies:
        if not dep["cross_environment"]:
            continue

        c_env = dep["consumer"]["env"].lower()
        p_env = dep["provider"]["env"].lower()

        # Determine risk
        c_is_prod = c_env in PROD_ENVS
        p_is_prod = p_env in PROD_ENVS
        c_is_nonprod = c_env in NON_PROD_ENVS
        p_is_nonprod = p_env in NON_PROD_ENVS

        if (c_is_prod and p_is_nonprod) or (c_is_nonprod and p_is_prod):
            risk = "critical"
            if c_is_prod and p_is_nonprod:
                violation_desc = f"Production ({dep['consumer']['key']}) depends on non-production ({dep['provider']['key']})"
            else:
                violation_desc = f"Non-production ({dep['consumer']['key']}) depends on production ({dep['provider']['key']})"
        else:
            risk = "warning"
            violation_desc = f"Cross-environment: {dep['consumer']['key']} depends on {dep['provider']['key']}"

        services_str = ", ".join(s.get("label", "") for s in dep.get("services", [])[:5])

        violations.append({
            "consumer": dep["consumer"]["key"],
            "consumer_app": dep["consumer"]["app"],
            "consumer_env": dep["consumer"]["env"],
            "provider": dep["provider"]["key"],
            "provider_app": dep["provider"]["app"],
            "provider_env": dep["provider"]["env"],
            "services": services_str,
            "connection_volume": dep["connection_volume"],
            "risk": risk,
            "violation": violation_desc,
        })

    violations.sort(key=lambda v: (0 if v["risk"] == "critical" else 1, -v["connection_volume"]))
    return violations


# ---------------------------------------------------------------------------
# Analysis: Change Impact
# ---------------------------------------------------------------------------

def analyze_change_impact(targets, applications):
    """
    Given a list of target hostnames/IPs, find which app|env they belong to,
    then run blast radius to find all affected apps.
    """
    affected_app_envs = set()
    target_mapping = {}  # target -> app_env key

    for target in targets:
        target = target.strip()
        if not target:
            continue
        key = workload_index.get(target, "")
        if key:
            affected_app_envs.add(key)
            target_mapping[target] = key
        else:
            target_mapping[target] = None

    if not affected_app_envs:
        return {
            "targets": targets,
            "target_mapping": target_mapping,
            "affected_applications": 0,
            "affected_workloads": 0,
            "blast_results": [],
            "recommended_notification": [],
            "maintenance_window_risk": "low",
        }

    # Run blast radius for each affected app_env
    all_affected = set()
    blast_results = []
    for ae in affected_app_envs:
        br = analyze_blast_radius(ae, applications)
        if "error" not in br:
            blast_results.append(br)
            for a in br.get("directly_affected", []):
                all_affected.add(a)
            for a in br.get("transitively_affected", []):
                all_affected.add(a)

    total_workloads = 0
    notifications = []
    for ae in all_affected:
        app_node = applications.get(ae, {})
        wl_count = app_node.get("workload_count", 0)
        total_workloads += wl_count
        if wl_count > 0:
            notifications.append(f"{ae} ({wl_count} workloads depend on targeted systems)")

    total_affected = len(all_affected)
    if total_affected >= 10:
        risk = "critical"
    elif total_affected >= 5:
        risk = "high"
    elif total_affected >= 2:
        risk = "medium"
    else:
        risk = "low"

    return {
        "targets": targets,
        "target_mapping": target_mapping,
        "affected_applications": total_affected,
        "affected_workloads": total_workloads,
        "affected_app_list": sorted(all_affected),
        "blast_results": blast_results,
        "recommended_notification": notifications,
        "maintenance_window_risk": risk,
    }


# ---------------------------------------------------------------------------
# Analysis: Infrastructure Hubs
# ---------------------------------------------------------------------------

def analyze_infrastructure_hubs(applications):
    """Sort providers by consumer count descending. Flag those above HUB_THRESHOLD."""
    hubs = []

    for key, app_node in applications.items():
        consumer_count = app_node.get("consumer_count", 0)
        if consumer_count < HUB_THRESHOLD:
            continue

        wl_count = app_node.get("workload_count", 0)
        if wl_count >= 3:
            redundancy = "high"
        elif wl_count >= 2:
            redundancy = "medium"
        else:
            redundancy = "low"

        hubs.append({
            "key": key,
            "app": app_node.get("app", ""),
            "env": app_node.get("env", ""),
            "consumer_count": consumer_count,
            "workload_count": wl_count,
            "roles": app_node.get("roles", []),
            "redundancy": redundancy,
            "depended_by": app_node.get("depended_by", []),
        })

    hubs.sort(key=lambda h: -h["consumer_count"])
    return hubs


# ---------------------------------------------------------------------------
# Full scan orchestration
# ---------------------------------------------------------------------------

def run_full_scan(pce):
    """Collect data, build dependencies, run all analyses."""
    start_time = time.time()

    log.info("Collecting PCE data...")
    labels = fetch_labels(pce)
    workloads = collect_workloads(pce)
    log.info("Collected %d workloads, %d labels", len(workloads), len(labels))
    flows = collect_traffic(pce)
    log.info("Collected %d traffic flows", len(flows))

    log.info("Building dependencies...")
    dependencies, app_env_workloads, app_env_roles, consumer_count_per_provider = build_dependencies(workloads, flows)
    log.info("Built %d dependencies", len(dependencies))

    log.info("Building application graph...")
    applications = build_applications(dependencies, app_env_workloads, app_env_roles, consumer_count_per_provider)
    log.info("Built %d application nodes", len(applications))

    log.info("Running analysis engines...")
    spof = analyze_spof(dependencies, applications)
    log.info("Found %d SPOFs", len(spof))

    cycles = analyze_cycles(applications)
    log.info("Found %d circular dependencies", len(cycles))

    cross_env = analyze_cross_env(dependencies)
    log.info("Found %d cross-environment violations", len(cross_env))

    infra_hubs = analyze_infrastructure_hubs(applications)
    log.info("Found %d infrastructure hubs", len(infra_hubs))

    duration = round(time.time() - start_time, 1)
    log.info("Scan complete in %.1fs", duration)

    return {
        "dependencies": dependencies,
        "applications": applications,
        "spof": spof,
        "cycles": cycles,
        "cross_env": cross_env,
        "infrastructure_hubs": infra_hubs,
        "workload_count": len(workloads),
        "flow_count": len(flows),
        "scan_duration": duration,
    }


# ---------------------------------------------------------------------------
# Background poller
# ---------------------------------------------------------------------------

def poller_loop(pce):
    while True:
        do_scan = False
        with state_lock:
            if app_state["scan_requested"]:
                app_state["scan_requested"] = False
                do_scan = True

        if do_scan or app_state["last_scan"] is None:
            pass  # Always run
        else:
            time.sleep(30)
            try:
                last = datetime.fromisoformat(app_state["last_scan"].replace("Z", "+00:00"))
                elapsed = (datetime.now(timezone.utc) - last).total_seconds()
                if elapsed < SCAN_INTERVAL:
                    continue
            except (ValueError, TypeError, AttributeError):
                pass

        try:
            with state_lock:
                app_state["scanning"] = True
                app_state["error"] = None

            result = run_full_scan(pce)

            with state_lock:
                app_state["dependencies"] = result["dependencies"]
                app_state["applications"] = result["applications"]
                app_state["spof"] = result["spof"]
                app_state["cycles"] = result["cycles"]
                app_state["cross_env"] = result["cross_env"]
                app_state["infrastructure_hubs"] = result["infrastructure_hubs"]
                app_state["workload_count"] = result["workload_count"]
                app_state["flow_count"] = result["flow_count"]
                app_state["scan_duration"] = result["scan_duration"]
                app_state["last_scan"] = datetime.now(timezone.utc).isoformat()
                app_state["scan_count"] += 1
                app_state["scanning"] = False

            log.info("State updated: %d deps, %d apps, %d SPOFs, %d cycles, %d cross-env, %d hubs",
                     len(result["dependencies"]), len(result["applications"]),
                     len(result["spof"]), len(result["cycles"]),
                     len(result["cross_env"]), len(result["infrastructure_hubs"]))

        except Exception as e:
            log.error("Scan failed: %s", e, exc_info=True)
            with state_lock:
                app_state["scanning"] = False
                app_state["error"] = str(e)

        time.sleep(60)


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Application Dependency Intelligence</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>
tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}
</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#11111b}
::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.tab-btn{transition:all 0.15s}
.tab-btn.active{background:#313244;color:#cdd6f4;border-color:#89b4fa}
.tab-btn:not(.active){color:#6c7086}
.risk-critical{color:#f38ba8;background:rgba(243,139,168,0.1);border:1px solid rgba(243,139,168,0.3)}
.risk-high{color:#fab387;background:rgba(250,179,135,0.1);border:1px solid rgba(250,179,135,0.3)}
.risk-warning{color:#f9e2af;background:rgba(249,226,175,0.1);border:1px solid rgba(249,226,175,0.3)}
.risk-medium{color:#f9e2af;background:rgba(249,226,175,0.1);border:1px solid rgba(249,226,175,0.3)}
.risk-low{color:#a6e3a1;background:rgba(166,227,161,0.1);border:1px solid rgba(166,227,161,0.3)}
.strength-strong{color:#a6e3a1}
.strength-moderate{color:#f9e2af}
.strength-weak{color:#6c7086}
.node-tooltip{position:absolute;background:#1e1e2e;border:1px solid #313244;border-radius:8px;padding:12px;pointer-events:none;z-index:50;max-width:300px;font-size:12px}
.graph-container{position:relative;width:100%;height:500px;background:#11111b;border-radius:8px;overflow:hidden}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.scanning-pulse{animation:pulse 2s infinite}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-6">

<!-- Header -->
<div class="flex items-center justify-between mb-6">
  <div>
    <h1 class="text-2xl font-bold text-white flex items-center gap-2">
      <svg class="w-7 h-7 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
      Application Dependency Intelligence
    </h1>
    <div class="flex items-center gap-2 mt-1">
      <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
      <span id="status-text" class="text-sm text-gray-400">Loading...</span>
    </div>
  </div>
  <button onclick="triggerScan()" id="scan-btn" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Scan Now</button>
</div>

<!-- Stats Bar -->
<div class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4 text-center">
    <div id="stat-apps" class="text-2xl font-bold text-blue-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Applications</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4 text-center">
    <div id="stat-deps" class="text-2xl font-bold text-purple-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Dependencies</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4 text-center">
    <div id="stat-crossenv" class="text-2xl font-bold text-yellow-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Cross-Env</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4 text-center">
    <div id="stat-spof" class="text-2xl font-bold text-red-400">--</div>
    <div class="text-xs text-gray-500 mt-1">SPOFs</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4 text-center">
    <div id="stat-cycles" class="text-2xl font-bold text-orange-400">--</div>
    <div class="text-xs text-gray-500 mt-1">Cycles</div>
  </div>
</div>

<!-- Tabs -->
<div class="flex gap-1 mb-6 overflow-x-auto border-b border-gray-700 pb-px">
  <button onclick="switchTab('graph')" class="tab-btn active px-4 py-2 text-sm font-medium rounded-t border border-b-0 border-transparent" data-tab="graph">Dependency Graph</button>
  <button onclick="switchTab('blast')" class="tab-btn px-4 py-2 text-sm font-medium rounded-t border border-b-0 border-transparent" data-tab="blast">Blast Radius</button>
  <button onclick="switchTab('resiliency')" class="tab-btn px-4 py-2 text-sm font-medium rounded-t border border-b-0 border-transparent" data-tab="resiliency">Resiliency</button>
  <button onclick="switchTab('compliance')" class="tab-btn px-4 py-2 text-sm font-medium rounded-t border border-b-0 border-transparent" data-tab="compliance">Compliance</button>
  <button onclick="switchTab('impact')" class="tab-btn px-4 py-2 text-sm font-medium rounded-t border border-b-0 border-transparent" data-tab="impact">Change Impact</button>
  <button onclick="switchTab('export')" class="tab-btn px-4 py-2 text-sm font-medium rounded-t border border-b-0 border-transparent" data-tab="export">Export</button>
</div>

<!-- Tab Content -->
<div id="tab-graph" class="tab-content">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4">
    <div class="flex items-center justify-between mb-3">
      <h3 class="text-sm font-semibold text-gray-400">Application Dependency Graph</h3>
      <div class="flex gap-2 text-xs text-gray-500">
        <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full" style="background:#a6e3a1"></span> prod</span>
        <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full" style="background:#89b4fa"></span> dev</span>
        <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full" style="background:#f9e2af"></span> staging</span>
        <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full" style="background:#cba6f7"></span> other</span>
        <span class="flex items-center gap-1"><span class="w-4 h-4 border-2 border-red-400 rounded-full"></span> hub</span>
      </div>
    </div>
    <div id="graph-container" class="graph-container"></div>
    <div id="node-detail" class="mt-4 p-4 bg-dark-900 rounded-lg border border-gray-700" style="display:none">
      <h4 id="detail-title" class="text-white font-semibold mb-2"></h4>
      <div id="detail-body" class="text-sm text-gray-400"></div>
    </div>
  </div>
</div>

<div id="tab-blast" class="tab-content" style="display:none">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
    <h3 class="text-lg font-semibold text-white mb-4">Blast Radius Calculator</h3>
    <div class="flex gap-3 mb-6">
      <input id="blast-input" type="text" placeholder="Enter application (e.g. shareddb|prod)" list="app-list"
             class="flex-1 bg-dark-900 border border-gray-600 rounded px-3 py-2 text-sm text-gray-300">
      <datalist id="app-list"></datalist>
      <button onclick="runBlastRadius()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded text-sm font-medium">Analyze</button>
    </div>
    <div id="blast-result" class="hidden">
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-dark-900 rounded-lg border border-gray-700 p-4 text-center">
          <div id="blast-target" class="text-sm text-blue-400 font-semibold truncate">--</div>
          <div class="text-xs text-gray-500 mt-1">Target</div>
        </div>
        <div class="bg-dark-900 rounded-lg border border-gray-700 p-4 text-center">
          <div id="blast-direct" class="text-2xl font-bold text-red-400">--</div>
          <div class="text-xs text-gray-500 mt-1">Directly Affected</div>
        </div>
        <div class="bg-dark-900 rounded-lg border border-gray-700 p-4 text-center">
          <div id="blast-transitive" class="text-2xl font-bold text-orange-400">--</div>
          <div class="text-xs text-gray-500 mt-1">Transitively Affected</div>
        </div>
        <div class="bg-dark-900 rounded-lg border border-gray-700 p-4 text-center">
          <div id="blast-workloads" class="text-2xl font-bold text-yellow-400">--</div>
          <div class="text-xs text-gray-500 mt-1">Total Workloads</div>
        </div>
      </div>
      <div id="blast-visual" class="flex justify-center mb-6"></div>
      <div id="blast-chain" class="text-sm text-gray-400"></div>
    </div>
    <div id="blast-error" class="text-red-400 text-sm hidden"></div>
  </div>
</div>

<div id="tab-resiliency" class="tab-content" style="display:none">
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- SPOFs -->
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Single Points of Failure</h3>
      <div id="spof-table" class="overflow-x-auto">
        <p class="text-sm text-gray-500">No data yet.</p>
      </div>
    </div>
    <!-- Cycles -->
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Circular Dependencies</h3>
      <div id="cycles-list">
        <p class="text-sm text-gray-500">No data yet.</p>
      </div>
    </div>
  </div>
  <!-- Resiliency scores -->
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 mt-6">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Application Resiliency Scores</h3>
    <div id="resiliency-scores" class="overflow-x-auto">
      <p class="text-sm text-gray-500">No data yet.</p>
    </div>
  </div>
</div>

<div id="tab-compliance" class="tab-content" style="display:none">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 mb-6">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Cross-Environment Dependency Matrix</h3>
    <div id="env-heatmap"></div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <h3 class="text-sm font-semibold text-gray-400 mb-3">Cross-Environment Violations</h3>
    <div id="violations-table" class="overflow-x-auto">
      <p class="text-sm text-gray-500">No data yet.</p>
    </div>
  </div>
</div>

<div id="tab-impact" class="tab-content" style="display:none">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
    <h3 class="text-lg font-semibold text-white mb-4">Change Impact Planner</h3>
    <div class="mb-4">
      <label class="text-sm text-gray-400 block mb-2">Enter hostnames or IPs (one per line):</label>
      <textarea id="impact-input" rows="5" placeholder="db01.shareddb.prod&#10;db02.shareddb.prod&#10;10.0.1.50"
                class="w-full bg-dark-900 border border-gray-600 rounded px-3 py-2 text-sm text-gray-300 font-mono"></textarea>
    </div>
    <button onclick="runImpact()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded text-sm font-medium mb-6">Analyze Impact</button>
    <div id="impact-result" class="hidden">
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div class="bg-dark-900 rounded-lg border border-gray-700 p-4 text-center">
          <div id="impact-apps" class="text-2xl font-bold text-red-400">--</div>
          <div class="text-xs text-gray-500 mt-1">Affected Applications</div>
        </div>
        <div class="bg-dark-900 rounded-lg border border-gray-700 p-4 text-center">
          <div id="impact-wl" class="text-2xl font-bold text-orange-400">--</div>
          <div class="text-xs text-gray-500 mt-1">Affected Workloads</div>
        </div>
        <div class="bg-dark-900 rounded-lg border border-gray-700 p-4 text-center">
          <div id="impact-risk" class="text-2xl font-bold text-yellow-400">--</div>
          <div class="text-xs text-gray-500 mt-1">Risk Level</div>
        </div>
      </div>
      <div id="impact-notifications" class="mb-4"></div>
      <div id="impact-details" class="text-sm text-gray-400"></div>
    </div>
    <div id="impact-error" class="text-red-400 text-sm hidden"></div>
  </div>
</div>

<div id="tab-export" class="tab-content" style="display:none">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-6">
    <h3 class="text-lg font-semibold text-white mb-4">Export Data</h3>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="bg-dark-900 rounded-lg border border-gray-700 p-6 text-center">
        <svg class="w-12 h-12 mx-auto text-blue-400 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
        <h4 class="text-white font-medium mb-2">JSON Export</h4>
        <p class="text-xs text-gray-500 mb-4">Full dependency data including applications, analysis results, and metadata.</p>
        <button onclick="downloadJSON()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded text-sm font-medium">Download JSON</button>
      </div>
      <div class="bg-dark-900 rounded-lg border border-gray-700 p-6 text-center">
        <svg class="w-12 h-12 mx-auto text-green-400 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3M3 17V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>
        <h4 class="text-white font-medium mb-2">CSV Export</h4>
        <p class="text-xs text-gray-500 mb-4">Dependency pairs with services and connection volumes for spreadsheet analysis.</p>
        <button onclick="downloadCSV()" class="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded text-sm font-medium">Download CSV</button>
      </div>
    </div>
  </div>
</div>

<!-- Footer -->
<div class="text-center text-xs text-gray-600 py-4">
  Application Dependency Intelligence — Powered by Illumio Plugger
</div>

</div>

<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\\/plugins\\/[^/]+\\/ui/);return m?m[0]:''})();
let stateData=null;

function formatNum(n){
  if(n>=1e6)return(n/1e6).toFixed(1)+'M';
  if(n>=1e3)return(n/1e3).toFixed(1)+'K';
  return String(n);
}

// --- Tab switching ---
function switchTab(tab){
  document.querySelectorAll('.tab-content').forEach(el=>el.style.display='none');
  document.querySelectorAll('.tab-btn').forEach(btn=>btn.classList.remove('active'));
  document.getElementById('tab-'+tab).style.display='block';
  document.querySelector('[data-tab="'+tab+'"]').classList.add('active');
  if(tab==='graph'&&stateData)renderGraph(stateData);
}

// --- Fetch state and render ---
async function fetchState(){
  try{
    const resp=await fetch(BASE+'/api/state');
    const data=await resp.json();
    stateData=data;
    updateStatus(data);
    updateStats(data);
    populateAppList(data);
    renderGraph(data);
    renderSpof(data.spof||[]);
    renderCycles(data.cycles||[]);
    renderResiliencyScores(data.applications||{},data.spof||[],data.cycles||[]);
    renderEnvHeatmap(data.dependencies||[],data.applications||{});
    renderViolations(data.cross_env||[]);
  }catch(e){
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-red-500';
    document.getElementById('status-text').textContent='Connection error';
  }
}

function updateStatus(data){
  const dot=document.getElementById('status-dot');
  const txt=document.getElementById('status-text');
  if(data.scanning){
    dot.className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning-pulse';
    txt.textContent='Scanning in progress...';
  }else if(data.error){
    dot.className='w-2.5 h-2.5 rounded-full bg-red-500';
    txt.textContent='Error: '+data.error;
  }else if(data.last_scan){
    dot.className='w-2.5 h-2.5 rounded-full bg-green-500';
    const ago=timeAgo(data.last_scan);
    txt.textContent=`Last scan: ${ago} | ${data.workload_count} workloads | ${data.flow_count} flows | ${(data.scan_duration||0).toFixed(1)}s`;
  }else{
    dot.className='w-2.5 h-2.5 rounded-full bg-gray-500';
    txt.textContent='No scan yet. Click Scan Now.';
  }
}

function timeAgo(ts){
  if(!ts)return '--';
  const d=(Date.now()-new Date(ts).getTime())/1000;
  if(d<60)return 'just now';
  if(d<3600)return Math.floor(d/60)+'m ago';
  if(d<86400)return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}

function updateStats(data){
  const apps=data.applications||{};
  const deps=data.dependencies||[];
  document.getElementById('stat-apps').textContent=Object.keys(apps).length;
  document.getElementById('stat-deps').textContent=deps.length;
  document.getElementById('stat-crossenv').textContent=(data.cross_env||[]).length;
  document.getElementById('stat-spof').textContent=(data.spof||[]).length;
  document.getElementById('stat-cycles').textContent=(data.cycles||[]).length;
}

function populateAppList(data){
  const dl=document.getElementById('app-list');
  dl.innerHTML='';
  for(const key of Object.keys(data.applications||{}).sort()){
    const opt=document.createElement('option');
    opt.value=key;
    dl.appendChild(opt);
  }
}

// --- Dependency Graph (D3.js) ---
let simulation=null;
function renderGraph(data){
  const container=document.getElementById('graph-container');
  container.innerHTML='';
  const apps=data.applications||{};
  const deps=data.dependencies||[];
  if(!Object.keys(apps).length){
    container.innerHTML='<div class="flex items-center justify-center h-full text-gray-500 text-sm">No dependency data available yet.</div>';
    return;
  }

  const width=container.clientWidth;
  const height=container.clientHeight||500;

  const envColors={
    'production':'#a6e3a1','prod':'#a6e3a1','prd':'#a6e3a1',
    'development':'#89b4fa','dev':'#89b4fa',
    'staging':'#f9e2af','stg':'#f9e2af',
    'test':'#94e2d5','tst':'#94e2d5','qa':'#94e2d5','uat':'#94e2d5',
  };

  const nodes=Object.values(apps).map(a=>({
    id:a.key,
    app:a.app,
    env:a.env,
    wl:a.workload_count,
    isInfra:a.is_infrastructure,
    inbound:a.dependency_count_inbound,
    outbound:a.dependency_count_outbound,
    roles:a.roles,
    r:Math.max(8,Math.min(30,5+Math.sqrt(a.workload_count)*4)),
    color:envColors[a.env.toLowerCase()]||'#cba6f7',
  }));

  const nodeMap={};
  nodes.forEach(n=>{nodeMap[n.id]=n});

  const links=deps.map(d=>({
    source:d.consumer.key,
    target:d.provider.key,
    volume:d.connection_volume,
    strength:d.strength,
    services:d.services.map(s=>s.label).join(', '),
  })).filter(l=>nodeMap[l.source]&&nodeMap[l.target]);

  const maxVol=Math.max(1,...links.map(l=>l.volume));

  const svg=d3.select(container).append('svg')
    .attr('width',width).attr('height',height)
    .attr('viewBox',[0,0,width,height]);

  // Arrow markers
  svg.append('defs').append('marker')
    .attr('id','arrow').attr('viewBox','0 -5 10 10')
    .attr('refX',20).attr('refY',0)
    .attr('markerWidth',6).attr('markerHeight',6)
    .attr('orient','auto')
    .append('path').attr('d','M0,-5L10,0L0,5').attr('fill','#585b70');

  const link=svg.append('g').selectAll('line').data(links).join('line')
    .attr('stroke','#585b70')
    .attr('stroke-opacity',0.5)
    .attr('stroke-width',l=>Math.max(1,Math.min(5,(l.volume/maxVol)*5)))
    .attr('marker-end','url(#arrow)');

  const node=svg.append('g').selectAll('g').data(nodes).join('g')
    .call(d3.drag()
      .on('start',(e,d)=>{if(!e.active)simulation.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;})
      .on('drag',(e,d)=>{d.fx=e.x;d.fy=e.y;})
      .on('end',(e,d)=>{if(!e.active)simulation.alphaTarget(0);d.fx=null;d.fy=null;})
    );

  node.append('circle')
    .attr('r',d=>d.r)
    .attr('fill',d=>d.color)
    .attr('fill-opacity',0.8)
    .attr('stroke',d=>d.isInfra?'#f38ba8':'#45475a')
    .attr('stroke-width',d=>d.isInfra?3:1.5);

  node.append('text')
    .text(d=>d.app)
    .attr('text-anchor','middle')
    .attr('dy','0.35em')
    .attr('font-size',d=>Math.max(8,Math.min(12,d.r*0.7)))
    .attr('fill','#11111b')
    .attr('font-weight','600')
    .attr('pointer-events','none');

  // Tooltip
  const tooltip=d3.select(container).append('div')
    .attr('class','node-tooltip').style('display','none');

  node.on('mouseover',(e,d)=>{
    tooltip.style('display','block')
      .html(`<div class="font-semibold text-white mb-1">${d.app} | ${d.env}</div>
        <div>Workloads: ${d.wl}</div>
        <div>Inbound deps: ${d.inbound}</div>
        <div>Outbound deps: ${d.outbound}</div>
        <div>Roles: ${d.roles.join(', ')||'--'}</div>
        ${d.isInfra?'<div class="text-red-400 mt-1">Infrastructure Hub</div>':''}`)
      .style('left',(e.offsetX+15)+'px')
      .style('top',(e.offsetY-10)+'px');
  }).on('mousemove',(e)=>{
    tooltip.style('left',(e.offsetX+15)+'px').style('top',(e.offsetY-10)+'px');
  }).on('mouseout',()=>{
    tooltip.style('display','none');
  }).on('click',(e,d)=>{
    showNodeDetail(d);
  });

  if(simulation)simulation.stop();
  simulation=d3.forceSimulation(nodes)
    .force('link',d3.forceLink(links).id(d=>d.id).distance(100))
    .force('charge',d3.forceManyBody().strength(-300))
    .force('center',d3.forceCenter(width/2,height/2))
    .force('collision',d3.forceCollide().radius(d=>d.r+5))
    .on('tick',()=>{
      link
        .attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
        .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
      node.attr('transform',d=>`translate(${d.x},${d.y})`);
    });
}

function showNodeDetail(d){
  const detail=document.getElementById('node-detail');
  detail.style.display='block';
  document.getElementById('detail-title').textContent=d.app+' | '+d.env;
  const apps=stateData?.applications||{};
  const appNode=apps[d.id]||{};
  let html=`<div class="grid grid-cols-2 gap-4">
    <div><span class="text-gray-500">Workloads:</span> <span class="text-white">${d.wl}</span></div>
    <div><span class="text-gray-500">Roles:</span> <span class="text-white">${d.roles.join(', ')||'--'}</span></div>
    <div><span class="text-gray-500">Inbound:</span> <span class="text-white">${d.inbound}</span></div>
    <div><span class="text-gray-500">Outbound:</span> <span class="text-white">${d.outbound}</span></div>
    <div><span class="text-gray-500">Infrastructure:</span> <span class="text-white">${d.isInfra?'Yes':'No'}</span></div>
  </div>`;
  if(appNode.depends_on&&appNode.depends_on.length){
    html+=`<div class="mt-3"><span class="text-gray-500">Depends on:</span><ul class="mt-1 ml-4 list-disc text-blue-400">`;
    appNode.depends_on.forEach(k=>{html+=`<li>${k}</li>`;});
    html+=`</ul></div>`;
  }
  if(appNode.depended_by&&appNode.depended_by.length){
    html+=`<div class="mt-3"><span class="text-gray-500">Depended by:</span><ul class="mt-1 ml-4 list-disc text-red-400">`;
    appNode.depended_by.forEach(k=>{html+=`<li>${k}</li>`;});
    html+=`</ul></div>`;
  }
  document.getElementById('detail-body').innerHTML=html;
}

// --- Blast Radius ---
async function runBlastRadius(){
  const target=document.getElementById('blast-input').value.trim();
  if(!target)return;
  const errEl=document.getElementById('blast-error');
  const resEl=document.getElementById('blast-result');
  errEl.classList.add('hidden');
  resEl.classList.add('hidden');
  try{
    const resp=await fetch(BASE+'/api/blast-radius',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({target})
    });
    const data=await resp.json();
    if(data.error){
      errEl.textContent=data.error;errEl.classList.remove('hidden');return;
    }
    resEl.classList.remove('hidden');
    document.getElementById('blast-target').textContent=data.target;
    document.getElementById('blast-direct').textContent=data.directly_affected.length;
    document.getElementById('blast-transitive').textContent=data.transitively_affected.length;
    document.getElementById('blast-workloads').textContent=data.total_affected_workloads;

    // Concentric circles visualization
    renderBlastVisual(data);

    // Chain details
    let chainHtml='<h4 class="text-white font-semibold mb-2">Dependency Chain</h4>';
    if(data.directly_affected.length){
      chainHtml+='<div class="mb-2"><span class="text-gray-500">Directly affected:</span>';
      chainHtml+='<div class="flex flex-wrap gap-2 mt-1">';
      data.directly_affected.forEach(a=>{chainHtml+=`<span class="risk-critical px-2 py-1 rounded text-xs">${a}</span>`;});
      chainHtml+='</div></div>';
    }
    if(data.transitively_affected.length){
      chainHtml+='<div class="mb-2"><span class="text-gray-500">Transitively affected:</span>';
      chainHtml+='<div class="flex flex-wrap gap-2 mt-1">';
      data.transitively_affected.forEach(a=>{chainHtml+=`<span class="risk-warning px-2 py-1 rounded text-xs">${a}</span>`;});
      chainHtml+='</div></div>';
    }
    if(!data.directly_affected.length&&!data.transitively_affected.length){
      chainHtml+='<p class="text-gray-500">No downstream dependencies found for this application.</p>';
    }
    document.getElementById('blast-chain').innerHTML=chainHtml;
  }catch(e){
    errEl.textContent='Failed to analyze: '+e.message;errEl.classList.remove('hidden');
  }
}

function renderBlastVisual(data){
  const container=document.getElementById('blast-visual');
  container.innerHTML='';
  const w=400,h=300,cx=w/2,cy=h/2;
  const svg=d3.select(container).append('svg').attr('width',w).attr('height',h);

  // Target center
  svg.append('circle').attr('cx',cx).attr('cy',cy).attr('r',30)
    .attr('fill','#89b4fa').attr('fill-opacity',0.3).attr('stroke','#89b4fa').attr('stroke-width',2);
  svg.append('text').attr('x',cx).attr('y',cy).attr('text-anchor','middle').attr('dy','0.35em')
    .attr('fill','#89b4fa').attr('font-size',10).attr('font-weight','600')
    .text(data.target_app||data.target.split('|')[0]);

  // Ring 1: directly affected
  if(data.directly_affected.length){
    svg.append('circle').attr('cx',cx).attr('cy',cy).attr('r',90)
      .attr('fill','none').attr('stroke','#f38ba8').attr('stroke-width',1).attr('stroke-dasharray','4,4');
    const step=2*Math.PI/Math.max(data.directly_affected.length,1);
    data.directly_affected.forEach((a,i)=>{
      const angle=step*i-Math.PI/2;
      const x=cx+Math.cos(angle)*90;
      const y=cy+Math.sin(angle)*90;
      svg.append('circle').attr('cx',x).attr('cy',y).attr('r',15)
        .attr('fill','#f38ba8').attr('fill-opacity',0.2).attr('stroke','#f38ba8').attr('stroke-width',1.5);
      svg.append('text').attr('x',x).attr('y',y).attr('text-anchor','middle').attr('dy','0.35em')
        .attr('fill','#f38ba8').attr('font-size',8).text(a.split('|')[0]);
    });
  }

  // Ring 2: transitively affected
  if(data.transitively_affected.length){
    svg.append('circle').attr('cx',cx).attr('cy',cy).attr('r',140)
      .attr('fill','none').attr('stroke','#fab387').attr('stroke-width',1).attr('stroke-dasharray','4,4');
    const step=2*Math.PI/Math.max(data.transitively_affected.length,1);
    data.transitively_affected.forEach((a,i)=>{
      const angle=step*i-Math.PI/2;
      const x=cx+Math.cos(angle)*140;
      const y=cy+Math.sin(angle)*140;
      svg.append('circle').attr('cx',x).attr('cy',y).attr('r',12)
        .attr('fill','#fab387').attr('fill-opacity',0.2).attr('stroke','#fab387').attr('stroke-width',1);
      svg.append('text').attr('x',x).attr('y',y).attr('text-anchor','middle').attr('dy','0.35em')
        .attr('fill','#fab387').attr('font-size',7).text(a.split('|')[0]);
    });
  }
}

// --- Resiliency Tab ---
function renderSpof(spofs){
  const container=document.getElementById('spof-table');
  if(!spofs.length){container.innerHTML='<p class="text-sm text-gray-500">No single points of failure detected.</p>';return;}
  let html=`<table class="w-full text-sm"><thead><tr class="text-left text-xs text-gray-500 uppercase border-b border-gray-700">
    <th class="px-3 py-2">Provider</th><th class="px-3 py-2">WL Count</th><th class="px-3 py-2">Consumers</th><th class="px-3 py-2">Risk</th>
  </tr></thead><tbody>`;
  spofs.forEach(s=>{
    html+=`<tr class="border-b border-gray-700/50 hover:bg-dark-900">
      <td class="px-3 py-2 text-gray-300">${s.provider.key}</td>
      <td class="px-3 py-2 text-gray-400">${s.workload_count}</td>
      <td class="px-3 py-2 text-gray-400">${s.consumer_count}</td>
      <td class="px-3 py-2"><span class="risk-${s.risk} px-2 py-0.5 rounded text-xs">${s.risk}</span></td>
    </tr>`;
  });
  html+='</tbody></table>';
  container.innerHTML=html;
}

function renderCycles(cycles){
  const container=document.getElementById('cycles-list');
  if(!cycles.length){container.innerHTML='<p class="text-sm text-gray-500">No circular dependencies detected.</p>';return;}
  let html='';
  cycles.forEach((c,i)=>{
    html+=`<div class="mb-3 p-3 bg-dark-900 rounded-lg border border-gray-700">
      <div class="text-sm text-orange-400 font-medium mb-1">Cycle ${i+1} (length: ${c.length})</div>
      <div class="text-xs text-gray-400 font-mono">${c.path.join(' -> ')}</div>
      <div class="text-xs text-gray-500 mt-1">${c.risk}</div>
    </div>`;
  });
  container.innerHTML=html;
}

function renderResiliencyScores(apps,spofs,cycles){
  const container=document.getElementById('resiliency-scores');
  const keys=Object.keys(apps).sort();
  if(!keys.length){container.innerHTML='<p class="text-sm text-gray-500">No data yet.</p>';return;}

  const spofKeys=new Set(spofs.map(s=>s.provider.key));
  const cycleKeys=new Set();
  cycles.forEach(c=>{c.path.forEach(p=>cycleKeys.add(p));});

  let html=`<table class="w-full text-sm"><thead><tr class="text-left text-xs text-gray-500 uppercase border-b border-gray-700">
    <th class="px-3 py-2">Application</th><th class="px-3 py-2">Env</th><th class="px-3 py-2">Workloads</th>
    <th class="px-3 py-2">In</th><th class="px-3 py-2">Out</th><th class="px-3 py-2">Score</th><th class="px-3 py-2">Issues</th>
  </tr></thead><tbody>`;

  keys.forEach(key=>{
    const a=apps[key];
    let score=100;
    const issues=[];
    if(spofKeys.has(key)){score-=30;issues.push('SPOF');}
    if(cycleKeys.has(key)){score-=20;issues.push('Cycle');}
    if(a.workload_count<=1){score-=10;issues.push('Single WL');}
    if(a.dependency_count_outbound>5){score-=5;issues.push('High deps');}
    score=Math.max(0,score);
    const color=score>=80?'text-green-400':score>=50?'text-yellow-400':'text-red-400';

    html+=`<tr class="border-b border-gray-700/50 hover:bg-dark-900">
      <td class="px-3 py-2 text-gray-300">${a.app}</td>
      <td class="px-3 py-2 text-gray-400">${a.env}</td>
      <td class="px-3 py-2 text-gray-400">${a.workload_count}</td>
      <td class="px-3 py-2 text-gray-400">${a.dependency_count_inbound}</td>
      <td class="px-3 py-2 text-gray-400">${a.dependency_count_outbound}</td>
      <td class="px-3 py-2 ${color} font-bold">${score}</td>
      <td class="px-3 py-2 text-xs text-gray-500">${issues.join(', ')||'--'}</td>
    </tr>`;
  });
  html+='</tbody></table>';
  container.innerHTML=html;
}

// --- Compliance Tab ---
function renderEnvHeatmap(deps,apps){
  const container=document.getElementById('env-heatmap');
  if(!deps.length){container.innerHTML='<p class="text-sm text-gray-500">No dependency data available.</p>';return;}

  // Build env matrix
  const matrix={};
  const envSet=new Set();
  deps.forEach(d=>{
    const ce=d.consumer.env;
    const pe=d.provider.env;
    envSet.add(ce);envSet.add(pe);
    const key=ce+'|'+pe;
    if(!matrix[key])matrix[key]={total:0,count:0};
    matrix[key].total+=d.connection_volume;
    matrix[key].count++;
  });
  const envs=[...envSet].sort();
  if(!envs.length){container.innerHTML='<p class="text-sm text-gray-500">No environment data.</p>';return;}

  const maxTotal=Math.max(1,...Object.values(matrix).map(m=>m.total));
  let html=`<div style="display:grid;grid-template-columns:100px repeat(${envs.length},1fr);gap:2px;max-width:100%;overflow-x:auto">`;
  html+='<div class="text-xs text-gray-500 p-1">src \\\\ dst</div>';
  envs.forEach(e=>{html+=`<div class="text-center text-xs text-gray-500 p-1 truncate">${e}</div>`;});

  envs.forEach(srcEnv=>{
    html+=`<div class="text-xs text-gray-400 p-1 text-right truncate">${srcEnv}</div>`;
    envs.forEach(dstEnv=>{
      const key=srcEnv+'|'+dstEnv;
      const cell=matrix[key];
      const total=cell?cell.total:0;
      const count=cell?cell.count:0;
      const intensity=total/maxTotal;
      let bg;
      if(srcEnv===dstEnv){
        bg=`rgba(137,180,250,${0.05+intensity*0.5})`;
      }else{
        const sLow=srcEnv.toLowerCase();
        const dLow=dstEnv.toLowerCase();
        const crossProdDev=(sLow in {'prod':1,'production':1,'prd':1}&&dLow in {'dev':1,'development':1})||
                           (dLow in {'prod':1,'production':1,'prd':1}&&sLow in {'dev':1,'development':1});
        if(crossProdDev&&total>0)bg=`rgba(243,139,168,${0.2+intensity*0.8})`;
        else if(total>0)bg=`rgba(249,226,175,${0.1+intensity*0.5})`;
        else bg='rgba(49,50,68,0.2)';
      }
      html+=`<div style="background:${bg};padding:6px;text-align:center;border-radius:3px;font-size:11px;color:#cdd6f4;cursor:default" title="${srcEnv} -> ${dstEnv}: ${total.toLocaleString()} connections (${count} deps)">${total>0?formatNum(total):'--'}</div>`;
    });
  });
  html+='</div>';
  container.innerHTML=html;
}

function renderViolations(violations){
  const container=document.getElementById('violations-table');
  if(!violations.length){container.innerHTML='<p class="text-sm text-gray-500">No cross-environment violations detected.</p>';return;}
  let html=`<table class="w-full text-sm"><thead><tr class="text-left text-xs text-gray-500 uppercase border-b border-gray-700">
    <th class="px-3 py-2">Consumer</th><th class="px-3 py-2">Provider</th><th class="px-3 py-2">Services</th>
    <th class="px-3 py-2">Volume</th><th class="px-3 py-2">Risk</th>
  </tr></thead><tbody>`;
  violations.forEach(v=>{
    html+=`<tr class="border-b border-gray-700/50 hover:bg-dark-900">
      <td class="px-3 py-2 text-gray-300">${v.consumer}</td>
      <td class="px-3 py-2 text-gray-300">${v.provider}</td>
      <td class="px-3 py-2 text-gray-400 text-xs">${v.services||'--'}</td>
      <td class="px-3 py-2 text-gray-400">${formatNum(v.connection_volume)}</td>
      <td class="px-3 py-2"><span class="risk-${v.risk} px-2 py-0.5 rounded text-xs">${v.risk}</span></td>
    </tr>`;
  });
  html+='</tbody></table>';
  container.innerHTML=html;
}

// --- Change Impact ---
async function runImpact(){
  const input=document.getElementById('impact-input').value.trim();
  if(!input)return;
  const targets=input.split('\\n').map(s=>s.trim()).filter(Boolean);
  const errEl=document.getElementById('impact-error');
  const resEl=document.getElementById('impact-result');
  errEl.classList.add('hidden');
  resEl.classList.add('hidden');
  try{
    const resp=await fetch(BASE+'/api/impact',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({targets})
    });
    const data=await resp.json();
    if(data.error){
      errEl.textContent=data.error;errEl.classList.remove('hidden');return;
    }
    resEl.classList.remove('hidden');
    document.getElementById('impact-apps').textContent=data.affected_applications;
    document.getElementById('impact-wl').textContent=data.affected_workloads;
    const riskEl=document.getElementById('impact-risk');
    riskEl.textContent=data.maintenance_window_risk;
    riskEl.className='text-2xl font-bold '+({critical:'text-red-400',high:'text-orange-400',medium:'text-yellow-400',low:'text-green-400'}[data.maintenance_window_risk]||'text-gray-400');

    // Notifications
    let notifHtml='';
    if(data.recommended_notification&&data.recommended_notification.length){
      notifHtml+='<h4 class="text-white font-semibold mb-2">Recommended Notifications</h4>';
      notifHtml+='<div class="space-y-1">';
      data.recommended_notification.forEach(n=>{
        notifHtml+=`<div class="text-sm text-gray-400 bg-dark-900 rounded px-3 py-2 border border-gray-700">${n}</div>`;
      });
      notifHtml+='</div>';
    }
    document.getElementById('impact-notifications').innerHTML=notifHtml;

    // Target mapping
    let detailHtml='<h4 class="text-white font-semibold mb-2 mt-4">Target Mapping</h4>';
    if(data.target_mapping){
      detailHtml+='<div class="grid grid-cols-1 md:grid-cols-2 gap-2">';
      Object.entries(data.target_mapping).forEach(([t,k])=>{
        detailHtml+=`<div class="text-xs bg-dark-900 rounded px-3 py-2 border border-gray-700">
          <span class="text-gray-400 font-mono">${t}</span>
          <span class="text-gray-600 mx-1">-></span>
          <span class="${k?'text-blue-400':'text-red-400'}">${k||'not found'}</span>
        </div>`;
      });
      detailHtml+='</div>';
    }
    if(data.affected_app_list&&data.affected_app_list.length){
      detailHtml+='<h4 class="text-white font-semibold mb-2 mt-4">All Affected Applications</h4>';
      detailHtml+='<div class="flex flex-wrap gap-2">';
      data.affected_app_list.forEach(a=>{
        detailHtml+=`<span class="risk-warning px-2 py-1 rounded text-xs">${a}</span>`;
      });
      detailHtml+='</div>';
    }
    document.getElementById('impact-details').innerHTML=detailHtml;
  }catch(e){
    errEl.textContent='Failed: '+e.message;errEl.classList.remove('hidden');
  }
}

// --- Export ---
function downloadJSON(){
  window.location.href=BASE+'/api/export/json';
}
function downloadCSV(){
  window.location.href=BASE+'/api/export/csv';
}

// --- Scan trigger ---
async function triggerScan(){
  try{
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-yellow-500 scanning-pulse';
    document.getElementById('status-text').textContent='Scan triggered...';
    await fetch(BASE+'/api/scan',{method:'POST'});
  }catch(e){}
}

// --- Init ---
fetchState();
setInterval(fetchState,30000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class DependencyHandler(BaseHTTPRequestHandler):
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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {}

    def do_OPTIONS(self):
        self._send(200, "")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/" or path == "":
            self._send(200, DASHBOARD_HTML, "text/html")

        elif path == "/healthz":
            with state_lock:
                status = "healthy" if not app_state["error"] else "degraded"
            self._send(200, json.dumps({"status": status}))

        elif path == "/api/state":
            with state_lock:
                data = {
                    "last_scan": app_state["last_scan"],
                    "scan_count": app_state["scan_count"],
                    "scanning": app_state["scanning"],
                    "error": app_state["error"],
                    "workload_count": app_state["workload_count"],
                    "flow_count": app_state["flow_count"],
                    "scan_duration": app_state["scan_duration"],
                    "dependencies": app_state["dependencies"],
                    "applications": app_state["applications"],
                    "spof": app_state["spof"],
                    "cycles": app_state["cycles"],
                    "cross_env": app_state["cross_env"],
                    "infrastructure_hubs": app_state["infrastructure_hubs"],
                }
            self._send(200, json.dumps(data, default=str))

        elif path == "/api/dependencies":
            with state_lock:
                deps = app_state["dependencies"]
            self._send(200, json.dumps(deps, default=str))

        elif path == "/api/applications":
            with state_lock:
                apps = app_state["applications"]
            self._send(200, json.dumps(apps, default=str))

        elif path == "/api/spof":
            with state_lock:
                spof = app_state["spof"]
            self._send(200, json.dumps(spof, default=str))

        elif path == "/api/cycles":
            with state_lock:
                cycles = app_state["cycles"]
            self._send(200, json.dumps(cycles, default=str))

        elif path == "/api/cross-env":
            with state_lock:
                cross_env = app_state["cross_env"]
            self._send(200, json.dumps(cross_env, default=str))

        elif path == "/api/infrastructure":
            with state_lock:
                hubs = app_state["infrastructure_hubs"]
            self._send(200, json.dumps(hubs, default=str))

        elif path == "/api/export/json":
            with state_lock:
                export = {
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "last_scan": app_state["last_scan"],
                    "workload_count": app_state["workload_count"],
                    "flow_count": app_state["flow_count"],
                    "dependencies": app_state["dependencies"],
                    "applications": app_state["applications"],
                    "analysis": {
                        "spof": app_state["spof"],
                        "cycles": app_state["cycles"],
                        "cross_env": app_state["cross_env"],
                        "infrastructure_hubs": app_state["infrastructure_hubs"],
                    },
                }
            body = json.dumps(export, indent=2, default=str)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=dependency-intel-export.json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body.encode())

        elif path == "/api/export/csv":
            with state_lock:
                deps = app_state["dependencies"]
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "consumer_app", "consumer_env", "provider_app", "provider_env",
                "services", "strength", "connection_volume",
                "consumer_workload_count", "provider_workload_count",
                "cross_environment", "cross_application", "infrastructure",
                "first_seen", "last_seen",
            ])
            for dep in deps:
                services_str = "; ".join(s.get("label", "") for s in dep.get("services", []))
                writer.writerow([
                    dep["consumer"]["app"], dep["consumer"]["env"],
                    dep["provider"]["app"], dep["provider"]["env"],
                    services_str, dep["strength"], dep["connection_volume"],
                    dep["consumer_workload_count"], dep["provider_workload_count"],
                    dep["cross_environment"], dep["cross_application"], dep["infrastructure"],
                    dep.get("first_seen", ""), dep.get("last_seen", ""),
                ])
            csv_content = output.getvalue()
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", "attachment; filename=dependencies-export.csv")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(csv_content.encode())

        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/scan":
            with state_lock:
                if app_state["scanning"]:
                    self._send(409, json.dumps({"error": "Scan already in progress"}))
                    return
                app_state["scan_requested"] = True
            self._send(200, json.dumps({"status": "scan_requested"}))

        elif path == "/api/blast-radius":
            body = self._read_body()
            target = body.get("target", "").strip()
            if not target:
                self._send(400, json.dumps({"error": "Missing 'target' field"}))
                return
            with state_lock:
                applications = app_state["applications"]
            result = analyze_blast_radius(target, applications)
            self._send(200, json.dumps(result, default=str))

        elif path == "/api/impact":
            body = self._read_body()
            targets = body.get("targets", [])
            if not targets:
                self._send(400, json.dumps({"error": "Missing 'targets' field"}))
                return
            with state_lock:
                applications = app_state["applications"]
            result = analyze_change_impact(targets, applications)
            self._send(200, json.dumps(result, default=str))

        else:
            self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("Application Dependency Intelligence starting...")
    log.info("Config: scan_interval=%ds, lookback=%dd, max_flows=%d, hub_threshold=%d, spof_threshold=%d",
             SCAN_INTERVAL, LOOKBACK_DAYS, MAX_FLOWS, HUB_THRESHOLD, SPOF_THRESHOLD)

    pce = get_pce()

    # Start poller thread
    poller = threading.Thread(target=poller_loop, args=(pce,), daemon=True)
    poller.start()

    # HTTP server
    server = HTTPServer(("0.0.0.0", HTTP_PORT), DependencyHandler)
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
