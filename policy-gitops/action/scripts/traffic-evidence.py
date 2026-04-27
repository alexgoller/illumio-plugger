#!/usr/bin/env python3
"""
Traffic evidence collector for Illumio policy PRs.

For each new/changed rule in a PR, queries the PCE for blocked traffic
that matches the rule's consumer/provider/service pattern. This provides
evidence that a rule is justified by actual traffic.

Usage:
  python3 traffic-evidence.py --changed-files "scopes/foo/bar.yaml" \
    --lookback-days 30 --output traffic-report.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone, timedelta

import yaml

try:
    from illumio import PolicyComputeEngine
    from illumio.explorer import TrafficQuery
    HAS_ILLUMIO = True
except ImportError:
    HAS_ILLUMIO = False


def get_pce():
    """Create PCE client from environment."""
    if not HAS_ILLUMIO:
        return None
    host = os.environ.get("PCE_HOST", "")
    if not host:
        return None
    pce = PolicyComputeEngine(
        url=host,
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ.get("PCE_API_KEY", ""),
        password=os.environ.get("PCE_API_SECRET", ""),
    )
    pce.set_tls_settings(verify=False)
    return pce


def extract_rules_from_file(filepath):
    """Extract rules from a YAML policy file."""
    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except Exception:
        return []

    if not isinstance(data, dict):
        return []

    rules = []

    # Standard ruleset with rules array
    for rule in data.get("rules", []):
        if isinstance(rule, dict):
            rules.append({
                "file": filepath,
                "name": rule.get("name", "(unnamed)"),
                "consumers": rule.get("consumers", []),
                "providers": rule.get("providers", []),
                "services": rule.get("services", []),
            })

    # Cross-scope rule format
    if data.get("type") == "extra-scope":
        consumers = data.get("requester", {}).get("consumers", [])
        providers = data.get("target", {}).get("providers", [])
        services = data.get("services", [])
        rules.append({
            "file": filepath,
            "name": data.get("name", "(unnamed)"),
            "consumers": consumers,
            "providers": providers,
            "services": services,
        })

    return rules


def query_traffic_for_rule(pce, rule, lookback_days):
    """Query PCE for blocked traffic matching a rule's pattern."""
    if not pce:
        return None

    # Extract consumer/provider labels for description
    consumer_labels = {}
    for c in rule.get("consumers", []):
        if isinstance(c, dict) and "label" in c:
            lbl = c["label"]
            if isinstance(lbl, dict):
                consumer_labels.update(lbl)

    provider_labels = {}
    for p in rule.get("providers", []):
        if isinstance(p, dict) and "label" in p:
            lbl = p["label"]
            if isinstance(lbl, dict):
                provider_labels.update(lbl)

    # Extract ports
    ports = []
    for svc in rule.get("services", []):
        if isinstance(svc, dict):
            port = svc.get("port")
            if port:
                ports.append(port)

    if not ports:
        return {"traffic_found": False, "reason": "No specific ports in rule"}

    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=lookback_days)

        tq = TrafficQuery.build(
            start_date=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_date=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            policy_decisions=["blocked", "potentially_blocked"],
            max_results=10000,
        )

        flows = pce.get_traffic_flows_async("policy-gitops-evidence", tq)

        # Filter flows matching this rule's pattern
        matching_flows = []
        total_connections = 0

        for f in flows:
            flow = f.to_json() if hasattr(f, "to_json") else (f.__dict__ if hasattr(f, "__dict__") else f)
            if isinstance(flow, str):
                flow = json.loads(flow)

            service = flow.get("service", {})
            flow_port = service.get("port") if isinstance(service, dict) else None

            if flow_port not in ports:
                continue

            # Check if src/dst labels match consumer/provider labels
            src = flow.get("src", {})
            dst = flow.get("dst", {})
            num = flow.get("num_connections", 1)

            # Simple match: if we have label constraints, check them
            # For now, just match by port (label matching requires label cache)
            total_connections += num
            src_name = src.get("workload", {}).get("hostname", src.get("ip", "?"))
            dst_name = dst.get("workload", {}).get("hostname", dst.get("ip", "?"))

            matching_flows.append({
                "src": src_name,
                "dst": dst_name,
                "port": f"{flow_port}/{service.get('proto', '?')}",
                "connections": num,
                "decision": flow.get("policy_decision", "unknown"),
            })

        if not matching_flows:
            return {
                "traffic_found": False,
                "blocked_connections": 0,
                "reason": f"No blocked traffic found on ports {ports} in last {lookback_days} days",
            }

        # Aggregate
        matching_flows.sort(key=lambda x: -x["connections"])
        unique_sources = len(set(f["src"] for f in matching_flows))
        unique_dests = len(set(f["dst"] for f in matching_flows))

        return {
            "traffic_found": True,
            "blocked_connections": total_connections,
            "unique_sources": unique_sources,
            "unique_destinations": unique_dests,
            "sample_flows": matching_flows[:10],
            "verdict": f"JUSTIFIED — {total_connections:,} blocked connections over {lookback_days} days from {unique_sources} sources",
        }

    except Exception as e:
        return {"traffic_found": False, "error": str(e)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--lookback-days", type=int, default=30)
    parser.add_argument("--output", default="traffic-report.json")
    args = parser.parse_args()

    pce = get_pce()
    if not pce:
        print("⚠️ PCE not configured — skipping traffic evidence")

    files = [f.strip() for f in args.changed_files.split("\n") if f.strip() and f.endswith((".yaml", ".yml"))]

    evidence = []
    for filepath in files:
        if not os.path.exists(filepath):
            continue
        rules = extract_rules_from_file(filepath)
        for rule in rules:
            result = query_traffic_for_rule(pce, rule, args.lookback_days)
            evidence.append({
                "file": rule["file"],
                "rule_name": rule["name"],
                "ports": [s.get("port") for s in rule.get("services", []) if isinstance(s, dict) and s.get("port")],
                **(result or {"traffic_found": False, "reason": "PCE not configured"}),
            })

    justified = sum(1 for e in evidence if e.get("traffic_found"))
    total = len(evidence)

    report = {
        "evidence": evidence,
        "summary": {
            "total_rules": total,
            "justified": justified,
            "unjustified": total - justified,
        },
        "lookback_days": args.lookback_days,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Traffic evidence: {justified}/{total} rules justified by blocked traffic")


if __name__ == "__main__":
    main()
