#!/usr/bin/env python3
"""
Security check for Illumio policy YAML files.

Evaluates changed policy files against configurable security rules.
Outputs a JSON report for the PR comment renderer.

Usage:
  python3 security-check.py --changed-files "scopes/foo/bar.yaml" --output report.json
"""

import argparse
import json
import os
import sys

import yaml


# Default security rules (overridden by .illumio/security-rules.yaml)
DEFAULT_RULES = [
    {
        "id": "SEC-001",
        "name": "No any-to-any rules",
        "severity": "critical",
        "action": "block",
        "description": "Rules with 'all workloads' on both providers and consumers defeat micro-segmentation.",
    },
    {
        "id": "SEC-002",
        "name": "No broad port ranges",
        "severity": "critical",
        "action": "block",
        "description": "Port ranges exceeding 1000 ports are too permissive.",
    },
    {
        "id": "SEC-003",
        "name": "No insecure protocols",
        "severity": "critical",
        "action": "block",
        "ports": [21, 23, 69, 513, 514],
        "description": "FTP, Telnet, TFTP, rlogin, rsh are insecure. Use SSH/SFTP.",
    },
    {
        "id": "SEC-004",
        "name": "Cross-scope rules need justification",
        "severity": "high",
        "action": "warn",
        "description": "Extra-scope rules should include a justification field.",
    },
    {
        "id": "SEC-005",
        "name": "RDP/SMB restricted",
        "severity": "high",
        "action": "warn",
        "ports": [3389, 445],
        "description": "RDP and SMB are lateral movement vectors.",
    },
    {
        "id": "SEC-006",
        "name": "Database ports scoped",
        "severity": "high",
        "action": "warn",
        "ports": [5432, 3306, 1433, 1521, 27017],
        "description": "Database ports should be scoped to specific consumer roles.",
    },
    {
        "id": "SEC-007",
        "name": "IP List broad CIDR",
        "severity": "medium",
        "action": "warn",
        "description": "IP lists with /8 or broader CIDRs are very permissive.",
    },
]


def load_security_rules():
    """Load security rules from .illumio/security-rules.yaml or use defaults."""
    rules_path = os.path.join(os.getcwd(), ".illumio", "security-rules.yaml")
    if os.path.exists(rules_path):
        with open(rules_path) as f:
            config = yaml.safe_load(f)
            return config.get("rules", DEFAULT_RULES), config.get("exemptions", [])
    return DEFAULT_RULES, []


def check_rule_any_to_any(rule_data):
    """SEC-001: Check for any-to-any rules."""
    providers = rule_data.get("providers", [])
    consumers = rule_data.get("consumers", [])
    prov_ams = any(p.get("actors") == "ams" for p in providers if isinstance(p, dict))
    cons_ams = any(c.get("actors") == "ams" for c in consumers if isinstance(c, dict))
    return prov_ams and cons_ams


def check_broad_port_range(services):
    """SEC-002: Check for port ranges > 1000."""
    for svc in services:
        if isinstance(svc, dict):
            port = svc.get("port", 0)
            to_port = svc.get("to_port", 0)
            if port and to_port and (to_port - port) > 1000:
                return True
    return False


def check_ports(services, blocked_ports):
    """Check if any service uses a blocked port."""
    found = []
    for svc in services:
        if isinstance(svc, dict):
            port = svc.get("port")
            if port in blocked_ports:
                found.append(port)
    return found


def check_broad_cidr(ip_ranges):
    """SEC-007: Check for very broad CIDRs."""
    for r in ip_ranges:
        if isinstance(r, dict):
            from_ip = r.get("from_ip", "")
            if "/" in from_ip:
                prefix = int(from_ip.split("/")[1])
                if prefix <= 8:
                    return from_ip
    return None


def analyze_file(filepath, rules, exemptions):
    """Analyze a single YAML policy file against security rules."""
    findings = []

    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        findings.append({
            "file": filepath,
            "rule_id": "PARSE",
            "severity": "critical",
            "action": "block",
            "message": f"Failed to parse YAML: {e}",
        })
        return findings

    if not isinstance(data, dict):
        return findings

    # Check exemptions
    ruleset_name = data.get("name", "")
    exempt_rules = set()
    for ex in exemptions:
        pattern = ex.get("ruleset_pattern", "")
        if pattern and pattern in ruleset_name:
            exempt_rules.update(ex.get("exempt_rules", []))

    # Check rules within rulesets
    for rule_data in data.get("rules", []):
        if not isinstance(rule_data, dict):
            continue

        rule_name = rule_data.get("name", "(unnamed)")
        services = rule_data.get("services", [])

        # SEC-001: any-to-any
        if "SEC-001" not in exempt_rules and check_rule_any_to_any(rule_data):
            findings.append({
                "file": filepath,
                "rule_id": "SEC-001",
                "severity": "critical",
                "action": "block",
                "message": f"Rule '{rule_name}' allows any-to-any traffic",
                "context": f"providers and consumers both use 'actors: ams'",
            })

        # SEC-002: broad port range
        if "SEC-002" not in exempt_rules and check_broad_port_range(services):
            findings.append({
                "file": filepath,
                "rule_id": "SEC-002",
                "severity": "critical",
                "action": "block",
                "message": f"Rule '{rule_name}' has a port range exceeding 1000 ports",
            })

        # SEC-003: insecure protocols
        if "SEC-003" not in exempt_rules:
            insecure = check_ports(services, [21, 23, 69, 513, 514])
            if insecure:
                findings.append({
                    "file": filepath,
                    "rule_id": "SEC-003",
                    "severity": "critical",
                    "action": "block",
                    "message": f"Rule '{rule_name}' allows insecure ports: {insecure}",
                })

        # SEC-005: RDP/SMB
        if "SEC-005" not in exempt_rules:
            risky = check_ports(services, [3389, 445])
            if risky:
                findings.append({
                    "file": filepath,
                    "rule_id": "SEC-005",
                    "severity": "high",
                    "action": "warn",
                    "message": f"Rule '{rule_name}' allows RDP/SMB ports: {risky}",
                })

        # SEC-006: DB ports without specific consumer
        if "SEC-006" not in exempt_rules:
            db_ports = check_ports(services, [5432, 3306, 1433, 1521, 27017])
            if db_ports:
                consumers = rule_data.get("consumers", [])
                has_specific = any(c.get("label", {}).get("role") for c in consumers if isinstance(c, dict))
                if not has_specific:
                    findings.append({
                        "file": filepath,
                        "rule_id": "SEC-006",
                        "severity": "high",
                        "action": "warn",
                        "message": f"Rule '{rule_name}' exposes DB ports {db_ports} without role-specific consumers",
                    })

    # SEC-004: cross-scope without justification
    if "SEC-004" not in exempt_rules:
        if data.get("type") == "extra-scope" or data.get("unscoped_consumers"):
            if not data.get("justification"):
                findings.append({
                    "file": filepath,
                    "rule_id": "SEC-004",
                    "severity": "high",
                    "action": "warn",
                    "message": "Cross-scope rule missing 'justification' field",
                })

    # SEC-007: IP list broad CIDR
    if "SEC-007" not in exempt_rules and "ip-lists" in filepath:
        broad = check_broad_cidr(data.get("ip_ranges", []))
        if broad:
            findings.append({
                "file": filepath,
                "rule_id": "SEC-007",
                "severity": "medium",
                "action": "warn",
                "message": f"IP list contains very broad CIDR: {broad}",
            })

    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--output", default="security-report.json")
    args = parser.parse_args()

    rules, exemptions = load_security_rules()
    files = [f.strip() for f in args.changed_files.split("\n") if f.strip() and f.endswith((".yaml", ".yml"))]

    all_findings = []
    for filepath in files:
        if os.path.exists(filepath):
            all_findings.extend(analyze_file(filepath, rules, exemptions))

    summary = {
        "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
        "high": sum(1 for f in all_findings if f["severity"] == "high"),
        "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
        "blocked": any(f["action"] == "block" for f in all_findings),
    }

    report = {"findings": all_findings, "summary": summary, "files_checked": len(files)}

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Security check: {len(files)} files, {len(all_findings)} findings "
          f"({summary['critical']}C {summary['high']}H {summary['medium']}M)")

    if summary["blocked"]:
        print("❌ BLOCKED: Critical security findings found")
        sys.exit(1)
    else:
        print("✅ PASSED: No blocking findings")


if __name__ == "__main__":
    main()
