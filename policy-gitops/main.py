#!/usr/bin/env python3
"""
policy-gitops — Export Illumio policy to Git, detect drift, provision from Git.

Serves a dashboard on port 8080 with export status, drift report, and
provisioning controls.

PCE connection: PCE_HOST, PCE_PORT, PCE_ORG_ID, PCE_API_KEY, PCE_API_SECRET
Git connection: GIT_REPO_URL, GIT_TOKEN, GIT_BRANCH, GIT_PROVIDER
"""

import json
import logging
import os
import re
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

import yaml
from illumio import PolicyComputeEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("policy_gitops")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
REPO_DIR = DATA_DIR / "repo"

GIT_REPO_URL = os.environ.get("GIT_REPO_URL", "")
GIT_TOKEN = os.environ.get("GIT_TOKEN", "")
GIT_BRANCH = os.environ.get("GIT_BRANCH", "main")
GIT_PROVIDER = os.environ.get("GIT_PROVIDER", "github")
SYNC_MODE = os.environ.get("SYNC_MODE", "export")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "3600"))
AUTO_PROVISION = os.environ.get("AUTO_PROVISION", "false").lower() in ("true", "1", "yes")
DRIFT_ALERT = os.environ.get("DRIFT_ALERT", "true").lower() in ("true", "1", "yes")

# Protocol number to name mapping (IANA)
PROTO_NUM_TO_NAME = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}
PROTO_NAME_TO_NUM = {v: k for k, v in PROTO_NUM_TO_NAME.items()}

# PCE metadata fields to strip during export
METADATA_KEYS = {
    "href", "created_at", "updated_at", "created_by", "updated_by",
    "deleted_at", "deleted_by", "update_type", "caps",
    "external_data_set", "external_data_reference",
}

# ---------------------------------------------------------------------------
# Global state (protected by state_lock)
# ---------------------------------------------------------------------------

state_lock = threading.Lock()
app_state = {
    "status": "initializing",
    "sync_mode": SYNC_MODE,
    "git_repo": GIT_REPO_URL,
    "git_branch": GIT_BRANCH,
    "git_provider": GIT_PROVIDER,
    "last_sync": None,
    "sync_count": 0,
    "last_error": None,
    # Export tracking
    "last_export": None,
    "export_count": 0,
    "exported_objects": {},      # {rulesets: N, ip_lists: N, services: N}
    # Drift tracking
    "drift_items": [],           # [{type, name, status, detail}]
    "last_drift_check": None,
    "drift_count": 0,
    # Provisioning tracking
    "last_provision": None,
    "provision_count": 0,
    "provision_history": [],     # [{timestamp, objects, status, detail}]
}


# ---------------------------------------------------------------------------
# PCE client
# ---------------------------------------------------------------------------

def get_pce() -> PolicyComputeEngine:
    """Create an authenticated PCE client from environment variables."""
    pce = PolicyComputeEngine(
        url=os.environ["PCE_HOST"],
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ["PCE_API_KEY"],
        password=os.environ["PCE_API_SECRET"],
    )
    skip_tls = os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() in ("true", "1", "yes")
    if skip_tls:
        pce.set_tls_settings(verify=False)
    return pce


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_filename(name: str) -> str:
    """Convert a name to a safe filesystem name (lowercase, hyphens)."""
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s or "unnamed"


def _proto_num_to_name(num) -> str:
    """Convert protocol number to name, pass through strings."""
    if isinstance(num, str):
        return num
    return PROTO_NUM_TO_NAME.get(num, str(num))


def _proto_name_to_num(name) -> int:
    """Convert protocol name to number, pass through ints."""
    if isinstance(name, int):
        return name
    return PROTO_NAME_TO_NUM.get(name.lower(), int(name) if name.isdigit() else 6)


def _strip_metadata(obj: dict) -> dict:
    """Remove PCE metadata keys from a dict (non-recursive top level)."""
    return {k: v for k, v in obj.items() if k not in METADATA_KEYS}


# ===================================================================
# PolicySerializer — convert between PCE objects and YAML files
# ===================================================================

class PolicySerializer:
    """Serialize PCE policy objects to/from YAML files."""

    def __init__(self, pce: PolicyComputeEngine):
        self.pce = pce
        self._label_cache = {}       # href -> {key, value}
        self._label_reverse = {}     # "key:value" -> href
        self._service_cache = {}     # href -> service dict
        self._ip_list_cache = {}     # href -> ip_list dict

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def refresh_label_cache(self):
        """Fetch all labels from PCE and cache href <-> key/value mapping."""
        try:
            resp = self.pce.get("/labels")
            if resp.status_code == 200:
                for lbl in resp.json():
                    href = lbl.get("href", "")
                    key = lbl.get("key", "")
                    value = lbl.get("value", "")
                    if href:
                        self._label_cache[href] = {"key": key, "value": value}
                        self._label_reverse[f"{key}:{value}"] = href
                log.info("Cached %d labels", len(self._label_cache))
        except Exception as e:
            log.warning("Failed to fetch labels: %s", e)

    def refresh_service_cache(self):
        """Fetch all services from PCE and cache href -> service mapping."""
        try:
            resp = self.pce.get("/sec_policy/active/services")
            if resp.status_code == 200:
                for svc in resp.json():
                    href = svc.get("href", "")
                    if href:
                        self._service_cache[href] = svc
                log.info("Cached %d services", len(self._service_cache))
        except Exception as e:
            log.warning("Failed to fetch services: %s", e)

    def refresh_ip_list_cache(self):
        """Fetch all IP lists from PCE and cache href -> ip_list mapping."""
        try:
            resp = self.pce.get("/sec_policy/active/ip_lists")
            if resp.status_code == 200:
                for ipl in resp.json():
                    href = ipl.get("href", "")
                    if href:
                        self._ip_list_cache[href] = ipl
                log.info("Cached %d IP lists", len(self._ip_list_cache))
        except Exception as e:
            log.warning("Failed to fetch IP lists: %s", e)

    def refresh_all_caches(self):
        """Refresh all caches (labels, services, IP lists)."""
        self.refresh_label_cache()
        self.refresh_service_cache()
        self.refresh_ip_list_cache()

    # ------------------------------------------------------------------
    # Label resolution helpers
    # ------------------------------------------------------------------

    def _resolve_label_href(self, href: str) -> dict:
        """Resolve a label href to {key: value}."""
        cached = self._label_cache.get(href, {})
        if cached:
            return {cached["key"]: cached["value"]}
        return {"href": href}

    def _label_kv_to_href(self, key: str, value: str) -> str:
        """Look up a label href by key:value. Returns href or empty string."""
        return self._label_reverse.get(f"{key}:{value}", "")

    # ------------------------------------------------------------------
    # Actor resolution helpers (export direction: PCE -> YAML)
    # ------------------------------------------------------------------

    def _resolve_actor_to_yaml(self, actor: dict) -> dict:
        """Convert a single PCE actor (consumer/provider) to YAML format.

        PCE actor formats:
          - {"actors": "ams"} -> all managed workloads
          - {"label": {"href": "..."}} -> label reference
          - {"label_group": {"href": "..."}} -> label group reference
          - {"ip_list": {"href": "..."}} -> IP list reference
          - {"workload": {"href": "..."}} -> specific workload
        """
        if actor.get("actors") == "ams":
            return {"actors": "ams"}

        if "label" in actor:
            lbl = actor["label"]
            href = lbl.get("href", "") if isinstance(lbl, dict) else ""
            resolved = self._label_cache.get(href, {})
            if resolved:
                return {"label": {resolved["key"]: resolved["value"]}}
            return {"label": {"href": href}}

        if "label_group" in actor:
            lg = actor["label_group"]
            href = lg.get("href", "") if isinstance(lg, dict) else ""
            return {"label_group": {"href": href}}

        if "ip_list" in actor:
            ipl = actor["ip_list"]
            href = ipl.get("href", "") if isinstance(ipl, dict) else ""
            cached = self._ip_list_cache.get(href)
            if cached:
                return {"ip_list": {"name": cached.get("name", href)}}
            return {"ip_list": {"href": href}}

        if "workload" in actor:
            wl = actor["workload"]
            href = wl.get("href", "") if isinstance(wl, dict) else ""
            return {"workload": {"href": href}}

        return actor

    def _resolve_service_to_yaml(self, svc: dict) -> dict:
        """Convert a single PCE ingress_service entry to YAML format.

        PCE formats:
          - {"href": "..."} -> service reference
          - {"port": N, "proto": N} -> inline port/proto
          - {"port": N, "to_port": N, "proto": N} -> port range
        """
        # Service reference (href only, no port key)
        if "href" in svc and "port" not in svc:
            href = svc["href"]
            cached = self._service_cache.get(href)
            if cached:
                return {"name": cached.get("name", href)}
            return {"href": href}

        # Inline port/proto
        if "port" in svc:
            result = {"port": svc["port"], "proto": _proto_num_to_name(svc.get("proto", 6))}
            if svc.get("to_port") and svc["to_port"] != svc["port"]:
                result["to_port"] = svc["to_port"]
            return result

        return svc

    # ------------------------------------------------------------------
    # Actor resolution helpers (import direction: YAML -> PCE)
    # ------------------------------------------------------------------

    def _resolve_actor_to_pce(self, actor: dict) -> dict:
        """Convert a single YAML actor to PCE API format.

        YAML actor formats:
          - {"actors": "ams"} -> all managed workloads
          - {"label": {"role": "web"}} -> label key:value
          - {"ip_list": {"name": "..."}} -> IP list by name
          - {"workload": {"href": "..."}} -> specific workload
        """
        if actor.get("actors") == "ams":
            return {"actors": "ams"}

        if "label" in actor:
            lbl = actor["label"]
            if isinstance(lbl, dict):
                for key, value in lbl.items():
                    if key == "href":
                        return {"label": {"href": value}}
                    href = self._label_kv_to_href(key, value)
                    if href:
                        return {"label": {"href": href}}
                    log.warning("Label not found: %s=%s", key, value)
                    return {"label": {"href": f"unresolved:{key}={value}"}}
            return actor

        if "ip_list" in actor:
            ipl = actor["ip_list"]
            if isinstance(ipl, dict) and "name" in ipl:
                name = ipl["name"]
                for href, cached in self._ip_list_cache.items():
                    if cached.get("name") == name:
                        return {"ip_list": {"href": href}}
                log.warning("IP list not found: %s", name)
            return actor

        if "workload" in actor:
            return actor

        return actor

    def _resolve_service_to_pce(self, svc: dict) -> dict:
        """Convert a single YAML service entry to PCE ingress_service format.

        YAML formats:
          - {"port": N, "proto": "tcp"} -> inline port/proto
          - {"port": N, "to_port": N, "proto": "tcp"} -> port range
          - {"name": "..."} -> service reference by name
        """
        if "name" in svc and "port" not in svc:
            name = svc["name"]
            for href, cached in self._service_cache.items():
                if cached.get("name") == name:
                    return {"href": href}
            log.warning("Service not found: %s", name)
            return svc

        if "port" in svc:
            result = {
                "port": svc["port"],
                "proto": _proto_name_to_num(svc.get("proto", "tcp")),
            }
            if svc.get("to_port"):
                result["to_port"] = svc["to_port"]
            return result

        return svc

    # ------------------------------------------------------------------
    # Export: PCE -> YAML
    # ------------------------------------------------------------------

    def export_ruleset_to_yaml(self, ruleset: dict) -> dict:
        """Convert a PCE ruleset JSON object to our YAML-friendly dict.

        Strips metadata, resolves label hrefs to {key: value} pairs,
        resolves services to {port, proto} or {name}.
        """
        # Resolve scopes: array of arrays of label refs
        scopes_yaml = []
        for scope_entry in ruleset.get("scopes", []):
            if not scope_entry:
                continue
            resolved_scope = []
            for item in scope_entry:
                if not isinstance(item, dict):
                    continue
                if "label" in item:
                    lbl = item["label"]
                    href = lbl.get("href", "") if isinstance(lbl, dict) else ""
                    resolved = self._label_cache.get(href, {})
                    if resolved:
                        entry = {"label": {resolved["key"]: resolved["value"]}}
                    else:
                        entry = {"label": {"href": href}}
                    if item.get("exclusion"):
                        entry["exclusion"] = True
                    resolved_scope.append(entry)
                elif "label_group" in item:
                    resolved_scope.append(item)
            if resolved_scope:
                scopes_yaml.append(resolved_scope)

        # Build the result
        result = {
            "name": ruleset.get("name", "unknown"),
            "description": ruleset.get("description", ""),
            "enabled": ruleset.get("enabled", True),
            "scopes": scopes_yaml,
            "rules": [],
        }

        # Convert allow rules
        for rule in ruleset.get("rules", []):
            rule_yaml = self._export_rule_to_yaml(rule)
            result["rules"].append(rule_yaml)

        # Convert deny rules if present
        deny_rules = []
        for rule in ruleset.get("deny_rules", []):
            rule_yaml = self._export_rule_to_yaml(rule)
            rule_yaml["type"] = "deny"
            deny_rules.append(rule_yaml)
        if deny_rules:
            result["deny_rules"] = deny_rules

        return result

    def _export_rule_to_yaml(self, rule: dict) -> dict:
        """Convert a single PCE rule to YAML format."""
        consumers = [self._resolve_actor_to_yaml(a) for a in rule.get("consumers", [])]
        providers = [self._resolve_actor_to_yaml(a) for a in rule.get("providers", [])]
        services = [self._resolve_service_to_yaml(s) for s in rule.get("ingress_services", [])]

        rule_yaml = {
            "name": rule.get("description", "") or rule.get("href", "unnamed"),
            "enabled": rule.get("enabled", True),
            "consumers": consumers,
            "providers": providers,
            "services": services,
        }

        if rule.get("unscoped_consumers"):
            rule_yaml["unscoped_consumers"] = True

        if rule.get("sec_connect"):
            rule_yaml["sec_connect"] = True

        if rule.get("machine_auth"):
            rule_yaml["machine_auth"] = True

        return rule_yaml

    # ------------------------------------------------------------------
    # Import: YAML -> PCE
    # ------------------------------------------------------------------

    def import_yaml_to_ruleset(self, yaml_data: dict) -> dict:
        """Convert a YAML ruleset dict to a PCE API-compatible ruleset payload.

        Resolves label key:value pairs to HREFs, services to inline or href format.
        """
        # Resolve scopes
        scopes_pce = []
        for scope_entry in yaml_data.get("scopes", []):
            if not scope_entry:
                continue
            resolved_scope = []
            for item in scope_entry:
                if not isinstance(item, dict):
                    continue
                if "label" in item:
                    lbl = item["label"]
                    if isinstance(lbl, dict):
                        for key, value in lbl.items():
                            if key == "href":
                                pce_item = {"label": {"href": value}}
                            else:
                                href = self._label_kv_to_href(key, value)
                                if href:
                                    pce_item = {"label": {"href": href}}
                                else:
                                    log.warning("Scope label not found: %s=%s", key, value)
                                    continue
                            if item.get("exclusion"):
                                pce_item["exclusion"] = True
                            resolved_scope.append(pce_item)
                            break
            if resolved_scope:
                scopes_pce.append(resolved_scope)

        # If no scopes resolved, use empty scope (global)
        if not scopes_pce:
            scopes_pce = [[]]

        # Build ruleset payload
        result = {
            "name": yaml_data.get("name", "unknown"),
            "description": yaml_data.get("description", ""),
            "enabled": yaml_data.get("enabled", True),
            "scopes": scopes_pce,
            "rules": [],
        }

        # Convert allow rules
        for rule in yaml_data.get("rules", []):
            rule_pce = self._import_rule_to_pce(rule)
            result["rules"].append(rule_pce)

        # Convert deny rules
        if yaml_data.get("deny_rules"):
            result["deny_rules"] = []
            for rule in yaml_data["deny_rules"]:
                rule_pce = self._import_rule_to_pce(rule)
                result["deny_rules"].append(rule_pce)

        return result

    def _import_rule_to_pce(self, rule: dict) -> dict:
        """Convert a single YAML rule to PCE API format."""
        consumers = [self._resolve_actor_to_pce(a) for a in rule.get("consumers", [])]
        providers = [self._resolve_actor_to_pce(a) for a in rule.get("providers", [])]
        services = [self._resolve_service_to_pce(s) for s in rule.get("services", [])]

        rule_pce = {
            "enabled": rule.get("enabled", True),
            "consumers": consumers,
            "providers": providers,
            "ingress_services": services,
        }

        # Use rule name as description (PCE rules use "description" field for name)
        if rule.get("name"):
            rule_pce["description"] = rule["name"]

        if rule.get("unscoped_consumers"):
            rule_pce["unscoped_consumers"] = True

        if rule.get("sec_connect"):
            rule_pce["sec_connect"] = True

        if rule.get("machine_auth"):
            rule_pce["machine_auth"] = True

        return rule_pce

    # ------------------------------------------------------------------
    # IP Lists
    # ------------------------------------------------------------------

    def export_ip_list_to_yaml(self, ip_list: dict) -> dict:
        """Convert a PCE IP list to YAML-friendly dict.

        Strips metadata, keeps name, description, ip_ranges, fqdns.
        """
        # Clean ip_ranges: strip metadata from each range entry
        clean_ranges = []
        for r in ip_list.get("ip_ranges", []):
            entry = {}
            if r.get("from_ip"):
                entry["from_ip"] = r["from_ip"]
            if r.get("to_ip") and r["to_ip"] != r.get("from_ip"):
                entry["to_ip"] = r["to_ip"]
            if r.get("exclusion"):
                entry["exclusion"] = True
            if r.get("description"):
                entry["description"] = r["description"]
            if entry:
                clean_ranges.append(entry)

        # Clean fqdns
        clean_fqdns = []
        for f in ip_list.get("fqdns", []):
            if isinstance(f, dict):
                fqdn = f.get("fqdn", "")
                if fqdn:
                    clean_fqdns.append(fqdn)
            elif isinstance(f, str):
                clean_fqdns.append(f)

        result = {
            "name": ip_list.get("name", "unknown"),
            "description": ip_list.get("description", ""),
            "ip_ranges": clean_ranges,
        }
        if clean_fqdns:
            result["fqdns"] = clean_fqdns

        return result

    def import_yaml_to_ip_list(self, yaml_data: dict) -> dict:
        """Convert a YAML IP list dict to PCE API format."""
        ip_ranges = []
        for r in yaml_data.get("ip_ranges", []):
            entry = {}
            if r.get("from_ip"):
                entry["from_ip"] = r["from_ip"]
            if r.get("to_ip"):
                entry["to_ip"] = r["to_ip"]
            if r.get("exclusion"):
                entry["exclusion"] = True
            if r.get("description"):
                entry["description"] = r["description"]
            if entry:
                ip_ranges.append(entry)

        fqdns = []
        for f in yaml_data.get("fqdns", []):
            if isinstance(f, str):
                fqdns.append({"fqdn": f})
            elif isinstance(f, dict):
                fqdns.append(f)

        result = {
            "name": yaml_data.get("name", "unknown"),
            "description": yaml_data.get("description", ""),
            "ip_ranges": ip_ranges,
        }
        if fqdns:
            result["fqdns"] = fqdns

        return result

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def export_service_to_yaml(self, service: dict) -> dict:
        """Convert a PCE service to YAML-friendly dict.

        Strips metadata, converts proto numbers to names.
        """
        clean_ports = []
        for sp in service.get("service_ports", []):
            entry = {}
            if "port" in sp:
                entry["port"] = sp["port"]
            if sp.get("to_port") and sp["to_port"] != sp.get("port"):
                entry["to_port"] = sp["to_port"]
            if "proto" in sp:
                entry["proto"] = _proto_num_to_name(sp["proto"])
            if sp.get("icmp_type") is not None:
                entry["icmp_type"] = sp["icmp_type"]
            if sp.get("icmp_code") is not None:
                entry["icmp_code"] = sp["icmp_code"]
            if entry:
                clean_ports.append(entry)

        # Also handle windows_services if present
        clean_windows = []
        for ws in service.get("windows_services", []):
            entry = _strip_metadata(ws)
            if entry:
                clean_windows.append(entry)

        result = {
            "name": service.get("name", "unknown"),
            "description": service.get("description", ""),
            "service_ports": clean_ports,
        }
        if clean_windows:
            result["windows_services"] = clean_windows

        return result

    def import_yaml_to_service(self, yaml_data: dict) -> dict:
        """Convert a YAML service dict to PCE API format."""
        service_ports = []
        for sp in yaml_data.get("service_ports", []):
            entry = {}
            if "port" in sp:
                entry["port"] = sp["port"]
            if sp.get("to_port"):
                entry["to_port"] = sp["to_port"]
            if "proto" in sp:
                entry["proto"] = _proto_name_to_num(sp["proto"])
            if sp.get("icmp_type") is not None:
                entry["icmp_type"] = sp["icmp_type"]
            if sp.get("icmp_code") is not None:
                entry["icmp_code"] = sp["icmp_code"]
            if entry:
                service_ports.append(entry)

        result = {
            "name": yaml_data.get("name", "unknown"),
            "description": yaml_data.get("description", ""),
            "service_ports": service_ports,
        }

        if yaml_data.get("windows_services"):
            result["windows_services"] = yaml_data["windows_services"]

        return result


# ===================================================================
# ScopeMapper — map rulesets to directory paths based on scope labels
# ===================================================================

class ScopeMapper:
    """Map Illumio RBAC scopes to Git repository directory structure."""

    def __init__(self, serializer: PolicySerializer):
        self.serializer = serializer

    def map_ruleset_to_directory(self, ruleset: dict) -> str:
        """Determine the directory path for a ruleset based on its scope labels.

        Returns relative path under scopes/ (e.g. "scopes/payments-prod" or
        "scopes/_global").

        Strategy:
          - If scopes is empty or [[]], return "scopes/_global".
          - Otherwise resolve the first scope entry's labels.
          - Build directory name from label values joined by hyphen
            (e.g. app=payments + env=prod -> "payments-prod").
        """
        scopes = ruleset.get("scopes", [])

        # Empty scopes or [[]] -> global
        if not scopes or scopes == [[]] or all(not s for s in scopes):
            return "scopes/_global"

        # Use the first scope entry to determine directory
        first_scope = scopes[0]
        if not first_scope:
            return "scopes/_global"

        # Resolve labels in the scope
        label_values = []
        for item in first_scope:
            if not isinstance(item, dict):
                continue
            if item.get("exclusion"):
                continue
            if "label" in item:
                lbl = item["label"]
                href = lbl.get("href", "") if isinstance(lbl, dict) else ""
                resolved = self.serializer._label_cache.get(href, {})
                if resolved:
                    label_values.append(resolved["value"])

        if not label_values:
            return "scopes/_global"

        # Build directory name: join label values with hyphen
        dir_name = _sanitize_filename("-".join(label_values))
        return f"scopes/{dir_name}"

    def resolve_scope_labels(self, scope_dir: str) -> list:
        """Read _scope.yaml from a directory and return label key:value pairs.

        Returns list of {key: value} label dicts defining the scope.
        """
        scope_file = Path(scope_dir) / "_scope.yaml"
        if scope_file.exists():
            try:
                data = yaml.safe_load(scope_file.read_text())
                if data and isinstance(data, dict):
                    labels = data.get("labels", {})
                    if isinstance(labels, dict):
                        return [{k: v} for k, v in labels.items()]
                    return labels
            except Exception as e:
                log.warning("Failed to read scope file %s: %s", scope_file, e)
        return []

    def build_codeowners(self, repo_path: Path) -> str:
        """Generate a CODEOWNERS file from all _scope.yaml definitions.

        Walks scopes/ directories, reads _scope.yaml for each, extracts owners,
        and generates CODEOWNERS entries per DESIGN.md format.
        """
        lines = [
            "# Auto-generated by policy-gitops -- do not edit manually",
            "",
            "# Global policy -- security team must review",
            "scopes/_global/         @org/security-team",
            "ip-lists/               @org/security-team",
            "services/               @org/security-team",
            "",
            "# Per-scope ownership",
        ]

        scopes_dir = repo_path / "scopes"
        if scopes_dir.is_dir():
            for scope_dir in sorted(scopes_dir.iterdir()):
                if not scope_dir.is_dir() or scope_dir.name.startswith("_"):
                    continue
                scope_file = scope_dir / "_scope.yaml"
                if scope_file.exists():
                    try:
                        data = yaml.safe_load(scope_file.read_text())
                        owners = data.get("owners", [])
                        for owner in owners:
                            github = owner.get("github", "")
                            if github:
                                lines.append(
                                    f"scopes/{scope_dir.name}/   {github}"
                                )
                    except Exception as e:
                        log.warning("Failed to read %s: %s", scope_file, e)

        lines.extend([
            "",
            "# Cross-scope rules require security team review",
            "scopes/*/cross-scope/   @org/security-team",
            "scopes/*/inbound/       @org/security-team",
            "",
        ])

        return "\n".join(lines) + "\n"


# ===================================================================
# GitClient — interact with Git repository via subprocess
# ===================================================================

class GitClient:
    """Manage Git repository operations using subprocess (git CLI)."""

    def __init__(self, repo_url: str, token: str, branch: str, provider: str,
                 repo_dir: Path):
        self.repo_url = repo_url
        self.token = token
        self.branch = branch
        self.provider = provider
        self.repo_dir = repo_dir

    def _auth_url(self) -> str:
        """Inject token into HTTPS URL for authentication.

        Converts: https://github.com/org/repo.git
              to: https://token@github.com/org/repo.git
        Or for GitLab-style: https://oauth2:token@gitlab.com/...
        """
        if not self.token or not self.repo_url:
            return self.repo_url

        url = self.repo_url

        # Already has credentials embedded
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            return url

        # SSH URL — token auth not applicable
        if url.startswith("git@") or url.startswith("ssh://"):
            return url

        # HTTPS URL — inject token
        if "://" in url:
            scheme, rest = url.split("://", 1)
            if self.provider == "gitlab":
                return f"{scheme}://oauth2:{self.token}@{rest}"
            else:
                # GitHub / Bitbucket: use token as username
                return f"{scheme}://{self.token}@{rest}"

        return url

    def _run(self, args: list, cwd: str = None, check: bool = True) -> subprocess.CompletedProcess:
        """Run a git command via subprocess."""
        cmd = ["git"] + args
        work_dir = cwd or str(self.repo_dir)
        log.debug("git %s (cwd=%s)", " ".join(args), work_dir)

        # Set up environment for git to avoid interactive prompts
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        result = subprocess.run(
            cmd, cwd=work_dir, capture_output=True, text=True,
            timeout=120, env=env, check=False,
        )

        if check and result.returncode != 0:
            log.error("git %s failed (rc=%d): %s", args[0], result.returncode,
                      result.stderr.strip())
            raise RuntimeError(f"git {args[0]} failed: {result.stderr.strip()}")

        return result

    def clone(self):
        """Clone the repository to repo_dir, or open if already cloned."""
        git_dir = self.repo_dir / ".git"

        if git_dir.is_dir():
            log.info("Repo already cloned at %s, pulling latest...", self.repo_dir)
            self.pull()
            return

        if not self.repo_url:
            log.warning("GIT_REPO_URL not set; creating local-only repo at %s", self.repo_dir)
            self.repo_dir.mkdir(parents=True, exist_ok=True)
            self._run(["init"], cwd=str(self.repo_dir))
            self._run(["checkout", "-b", self.branch], cwd=str(self.repo_dir), check=False)
            return

        log.info("Cloning %s -> %s (branch=%s)", self.repo_url, self.repo_dir, self.branch)
        self.repo_dir.mkdir(parents=True, exist_ok=True)

        self._run(
            ["clone", "--branch", self.branch, "--single-branch",
             self._auth_url(), str(self.repo_dir)],
            cwd=str(self.repo_dir.parent),
        )
        log.info("Clone complete")

    def pull(self) -> bool:
        """Pull latest changes from remote.

        Returns True if new changes were pulled, False if already up to date.
        """
        if not self.repo_url:
            return False

        try:
            # Capture HEAD before pull
            before = self._run(["rev-parse", "HEAD"], check=False)
            before_sha = before.stdout.strip()

            # Update remote URL in case token changed
            self._run(["remote", "set-url", "origin", self._auth_url()], check=False)

            self._run(["fetch", "origin", self.branch])
            result = self._run(
                ["merge", "--ff-only", f"origin/{self.branch}"],
                check=False,
            )

            after = self._run(["rev-parse", "HEAD"], check=False)
            after_sha = after.stdout.strip()

            changed = before_sha != after_sha
            if changed:
                log.info("Pulled new changes (%s -> %s)", before_sha[:8], after_sha[:8])
            else:
                log.info("Already up to date at %s", after_sha[:8])
            return changed

        except Exception as e:
            log.warning("Pull failed: %s", e)
            return False

    def commit(self, message: str, files: list = None):
        """Stage and commit changes.

        Args:
            message: Commit message.
            files: List of file paths to stage (relative to repo root).
                   If None, stage all changes.
        """
        # Configure bot identity
        self._run(["config", "user.email", "policy-gitops@illumio.plugger"], check=False)
        self._run(["config", "user.name", "policy-gitops"], check=False)

        # Stage files
        if files:
            for f in files:
                self._run(["add", f], check=False)
        else:
            self._run(["add", "-A"])

        # Check if there are changes to commit
        status = self._run(["status", "--porcelain"], check=False)
        if not status.stdout.strip():
            log.info("No changes to commit")
            return

        self._run(["commit", "-m", message])
        log.info("Committed: %s", message)

    def push(self):
        """Push commits to remote."""
        if not self.repo_url:
            log.info("No remote configured, skip push")
            return

        # Ensure remote URL has auth token
        self._run(["remote", "set-url", "origin", self._auth_url()], check=False)
        self._run(["push", "origin", self.branch])
        log.info("Pushed to %s/%s", self.repo_url, self.branch)

    def create_pr(self, title: str, body: str, source_branch: str,
                  target_branch: str = None) -> dict:
        """Create a pull/merge request on the Git provider via REST API.

        Returns dict with PR details (url, number, etc.)
        """
        import requests

        target = target_branch or self.branch
        headers = {"Accept": "application/json"}

        if self.provider == "github":
            # Parse owner/repo from URL
            match = re.search(r"github\.com[/:]([^/]+)/([^/.]+)", self.repo_url)
            if not match:
                return {"url": "", "number": 0, "status": "error",
                        "error": "Cannot parse GitHub owner/repo from URL"}
            owner, repo = match.group(1), match.group(2)
            headers["Authorization"] = f"token {self.token}"

            resp = requests.post(
                f"https://api.github.com/repos/{owner}/{repo}/pulls",
                headers=headers,
                json={"title": title, "body": body, "head": source_branch, "base": target},
                timeout=30,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return {"url": data.get("html_url", ""), "number": data.get("number", 0),
                        "status": "created"}
            return {"url": "", "number": 0, "status": "error",
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

        elif self.provider == "gitlab":
            match = re.search(r"gitlab\.com[/:](.+?)(?:\.git)?$", self.repo_url)
            if not match:
                return {"url": "", "number": 0, "status": "error",
                        "error": "Cannot parse GitLab project from URL"}
            project = match.group(1).replace("/", "%2F")
            headers["PRIVATE-TOKEN"] = self.token

            resp = requests.post(
                f"https://gitlab.com/api/v4/projects/{project}/merge_requests",
                headers=headers,
                json={"title": title, "description": body,
                      "source_branch": source_branch, "target_branch": target},
                timeout=30,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return {"url": data.get("web_url", ""), "number": data.get("iid", 0),
                        "status": "created"}
            return {"url": "", "number": 0, "status": "error",
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

        return {"url": "", "number": 0, "status": "not_supported",
                "error": f"Provider {self.provider} not supported for PR creation"}

    def get_changed_files(self) -> list:
        """Return list of files changed in the working tree (staged + unstaged + untracked).

        Returns list of relative file paths.
        """
        result = self._run(["status", "--porcelain"], check=False)
        files = []
        for line in result.stdout.strip().splitlines():
            if line.strip():
                # Status is first 2 chars, then space, then filename
                filename = line[3:].strip()
                # Handle renames: "R  old -> new"
                if " -> " in filename:
                    filename = filename.split(" -> ", 1)[1]
                files.append(filename)
        return files


# ===================================================================
# DriftDetector — compare Git state vs PCE state
# ===================================================================

class DriftDetector:
    """Detect differences between Git repository and PCE active policy."""

    def __init__(self, serializer: PolicySerializer, scope_mapper: ScopeMapper,
                 git_client: GitClient):
        self.serializer = serializer
        self.scope_mapper = scope_mapper
        self.git_client = git_client

    def compare_git_vs_pce(self, pce: PolicyComputeEngine) -> list:
        """Compare all policy objects between Git and PCE.

        Returns list of drift items:
        [{type, name, status, git_value, pce_value, detail}]
        status is one of: "in_sync", "drift_modified", "git_only", "pce_only"
        """
        drift_items = []
        repo_dir = self.git_client.repo_dir

        # Refresh caches for accurate comparison
        self.serializer.refresh_all_caches()

        # --- Compare rulesets ---
        drift_items.extend(self._compare_rulesets(pce, repo_dir))

        # --- Compare IP lists ---
        drift_items.extend(self._compare_ip_lists(pce, repo_dir))

        # --- Compare services ---
        drift_items.extend(self._compare_services(pce, repo_dir))

        return drift_items

    def _compare_rulesets(self, pce: PolicyComputeEngine, repo_dir: Path) -> list:
        """Compare rulesets between Git and PCE."""
        drift = []

        # Read all ruleset YAML files from Git
        git_rulesets = {}  # name -> yaml_data
        scopes_dir = repo_dir / "scopes"
        if scopes_dir.is_dir():
            for yaml_file in scopes_dir.rglob("*.yaml"):
                if yaml_file.name.startswith("_"):
                    continue
                try:
                    data = yaml.safe_load(yaml_file.read_text())
                    if data and isinstance(data, dict) and "rules" in data:
                        name = data.get("name", yaml_file.stem)
                        git_rulesets[name] = data
                except Exception as e:
                    log.warning("Failed to read %s: %s", yaml_file, e)

        # Fetch rulesets from PCE
        pce_rulesets = {}  # name -> serialized yaml_data
        try:
            resp = pce.get("/sec_policy/active/rule_sets", params={"max_results": 5000})
            if resp.status_code == 200:
                for rs in resp.json():
                    name = rs.get("name", "")
                    serialized = self.serializer.export_ruleset_to_yaml(rs)
                    pce_rulesets[name] = serialized
        except Exception as e:
            log.error("Failed to fetch rulesets for drift check: %s", e)

        # Compare
        all_names = set(git_rulesets.keys()) | set(pce_rulesets.keys())
        for name in sorted(all_names):
            in_git = name in git_rulesets
            in_pce = name in pce_rulesets

            if in_git and not in_pce:
                drift.append({
                    "type": "ruleset", "name": name, "status": "git_only",
                    "detail": "Exists in Git but not in PCE active policy",
                })
            elif in_pce and not in_git:
                drift.append({
                    "type": "ruleset", "name": name, "status": "pce_only",
                    "detail": "Exists in PCE but not in Git repository",
                })
            else:
                diffs = self._compare_objects(
                    git_rulesets[name], pce_rulesets[name],
                    ignore_keys={"href", "created_at", "updated_at"},
                )
                if diffs:
                    drift.append({
                        "type": "ruleset", "name": name, "status": "drift_modified",
                        "detail": "; ".join(diffs[:5]),
                    })

        return drift

    def _compare_ip_lists(self, pce: PolicyComputeEngine, repo_dir: Path) -> list:
        """Compare IP lists between Git and PCE."""
        drift = []

        # Read Git IP lists
        git_ip_lists = {}
        ip_lists_dir = repo_dir / "ip-lists"
        if ip_lists_dir.is_dir():
            for yaml_file in ip_lists_dir.glob("*.yaml"):
                try:
                    data = yaml.safe_load(yaml_file.read_text())
                    if data and isinstance(data, dict):
                        name = data.get("name", yaml_file.stem)
                        git_ip_lists[name] = data
                except Exception as e:
                    log.warning("Failed to read %s: %s", yaml_file, e)

        # Fetch PCE IP lists
        pce_ip_lists = {}
        try:
            resp = pce.get("/sec_policy/active/ip_lists")
            if resp.status_code == 200:
                for ipl in resp.json():
                    name = ipl.get("name", "")
                    serialized = self.serializer.export_ip_list_to_yaml(ipl)
                    pce_ip_lists[name] = serialized
        except Exception as e:
            log.error("Failed to fetch IP lists for drift check: %s", e)

        # Compare
        all_names = set(git_ip_lists.keys()) | set(pce_ip_lists.keys())
        for name in sorted(all_names):
            in_git = name in git_ip_lists
            in_pce = name in pce_ip_lists

            if in_git and not in_pce:
                drift.append({
                    "type": "ip_list", "name": name, "status": "git_only",
                    "detail": "Exists in Git but not in PCE",
                })
            elif in_pce and not in_git:
                drift.append({
                    "type": "ip_list", "name": name, "status": "pce_only",
                    "detail": "Exists in PCE but not in Git",
                })
            else:
                diffs = self._compare_objects(git_ip_lists[name], pce_ip_lists[name])
                if diffs:
                    drift.append({
                        "type": "ip_list", "name": name, "status": "drift_modified",
                        "detail": "; ".join(diffs[:5]),
                    })

        return drift

    def _compare_services(self, pce: PolicyComputeEngine, repo_dir: Path) -> list:
        """Compare services between Git and PCE."""
        drift = []

        # Read Git services
        git_services = {}
        services_dir = repo_dir / "services"
        if services_dir.is_dir():
            for yaml_file in services_dir.glob("*.yaml"):
                try:
                    data = yaml.safe_load(yaml_file.read_text())
                    if data and isinstance(data, dict):
                        name = data.get("name", yaml_file.stem)
                        git_services[name] = data
                except Exception as e:
                    log.warning("Failed to read %s: %s", yaml_file, e)

        # Fetch PCE services
        pce_services = {}
        try:
            resp = pce.get("/sec_policy/active/services")
            if resp.status_code == 200:
                for svc in resp.json():
                    name = svc.get("name", "")
                    serialized = self.serializer.export_service_to_yaml(svc)
                    pce_services[name] = serialized
        except Exception as e:
            log.error("Failed to fetch services for drift check: %s", e)

        # Compare
        all_names = set(git_services.keys()) | set(pce_services.keys())
        for name in sorted(all_names):
            in_git = name in git_services
            in_pce = name in pce_services

            if in_git and not in_pce:
                drift.append({
                    "type": "service", "name": name, "status": "git_only",
                    "detail": "Exists in Git but not in PCE",
                })
            elif in_pce and not in_git:
                drift.append({
                    "type": "service", "name": name, "status": "pce_only",
                    "detail": "Exists in PCE but not in Git",
                })
            else:
                diffs = self._compare_objects(git_services[name], pce_services[name])
                if diffs:
                    drift.append({
                        "type": "service", "name": name, "status": "drift_modified",
                        "detail": "; ".join(diffs[:5]),
                    })

        return drift

    def _compare_objects(self, git_obj: dict, pce_obj: dict,
                         ignore_keys: set = None) -> list:
        """Recursive field-level comparison of two objects.

        Returns list of difference strings, empty if objects match.
        """
        if ignore_keys is None:
            ignore_keys = set()

        diffs = []
        self._diff_recursive(git_obj, pce_obj, "", ignore_keys, diffs)
        return diffs

    def _diff_recursive(self, a, b, path: str, ignore_keys: set, diffs: list):
        """Walk both structures recursively and report differences."""
        if isinstance(a, dict) and isinstance(b, dict):
            all_keys = set(a.keys()) | set(b.keys())
            for key in sorted(all_keys):
                if key in ignore_keys:
                    continue
                key_path = f"{path}.{key}" if path else key
                if key not in a:
                    diffs.append(f"{key_path}: missing in Git (PCE has value)")
                elif key not in b:
                    diffs.append(f"{key_path}: missing in PCE (Git has value)")
                else:
                    self._diff_recursive(a[key], b[key], key_path, ignore_keys, diffs)

        elif isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                diffs.append(f"{path}: list length differs (git={len(a)}, pce={len(b)})")
            for i in range(min(len(a), len(b))):
                self._diff_recursive(a[i], b[i], f"{path}[{i}]", ignore_keys, diffs)

        else:
            if a != b:
                a_str = str(a)[:80]
                b_str = str(b)[:80]
                diffs.append(f"{path}: git='{a_str}' vs pce='{b_str}'")


# ===================================================================
# Sync orchestration
# ===================================================================

def run_export(pce: PolicyComputeEngine, serializer: PolicySerializer,
               scope_mapper: ScopeMapper, git_client: GitClient):
    """Export PCE policy to Git repository (PCE -> Git direction).

    Fetches all rulesets, IP lists, and services from the PCE, converts them
    to YAML, writes to the appropriate directories, and commits + pushes.
    """
    log.info("Starting export (PCE -> Git)...")
    now = datetime.now(timezone.utc).isoformat()
    counts = {"rulesets": 0, "ip_lists": 0, "services": 0}

    try:
        # Ensure we have latest from remote
        git_client.pull()

        # Refresh all caches
        serializer.refresh_all_caches()

        repo_dir = git_client.repo_dir
        changed_files = []

        # --- Export rulesets ---
        try:
            resp = pce.get("/sec_policy/active/rule_sets", params={"max_results": 5000})
            if resp.status_code == 200:
                rulesets = resp.json()
                log.info("Fetched %d rulesets from PCE", len(rulesets))

                for rs in rulesets:
                    yaml_data = serializer.export_ruleset_to_yaml(rs)
                    directory = scope_mapper.map_ruleset_to_directory(rs)
                    dir_path = repo_dir / directory
                    dir_path.mkdir(parents=True, exist_ok=True)

                    filename = _sanitize_filename(rs.get("name", "unnamed")) + ".yaml"
                    file_path = dir_path / filename

                    yaml_content = yaml.dump(
                        yaml_data, default_flow_style=False,
                        sort_keys=False, allow_unicode=True,
                    )
                    file_path.write_text(yaml_content)
                    changed_files.append(str(file_path.relative_to(repo_dir)))
                    counts["rulesets"] += 1

                    # Write _scope.yaml for non-global scope directories
                    if directory != "scopes/_global":
                        scope_file = dir_path / "_scope.yaml"
                        if not scope_file.exists():
                            scope_labels = {}
                            for scope_entry in yaml_data.get("scopes", []):
                                for item in scope_entry:
                                    if isinstance(item, dict) and "label" in item:
                                        lbl = item["label"]
                                        if isinstance(lbl, dict):
                                            scope_labels.update(lbl)
                            if scope_labels:
                                scope_data = {
                                    "name": directory.split("/")[-1],
                                    "labels": scope_labels,
                                    "owners": [],
                                    "description": f"Auto-generated scope for {directory.split('/')[-1]}",
                                }
                                scope_file.write_text(yaml.dump(
                                    scope_data, default_flow_style=False, sort_keys=False,
                                ))
                                changed_files.append(str(scope_file.relative_to(repo_dir)))
            else:
                log.error("Failed to fetch rulesets: HTTP %d", resp.status_code)
        except Exception as e:
            log.error("Failed to export rulesets: %s", e)

        # --- Export IP lists ---
        try:
            resp = pce.get("/sec_policy/active/ip_lists")
            if resp.status_code == 200:
                ip_lists = resp.json()
                log.info("Fetched %d IP lists from PCE", len(ip_lists))

                ip_lists_dir = repo_dir / "ip-lists"
                ip_lists_dir.mkdir(parents=True, exist_ok=True)

                for ipl in ip_lists:
                    yaml_data = serializer.export_ip_list_to_yaml(ipl)
                    filename = _sanitize_filename(ipl.get("name", "unnamed")) + ".yaml"
                    file_path = ip_lists_dir / filename

                    yaml_content = yaml.dump(
                        yaml_data, default_flow_style=False,
                        sort_keys=False, allow_unicode=True,
                    )
                    file_path.write_text(yaml_content)
                    changed_files.append(str(file_path.relative_to(repo_dir)))
                    counts["ip_lists"] += 1
            else:
                log.error("Failed to fetch IP lists: HTTP %d", resp.status_code)
        except Exception as e:
            log.error("Failed to export IP lists: %s", e)

        # --- Export services ---
        try:
            resp = pce.get("/sec_policy/active/services")
            if resp.status_code == 200:
                services = resp.json()
                log.info("Fetched %d services from PCE", len(services))

                services_dir = repo_dir / "services"
                services_dir.mkdir(parents=True, exist_ok=True)

                for svc in services:
                    yaml_data = serializer.export_service_to_yaml(svc)
                    filename = _sanitize_filename(svc.get("name", "unnamed")) + ".yaml"
                    file_path = services_dir / filename

                    yaml_content = yaml.dump(
                        yaml_data, default_flow_style=False,
                        sort_keys=False, allow_unicode=True,
                    )
                    file_path.write_text(yaml_content)
                    changed_files.append(str(file_path.relative_to(repo_dir)))
                    counts["services"] += 1
            else:
                log.error("Failed to fetch services: HTTP %d", resp.status_code)
        except Exception as e:
            log.error("Failed to export services: %s", e)

        # --- Generate CODEOWNERS ---
        try:
            codeowners_content = scope_mapper.build_codeowners(repo_dir)
            codeowners_path = repo_dir / "CODEOWNERS"
            codeowners_path.write_text(codeowners_content)
            changed_files.append("CODEOWNERS")
        except Exception as e:
            log.warning("Failed to generate CODEOWNERS: %s", e)

        # --- Commit and push ---
        total = counts["rulesets"] + counts["ip_lists"] + counts["services"]
        commit_msg = (
            f"policy-gitops: export from PCE at {now}\n\n"
            f"Exported {counts['rulesets']} rulesets, "
            f"{counts['ip_lists']} IP lists, "
            f"{counts['services']} services"
        )
        git_client.commit(commit_msg, changed_files)
        git_client.push()

        with state_lock:
            app_state["last_export"] = now
            app_state["export_count"] += 1
            app_state["exported_objects"] = counts
            app_state["last_error"] = None

        log.info("Export complete: %d rulesets, %d IP lists, %d services",
                 counts["rulesets"], counts["ip_lists"], counts["services"])

    except Exception as e:
        log.exception("Export failed")
        with state_lock:
            app_state["last_error"] = f"Export failed: {e}"


def run_provision(pce: PolicyComputeEngine, serializer: PolicySerializer,
                  scope_mapper: ScopeMapper, git_client: GitClient):
    """Provision policy from Git to PCE (Git -> PCE direction).

    Reads YAML files from the repo, resolves label/service references,
    creates or updates rulesets, IP lists, and services on the PCE draft,
    and optionally provisions draft -> active.
    """
    log.info("Starting provision (Git -> PCE)...")
    now = datetime.now(timezone.utc).isoformat()
    provisioned_objects = 0
    errors = []

    try:
        # Pull latest from Git
        git_client.pull()

        # Refresh caches for resolution
        serializer.refresh_all_caches()

        repo_dir = git_client.repo_dir

        # Build a map of existing PCE rulesets/ip_lists/services by name for update detection
        pce_rulesets = {}    # name -> href
        pce_ip_lists = {}    # name -> href
        pce_services = {}    # name -> href

        try:
            resp = pce.get("/sec_policy/draft/rule_sets", params={"max_results": 5000})
            if resp.status_code == 200:
                for rs in resp.json():
                    pce_rulesets[rs.get("name", "")] = rs.get("href", "")
        except Exception as e:
            log.warning("Failed to fetch draft rulesets: %s", e)

        # Fall back to active if draft is empty
        if not pce_rulesets:
            try:
                resp = pce.get("/sec_policy/active/rule_sets", params={"max_results": 5000})
                if resp.status_code == 200:
                    for rs in resp.json():
                        pce_rulesets[rs.get("name", "")] = rs.get("href", "")
            except Exception:
                pass

        try:
            resp = pce.get("/sec_policy/draft/ip_lists")
            if resp.status_code == 200:
                for ipl in resp.json():
                    pce_ip_lists[ipl.get("name", "")] = ipl.get("href", "")
        except Exception:
            pass
        if not pce_ip_lists:
            try:
                resp = pce.get("/sec_policy/active/ip_lists")
                if resp.status_code == 200:
                    for ipl in resp.json():
                        pce_ip_lists[ipl.get("name", "")] = ipl.get("href", "")
            except Exception:
                pass

        try:
            resp = pce.get("/sec_policy/draft/services")
            if resp.status_code == 200:
                for svc in resp.json():
                    pce_services[svc.get("name", "")] = svc.get("href", "")
        except Exception:
            pass
        if not pce_services:
            try:
                resp = pce.get("/sec_policy/active/services")
                if resp.status_code == 200:
                    for svc in resp.json():
                        pce_services[svc.get("name", "")] = svc.get("href", "")
            except Exception:
                pass

        provisioned_hrefs = []  # for optional bulk provision at end

        # --- Provision services (must come first, rulesets may reference them) ---
        services_dir = repo_dir / "services"
        if services_dir.is_dir():
            for yaml_file in sorted(services_dir.glob("*.yaml")):
                try:
                    data = yaml.safe_load(yaml_file.read_text())
                    if not data or not isinstance(data, dict):
                        continue
                    name = data.get("name", yaml_file.stem)
                    payload = serializer.import_yaml_to_service(data)

                    if name in pce_services:
                        href = pce_services[name]
                        resp = pce.put(href, json=payload)
                        if resp.status_code in (200, 201, 204):
                            log.info("Updated service: %s", name)
                            provisioned_objects += 1
                        else:
                            errors.append(f"Update service {name}: HTTP {resp.status_code}")
                    else:
                        resp = pce.post("/sec_policy/draft/services", json=payload)
                        if resp.status_code in (200, 201):
                            href = resp.json().get("href", "")
                            log.info("Created service: %s -> %s", name, href)
                            provisioned_objects += 1
                            # Update cache for later ruleset resolution
                            serializer._service_cache[href] = resp.json()
                        else:
                            errors.append(f"Create service {name}: HTTP {resp.status_code}")
                except Exception as e:
                    errors.append(f"Service {yaml_file.name}: {e}")

        # --- Provision IP lists ---
        ip_lists_dir = repo_dir / "ip-lists"
        if ip_lists_dir.is_dir():
            for yaml_file in sorted(ip_lists_dir.glob("*.yaml")):
                try:
                    data = yaml.safe_load(yaml_file.read_text())
                    if not data or not isinstance(data, dict):
                        continue
                    name = data.get("name", yaml_file.stem)
                    payload = serializer.import_yaml_to_ip_list(data)

                    if name in pce_ip_lists:
                        href = pce_ip_lists[name]
                        resp = pce.put(href, json=payload)
                        if resp.status_code in (200, 201, 204):
                            log.info("Updated IP list: %s", name)
                            provisioned_objects += 1
                        else:
                            errors.append(f"Update IP list {name}: HTTP {resp.status_code}")
                    else:
                        resp = pce.post("/sec_policy/draft/ip_lists", json=payload)
                        if resp.status_code in (200, 201):
                            href = resp.json().get("href", "")
                            log.info("Created IP list: %s -> %s", name, href)
                            provisioned_objects += 1
                            serializer._ip_list_cache[href] = resp.json()
                        else:
                            errors.append(f"Create IP list {name}: HTTP {resp.status_code}")
                except Exception as e:
                    errors.append(f"IP list {yaml_file.name}: {e}")

        # --- Provision rulesets ---
        scopes_dir = repo_dir / "scopes"
        if scopes_dir.is_dir():
            for yaml_file in sorted(scopes_dir.rglob("*.yaml")):
                if yaml_file.name.startswith("_"):
                    continue
                try:
                    data = yaml.safe_load(yaml_file.read_text())
                    if not data or not isinstance(data, dict):
                        continue
                    # Only process files that look like rulesets (have rules key)
                    if "rules" not in data:
                        continue

                    name = data.get("name", yaml_file.stem)

                    # If scope info is not in the YAML, try to infer from _scope.yaml
                    if not data.get("scopes"):
                        scope_labels = scope_mapper.resolve_scope_labels(
                            str(yaml_file.parent)
                        )
                        if scope_labels:
                            data["scopes"] = [
                                [{"label": lbl} for lbl in scope_labels]
                            ]

                    payload = serializer.import_yaml_to_ruleset(data)

                    if name in pce_rulesets:
                        href = pce_rulesets[name]
                        resp = pce.put(href, json=payload)
                        if resp.status_code in (200, 201, 204):
                            log.info("Updated ruleset: %s", name)
                            provisioned_objects += 1
                            provisioned_hrefs.append(href)
                        else:
                            errors.append(f"Update ruleset {name}: HTTP {resp.status_code}")
                    else:
                        resp = pce.post("/sec_policy/draft/rule_sets", json=payload)
                        if resp.status_code in (200, 201):
                            href = resp.json().get("href", "")
                            log.info("Created ruleset: %s -> %s", name, href)
                            provisioned_objects += 1
                            provisioned_hrefs.append(href)
                        else:
                            errors.append(f"Create ruleset {name}: HTTP {resp.status_code}")
                except Exception as e:
                    errors.append(f"Ruleset {yaml_file.name}: {e}")

        # --- Optionally provision draft -> active ---
        provision_status = "draft_only"
        if AUTO_PROVISION and provisioned_objects > 0:
            try:
                provision_data = {
                    "update_description": f"policy-gitops provision at {now}",
                }
                # If we have specific hrefs, do a targeted provision
                if provisioned_hrefs:
                    provision_data["change_subset"] = {
                        "rule_sets": [{"href": h} for h in provisioned_hrefs]
                    }

                resp = pce.post("/sec_policy", json=provision_data)
                if resp.status_code in (200, 201, 204):
                    log.info("Provisioned draft -> active")
                    provision_status = "provisioned"
                else:
                    error_msg = f"Provision draft->active: HTTP {resp.status_code}"
                    errors.append(error_msg)
                    provision_status = "provision_failed"
            except Exception as e:
                errors.append(f"Provision draft->active: {e}")
                provision_status = "provision_failed"

        # Build result
        status_str = provision_status
        if errors:
            status_str += f" ({len(errors)} errors)"
        detail = "; ".join(errors[:10]) if errors else f"{provisioned_objects} objects synced"

        provision_entry = {
            "timestamp": now,
            "objects": provisioned_objects,
            "status": status_str,
            "detail": detail,
        }

        with state_lock:
            app_state["last_provision"] = now
            app_state["provision_count"] += 1
            app_state["provision_history"].append(provision_entry)
            if len(app_state["provision_history"]) > 50:
                app_state["provision_history"] = app_state["provision_history"][-50:]
            app_state["last_error"] = errors[0] if errors else None

        log.info("Provision complete: %d objects, status=%s", provisioned_objects, status_str)

    except Exception as e:
        log.exception("Provision failed")
        with state_lock:
            app_state["last_error"] = f"Provision failed: {e}"
            app_state["provision_history"].append({
                "timestamp": now, "objects": 0,
                "status": "failed", "detail": str(e),
            })


def run_drift_check(pce: PolicyComputeEngine, detector: DriftDetector):
    """Run drift detection between Git and PCE."""
    log.info("Running drift detection...")
    now = datetime.now(timezone.utc).isoformat()

    try:
        drift_items = detector.compare_git_vs_pce(pce)

        with state_lock:
            app_state["drift_items"] = drift_items
            app_state["last_drift_check"] = now
            app_state["drift_count"] = len(
                [d for d in drift_items if d["status"] != "in_sync"]
            )
            app_state["last_error"] = None

        drifted = [d for d in drift_items if d["status"] != "in_sync"]
        log.info("Drift check complete: %d items checked, %d drifted",
                 len(drift_items), len(drifted))

    except Exception as e:
        log.exception("Drift check failed")
        with state_lock:
            app_state["last_error"] = f"Drift check failed: {e}"


# ===================================================================
# Background sync loop
# ===================================================================

def sync_loop(pce: PolicyComputeEngine, serializer: PolicySerializer,
              scope_mapper: ScopeMapper, git_client: GitClient,
              detector: DriftDetector):
    """Background thread that runs sync operations on schedule."""
    while True:
        try:
            with state_lock:
                app_state["status"] = "syncing"

            if SYNC_MODE in ("export", "bidirectional"):
                run_export(pce, serializer, scope_mapper, git_client)

            if SYNC_MODE in ("provision", "bidirectional"):
                run_provision(pce, serializer, scope_mapper, git_client)

            if DRIFT_ALERT:
                run_drift_check(pce, detector)

            with state_lock:
                app_state["status"] = "idle"
                app_state["last_sync"] = datetime.now(timezone.utc).isoformat()
                app_state["sync_count"] += 1

            log.info("Sync cycle #%d complete, sleeping %ds",
                     app_state["sync_count"], SCAN_INTERVAL)

        except Exception:
            log.exception("Sync cycle failed")
            with state_lock:
                app_state["status"] = "error"
                app_state["last_error"] = "Sync cycle failed -- see logs"

        time.sleep(SCAN_INTERVAL)


# ===================================================================
# Dashboard HTML
# ===================================================================

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Policy GitOps</title>
<style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#11111b; color:#cdd6f4; min-height:100vh; }
    .container { max-width:960px; margin:0 auto; padding:32px 24px; }
    h1 { font-size:24px; font-weight:700; margin-bottom:8px; color:#fff; }
    h2 { font-size:16px; font-weight:600; margin-bottom:16px; color:#cdd6f4; }
    .subtitle { color:#6b7280; font-size:14px; margin-bottom:24px; }
    .card { background:#1e1e2e; border-radius:12px; padding:24px; margin-bottom:16px; border:1px solid #313244; }
    .tabs { display:flex; gap:0; margin-bottom:24px; border-bottom:1px solid #313244; }
    .tab { padding:10px 20px; cursor:pointer; color:#6b7280; font-size:14px; font-weight:500; border-bottom:2px solid transparent; transition:all 0.2s; }
    .tab:hover { color:#cdd6f4; }
    .tab.active { color:#93c5fd; border-bottom-color:#93c5fd; }
    .tab-content { display:none; }
    .tab-content.active { display:block; }
    .badge { display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:999px; font-size:12px; font-weight:600; }
    .badge-green { background:#052e16; color:#22c55e; }
    .badge-yellow { background:#422006; color:#eab308; }
    .badge-red { background:#450a0a; color:#ef4444; }
    .badge-gray { background:#1f2937; color:#9ca3af; }
    .badge-blue { background:#172554; color:#60a5fa; }
    .stat-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:20px; }
    .stat { background:#11111b; border-radius:8px; padding:16px; text-align:center; }
    .stat-value { font-size:28px; font-weight:700; color:#fff; }
    .stat-label { font-size:12px; color:#6b7280; margin-top:4px; }
    .kv { display:flex; gap:8px; padding:8px 0; border-bottom:1px solid #31324440; font-size:13px; }
    .kv:last-child { border-bottom:none; }
    .kv-key { color:#6b7280; min-width:140px; }
    .kv-val { color:#cdd6f4; word-break:break-all; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th { text-align:left; padding:8px 12px; color:#6b7280; border-bottom:1px solid #313244; font-weight:500; text-transform:uppercase; font-size:11px; letter-spacing:0.05em; }
    td { padding:8px 12px; border-bottom:1px solid #31324440; }
    tr:hover { background:#31324420; }
    code { background:#313244; padding:2px 6px; border-radius:4px; font-size:12px; }
    .empty { color:#6b7280; font-style:italic; padding:24px; text-align:center; }
    .btn { display:inline-flex; align-items:center; gap:6px; padding:8px 16px; border-radius:8px; border:1px solid #313244; background:#1e1e2e; color:#cdd6f4; font-size:13px; cursor:pointer; transition:all 0.2s; }
    .btn:hover { background:#313244; border-color:#585b70; }
    .btn-primary { background:#1d4ed8; border-color:#1d4ed8; color:#fff; }
    .btn-primary:hover { background:#2563eb; }
    .footer { text-align:center; color:#6b7280; font-size:12px; margin-top:32px; }
    .footer a { color:#93c5fd; text-decoration:none; }
    .footer a:hover { text-decoration:underline; }
    @keyframes fadeIn { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:translateY(0); } }
    .fade-in { animation:fadeIn 0.3s ease-out; }
</style>
</head>
<body>
<div class="container">
    <h1>Policy GitOps</h1>
    <div class="subtitle" id="subtitle">Loading...</div>

    <!-- Status card -->
    <div class="card fade-in" id="status-card">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
            <span id="status-badge" class="badge badge-gray">INITIALIZING</span>
            <span style="color:#6b7280;font-size:12px;" id="sync-count"></span>
        </div>
        <div class="stat-row">
            <div class="stat">
                <div class="stat-value" id="stat-exports">0</div>
                <div class="stat-label">Exports</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="stat-drift">0</div>
                <div class="stat-label">Drift Items</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="stat-provisions">0</div>
                <div class="stat-label">Provisions</div>
            </div>
        </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
        <div class="tab active" data-tab="export">Export Status</div>
        <div class="tab" data-tab="drift">Drift Report</div>
        <div class="tab" data-tab="provision">Provisioning</div>
        <div class="tab" data-tab="config">Config</div>
    </div>

    <!-- Export Tab -->
    <div class="tab-content active" id="tab-export">
        <div class="card fade-in">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
                <h2 style="margin-bottom:0;">Export Status (PCE -> Git)</h2>
                <button class="btn btn-primary" onclick="triggerExport()">Run Export</button>
            </div>
            <div class="kv"><span class="kv-key">Last export</span><span class="kv-val" id="last-export">never</span></div>
            <div class="kv"><span class="kv-key">Export count</span><span class="kv-val" id="export-count">0</span></div>
            <div class="kv"><span class="kv-key">Rulesets</span><span class="kv-val" id="export-rulesets">0</span></div>
            <div class="kv"><span class="kv-key">IP Lists</span><span class="kv-val" id="export-iplists">0</span></div>
            <div class="kv"><span class="kv-key">Services</span><span class="kv-val" id="export-services">0</span></div>
        </div>
    </div>

    <!-- Drift Tab -->
    <div class="tab-content" id="tab-drift">
        <div class="card fade-in">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
                <h2 style="margin-bottom:0;">Drift Report (Git vs PCE)</h2>
                <span style="color:#6b7280;font-size:12px;" id="drift-time">Last check: never</span>
            </div>
            <div id="drift-table-container">
                <div class="empty">No drift items detected (or sync has not run yet).</div>
            </div>
        </div>
    </div>

    <!-- Provision Tab -->
    <div class="tab-content" id="tab-provision">
        <div class="card fade-in">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
                <h2 style="margin-bottom:0;">Provisioning (Git -> PCE)</h2>
                <button class="btn btn-primary" onclick="triggerProvision()">Run Provision</button>
            </div>
            <div class="kv"><span class="kv-key">Last provision</span><span class="kv-val" id="last-provision">never</span></div>
            <div class="kv"><span class="kv-key">Provision count</span><span class="kv-val" id="provision-count">0</span></div>
            <div class="kv"><span class="kv-key">Auto-provision</span><span class="kv-val" id="auto-provision">-</span></div>

            <h2 style="margin-top:24px;">History</h2>
            <div id="provision-history">
                <div class="empty">No provisioning history yet.</div>
            </div>
        </div>
    </div>

    <!-- Config Tab -->
    <div class="tab-content" id="tab-config">
        <div class="card fade-in">
            <h2>Configuration</h2>
            <div class="kv"><span class="kv-key">Git repository</span><span class="kv-val" id="cfg-repo">-</span></div>
            <div class="kv"><span class="kv-key">Branch</span><span class="kv-val" id="cfg-branch">-</span></div>
            <div class="kv"><span class="kv-key">Provider</span><span class="kv-val" id="cfg-provider">-</span></div>
            <div class="kv"><span class="kv-key">Sync mode</span><span class="kv-val" id="cfg-mode">-</span></div>
            <div class="kv"><span class="kv-key">Scan interval</span><span class="kv-val" id="cfg-interval">-</span></div>
            <div class="kv"><span class="kv-key">Drift alerts</span><span class="kv-val" id="cfg-drift">-</span></div>
        </div>
    </div>

    <div class="footer">
        Auto-refreshes every 15s &middot;
        <a href="/api/state">JSON API</a> &middot;
        <a href="/healthz">Health</a>
    </div>
</div>

<script>
// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
});

// Detect base URL for reverse proxy support
const BASE = (() => {
    const m = window.location.pathname.match(/^\\/plugins\\/[^/]+\\/ui/);
    return m ? m[0] : '';
})();

function fmt(ts) {
    if (!ts) return 'never';
    return new Date(ts).toLocaleString();
}

function statusBadge(status) {
    const map = {
        idle: ['IDLE', 'badge-green'],
        syncing: ['SYNCING', 'badge-blue'],
        error: ['ERROR', 'badge-red'],
        initializing: ['INITIALIZING', 'badge-gray'],
    };
    const [label, cls] = map[status] || ['UNKNOWN', 'badge-gray'];
    return `<span class="badge ${cls}">${label}</span>`;
}

function driftBadge(status) {
    const map = {
        in_sync: ['In Sync', 'badge-green'],
        drift_modified: ['Modified', 'badge-yellow'],
        git_only: ['Git Only', 'badge-blue'],
        pce_only: ['PCE Only', 'badge-red'],
    };
    const [label, cls] = map[status] || [status, 'badge-gray'];
    return `<span class="badge ${cls}">${label}</span>`;
}

async function fetchState() {
    try {
        const resp = await fetch(BASE + '/api/state');
        const s = await resp.json();

        // Status
        document.getElementById('status-badge').outerHTML = statusBadge(s.status);
        document.getElementById('sync-count').textContent = 'Sync #' + s.sync_count;
        document.getElementById('subtitle').textContent =
            s.sync_mode + ' mode | ' + s.git_repo + ' @ ' + s.git_branch;

        // Stats
        document.getElementById('stat-exports').textContent = s.export_count;
        document.getElementById('stat-drift').textContent = s.drift_count;
        document.getElementById('stat-provisions').textContent = s.provision_count;

        // Export tab
        document.getElementById('last-export').textContent = fmt(s.last_export);
        document.getElementById('export-count').textContent = s.export_count;
        const eo = s.exported_objects || {};
        document.getElementById('export-rulesets').textContent = eo.rulesets || 0;
        document.getElementById('export-iplists').textContent = eo.ip_lists || 0;
        document.getElementById('export-services').textContent = eo.services || 0;

        // Drift tab
        document.getElementById('drift-time').textContent = 'Last check: ' + fmt(s.last_drift_check);
        const driftContainer = document.getElementById('drift-table-container');
        if (s.drift_items && s.drift_items.length > 0) {
            let html = '<table><thead><tr><th>Type</th><th>Name</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
            s.drift_items.forEach(d => {
                html += `<tr><td>${d.type}</td><td><code>${d.name}</code></td><td>${driftBadge(d.status)}</td><td>${d.detail || ''}</td></tr>`;
            });
            html += '</tbody></table>';
            driftContainer.innerHTML = html;
        } else {
            driftContainer.innerHTML = '<div class="empty">No drift items detected (or sync has not run yet).</div>';
        }

        // Provision tab
        document.getElementById('last-provision').textContent = fmt(s.last_provision);
        document.getElementById('provision-count').textContent = s.provision_count;
        document.getElementById('auto-provision').textContent = s.auto_provision || 'false';
        const phContainer = document.getElementById('provision-history');
        if (s.provision_history && s.provision_history.length > 0) {
            let html = '<table><thead><tr><th>Time</th><th>Objects</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
            s.provision_history.slice().reverse().forEach(p => {
                html += `<tr><td>${fmt(p.timestamp)}</td><td>${p.objects}</td><td>${p.status}</td><td>${p.detail || ''}</td></tr>`;
            });
            html += '</tbody></table>';
            phContainer.innerHTML = html;
        } else {
            phContainer.innerHTML = '<div class="empty">No provisioning history yet.</div>';
        }

        // Config tab
        document.getElementById('cfg-repo').textContent = s.git_repo || '-';
        document.getElementById('cfg-branch').textContent = s.git_branch || '-';
        document.getElementById('cfg-provider').textContent = s.git_provider || '-';
        document.getElementById('cfg-mode').textContent = s.sync_mode || '-';
        document.getElementById('cfg-interval').textContent = (s.scan_interval || SCAN_INTERVAL) + 's';
        document.getElementById('cfg-drift').textContent = s.drift_alert || '-';

    } catch (e) {
        console.error('Fetch failed:', e);
    }
}

async function triggerExport() {
    try {
        const resp = await fetch(BASE + '/api/export', { method: 'POST' });
        const data = await resp.json();
        alert(data.message || 'Export triggered');
        setTimeout(fetchState, 1000);
    } catch (e) {
        alert('Failed to trigger export: ' + e);
    }
}

async function triggerProvision() {
    if (!confirm('Provision policy from Git to PCE? This will modify PCE draft policy.')) return;
    try {
        const resp = await fetch(BASE + '/api/provision', { method: 'POST' });
        const data = await resp.json();
        alert(data.message || 'Provision triggered');
        setTimeout(fetchState, 1000);
    } catch (e) {
        alert('Failed to trigger provision: ' + e);
    }
}

// Init
fetchState();
setInterval(fetchState, 15000);
</script>
</body>
</html>"""


# ===================================================================
# HTTP server
# ===================================================================

class GitOpsHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Policy GitOps dashboard and API."""

    # These are set in main() before the server starts
    pce = None
    serializer = None
    scope_mapper = None
    git_client = None
    detector = None

    def do_GET(self):
        path = self.path.split("?")[0]  # strip query params

        if path == "/healthz":
            self.send_json(200, {"status": "healthy"})

        elif path == "/api/state":
            with state_lock:
                data = dict(app_state)
                data["auto_provision"] = str(AUTO_PROVISION).lower()
                data["scan_interval"] = SCAN_INTERVAL
                data["drift_alert"] = str(DRIFT_ALERT).lower()
            self.send_json(200, data)

        elif path == "/api/drift":
            # Trigger a drift check and return results
            threading.Thread(
                target=run_drift_check,
                args=(self.pce, self.detector),
                daemon=True,
            ).start()
            self.send_json(200, {"message": "Drift check triggered", "status": "accepted"})

        elif path == "/":
            self.send_html(DASHBOARD_HTML)

        else:
            self.send_error(404)

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/api/export":
            threading.Thread(
                target=run_export,
                args=(self.pce, self.serializer, self.scope_mapper, self.git_client),
                daemon=True,
            ).start()
            self.send_json(200, {"message": "Export triggered", "status": "accepted"})

        elif path == "/api/provision":
            threading.Thread(
                target=run_provision,
                args=(self.pce, self.serializer, self.scope_mapper, self.git_client),
                daemon=True,
            ).start()
            self.send_json(200, {"message": "Provision triggered", "status": "accepted"})

        elif path == "/api/drift":
            threading.Thread(
                target=run_drift_check,
                args=(self.pce, self.detector),
                daemon=True,
            ).start()
            self.send_json(200, {"message": "Drift check triggered", "status": "accepted"})

        else:
            self.send_error(404)

    def send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # suppress default HTTP logging


# ===================================================================
# Main entrypoint
# ===================================================================

def main():
    log.info("Starting policy-gitops...")
    log.info("  SYNC_MODE=%s", SYNC_MODE)
    log.info("  GIT_REPO_URL=%s", GIT_REPO_URL)
    log.info("  GIT_BRANCH=%s", GIT_BRANCH)
    log.info("  GIT_PROVIDER=%s", GIT_PROVIDER)
    log.info("  SCAN_INTERVAL=%ds", SCAN_INTERVAL)
    log.info("  AUTO_PROVISION=%s", AUTO_PROVISION)
    log.info("  DRIFT_ALERT=%s", DRIFT_ALERT)

    port = int(os.environ.get("HTTP_PORT", "8080"))

    # Initialize PCE client
    pce = get_pce()
    log.info("Connected to PCE: %s", pce.base_url)

    # Initialize components
    serializer = PolicySerializer(pce)
    scope_mapper = ScopeMapper(serializer)
    git_client = GitClient(
        repo_url=GIT_REPO_URL,
        token=GIT_TOKEN,
        branch=GIT_BRANCH,
        provider=GIT_PROVIDER,
        repo_dir=REPO_DIR,
    )
    detector = DriftDetector(serializer, scope_mapper, git_client)

    # Initialize Git repo
    git_client.clone()

    # Attach references to handler class for HTTP endpoints
    GitOpsHandler.pce = pce
    GitOpsHandler.serializer = serializer
    GitOpsHandler.scope_mapper = scope_mapper
    GitOpsHandler.git_client = git_client
    GitOpsHandler.detector = detector

    # Start background sync loop
    sync_thread = threading.Thread(
        target=sync_loop,
        args=(pce, serializer, scope_mapper, git_client, detector),
        daemon=True,
    )
    sync_thread.start()

    with state_lock:
        app_state["status"] = "idle"

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", port), GitOpsHandler)
    log.info("Dashboard listening on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Received signal %d, shutting down...", signum)
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server.serve_forever()
    log.info("Stopped.")


if __name__ == "__main__":
    main()
