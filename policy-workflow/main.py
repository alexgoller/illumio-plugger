#!/usr/bin/env python3
"""
policy-workflow — Approval workflow for Illumio PCE policy changes.

Detects draft policy changes, classifies them by risk, routes approval
requests to external workflow systems, and gates provisioning on approval.

PCE connection details are injected as environment variables:
  PCE_HOST, PCE_PORT, PCE_ORG_ID, PCE_API_KEY, PCE_API_SECRET
"""

import json
import logging
import os
import signal
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("policy_workflow")


# ============================================================
# PCE Client
# ============================================================

def get_pce():
    """Create an authenticated PCE client from environment variables."""
    from illumio import PolicyComputeEngine

    pce = PolicyComputeEngine(
        url=os.environ.get("PCE_HOST", ""),
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ.get("PCE_API_KEY", ""),
        password=os.environ.get("PCE_API_SECRET", ""),
    )
    skip_tls = os.environ.get("PCE_TLS_SKIP_VERIFY", "false").lower() in ("true", "1", "yes")
    pce.set_tls_settings(verify=not skip_tls)
    return pce


# ============================================================
# Constants and Configuration
# ============================================================

RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-HTTPS",
}

BROAD_CIDR_PREFIXES = [0, 1, 2, 3, 4, 5, 6, 7, 8]  # /0 through /8


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ChangeStatus(str, Enum):
    DETECTED = "detected"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    PROVISIONING = "provisioning"
    PROVISIONED = "provisioned"
    FAILED = "failed"


class ChangeType(str, Enum):
    NEW_RULESET = "new_ruleset"
    MODIFIED_RULESET = "modified_ruleset"
    DELETED_RULESET = "deleted_ruleset"
    NEW_RULE = "new_rule"
    MODIFIED_RULE = "modified_rule"
    DELETED_RULE = "deleted_rule"
    NEW_IP_LIST = "new_ip_list"
    MODIFIED_IP_LIST = "modified_ip_list"
    NEW_SERVICE = "new_service"
    MODIFIED_SERVICE = "modified_service"
    NEW_LABEL_GROUP = "new_label_group"
    MODIFIED_LABEL_GROUP = "modified_label_group"
    MODIFIED_ENFORCEMENT_BOUNDARY = "modified_enforcement_boundary"
    DELETED_ENFORCEMENT_BOUNDARY = "deleted_enforcement_boundary"


# ============================================================
# Approval Configuration
# ============================================================

def load_approval_config(path: str = "/data/approval-config.yaml") -> dict:
    """Load approval routing configuration from YAML file."""
    default_config = {
        "approvers": {
            "scopes": {},
            "default": {
                "team": "security-team",
                "slack_channel": "#security-approvals",
                "email": "security@example.com",
            },
            "cross_scope": {
                "team": "security-team",
                "slack_channel": "#security-approvals",
            },
            "critical": {
                "team": "security-leadership",
                "slack_channel": "#security-urgent",
            },
        },
        "require_approval": ["critical", "high", "medium"],
        "auto_provision": False,
    }

    if not os.path.exists(path):
        log.warning("Approval config not found at %s, using defaults", path)
        return default_config

    try:
        with open(path, "r") as f:
            config = yaml.safe_load(f)
        if not config:
            return default_config
        return config
    except Exception:
        log.exception("Failed to load approval config from %s", path)
        return default_config


# ============================================================
# Risk Classifier — FULLY FUNCTIONAL
# ============================================================

class RiskClassifier:
    """Classify policy changes by risk level.

    This classifier implements the full risk matrix from the design doc.
    It examines rule properties (actors, ports, scope, IP ranges) to
    assign critical/high/medium/low/info risk levels with reasons.
    """

    def classify(self, change: dict) -> tuple:
        """Classify a change and return (RiskLevel, list_of_reasons).

        Args:
            change: A dict describing the change, with keys like:
                - change_type: one of ChangeType values
                - rule: the rule object (if applicable)
                - ruleset: the ruleset object (if applicable)
                - ip_list: the IP list object (if applicable)
                - old_value / new_value: for modifications

        Returns:
            Tuple of (RiskLevel, list[str]) where reasons explain the rating.
        """
        change_type = change.get("change_type", "")
        reasons = []

        # --- CRITICAL checks ---

        # Any-to-any rule (ams on both providers and consumers)
        if self._is_any_to_any(change):
            reasons.append("Any-to-any rule (all workloads on both sides)")
            return RiskLevel.CRITICAL, reasons

        # Huge port range (> 1000 ports)
        port_range_size = self._get_port_range_size(change)
        if port_range_size > 1000:
            reasons.append(f"Excessively broad port range ({port_range_size} ports)")
            return RiskLevel.CRITICAL, reasons

        # Deletion of enforcement boundary
        if change_type in (ChangeType.DELETED_ENFORCEMENT_BOUNDARY,):
            reasons.append("Deletion of enforcement boundary")
            return RiskLevel.CRITICAL, reasons

        # Enabling a previously disabled ruleset with broad scope
        if change_type == ChangeType.MODIFIED_RULESET:
            if self._is_ruleset_being_enabled(change) and self._is_broad_scope(change):
                reasons.append("Enabling a disabled ruleset with broad scope")
                return RiskLevel.CRITICAL, reasons

        # --- HIGH checks ---

        # Cross-scope / extra-scope rules
        if self._is_cross_scope(change):
            reasons.append("Cross-scope rule (unscoped consumers)")

        # Risky ports
        risky = self._get_risky_ports(change)
        for port_num, port_name in risky:
            reasons.append(f"Allows {port_name} ({port_num}/tcp)")

        # New ruleset with broad scope (env-only, no app constraint)
        if change_type == ChangeType.NEW_RULESET and self._is_broad_scope(change):
            reasons.append("New ruleset with broad scope (no app-level constraint)")

        # IP list adding 0.0.0.0/0 or broad CIDRs
        if change_type in (ChangeType.NEW_IP_LIST, ChangeType.MODIFIED_IP_LIST):
            broad = self._get_broad_cidrs(change)
            for cidr in broad:
                reasons.append(f"IP list contains broad CIDR: {cidr}")

        if reasons:
            return RiskLevel.HIGH, reasons

        # --- MEDIUM checks ---

        # New intra-scope rules with specific services
        if change_type == ChangeType.NEW_RULE and not self._is_cross_scope(change):
            services = self._get_services_summary(change)
            if services:
                reasons.append(f"New intra-scope rule with services: {services}")
                return RiskLevel.MEDIUM, reasons
            reasons.append("New intra-scope rule")
            return RiskLevel.MEDIUM, reasons

        # Modifications to existing rules
        if change_type == ChangeType.MODIFIED_RULE:
            reasons.append("Modified existing rule")
            return RiskLevel.MEDIUM, reasons

        # New IP lists with specific ranges
        if change_type == ChangeType.NEW_IP_LIST:
            reasons.append("New IP list")
            return RiskLevel.MEDIUM, reasons

        # Modified IP lists
        if change_type == ChangeType.MODIFIED_IP_LIST:
            reasons.append("Modified IP list")
            return RiskLevel.MEDIUM, reasons

        # --- LOW checks ---

        # Disabling a rule
        if change_type == ChangeType.MODIFIED_RULE and self._is_rule_being_disabled(change):
            reasons.append("Rule disabled (reducing access)")
            return RiskLevel.LOW, reasons

        # Deleted rule
        if change_type == ChangeType.DELETED_RULE:
            reasons.append("Rule deleted")
            return RiskLevel.LOW, reasons

        # Ruleset name/description changes
        if change_type == ChangeType.MODIFIED_RULESET and not self._is_ruleset_being_enabled(change):
            reasons.append("Ruleset metadata change")
            return RiskLevel.LOW, reasons

        # New ruleset (non-broad)
        if change_type == ChangeType.NEW_RULESET:
            reasons.append("New ruleset")
            return RiskLevel.MEDIUM, reasons

        # Deleted ruleset
        if change_type == ChangeType.DELETED_RULESET:
            reasons.append("Ruleset deleted")
            return RiskLevel.MEDIUM, reasons

        # --- INFO checks ---

        if change_type in (ChangeType.NEW_LABEL_GROUP, ChangeType.MODIFIED_LABEL_GROUP):
            reasons.append("Label group change")
            return RiskLevel.INFO, reasons

        if change_type in (ChangeType.NEW_SERVICE, ChangeType.MODIFIED_SERVICE):
            reasons.append("Service definition change")
            return RiskLevel.INFO, reasons

        # Fallback
        reasons.append("Unclassified change")
        return RiskLevel.MEDIUM, reasons

    # ---- Helper methods ----

    def _is_any_to_any(self, change: dict) -> bool:
        """Check if rule has 'ams' (all managed systems) on both providers and consumers."""
        rule = change.get("rule", {})
        if not rule:
            return False

        providers = rule.get("providers", [])
        consumers = rule.get("consumers", [])

        providers_ams = any(
            (isinstance(a, dict) and a.get("actors") == "ams") or a == "ams"
            for a in providers
        )
        consumers_ams = any(
            (isinstance(a, dict) and a.get("actors") == "ams") or a == "ams"
            for a in consumers
        )
        return providers_ams and consumers_ams

    def _get_port_range_size(self, change: dict) -> int:
        """Return the largest port range size in the rule's ingress services."""
        rule = change.get("rule", {})
        if not rule:
            return 0

        max_range = 0
        for svc in rule.get("ingress_services", []):
            if isinstance(svc, dict):
                port = svc.get("port")
                to_port = svc.get("to_port")
                if port is not None and to_port is not None:
                    range_size = to_port - port + 1
                    max_range = max(max_range, range_size)
        return max_range

    def _is_cross_scope(self, change: dict) -> bool:
        """Check if the rule uses unscoped_consumers (cross-scope / extra-scope)."""
        rule = change.get("rule", {})
        if not rule:
            return False
        return bool(rule.get("unscoped_consumers", False))

    def _get_risky_ports(self, change: dict) -> list:
        """Return list of (port_number, port_name) for any risky ports in the rule."""
        rule = change.get("rule", {})
        if not rule:
            return []

        found = []
        for svc in rule.get("ingress_services", []):
            if isinstance(svc, dict):
                port = svc.get("port")
                to_port = svc.get("to_port", port)
                if port is not None:
                    # Check single port or range
                    check_end = to_port if to_port is not None else port
                    for risky_port, name in RISKY_PORTS.items():
                        if port <= risky_port <= check_end:
                            found.append((risky_port, name))
        return found

    def _is_broad_scope(self, change: dict) -> bool:
        """Check if ruleset has a broad scope (env-only, no app constraint)."""
        ruleset = change.get("ruleset", {})
        if not ruleset:
            return False

        scopes = ruleset.get("scopes", [])
        if not scopes:
            return True  # No scope at all = broadest possible

        for scope_list in scopes:
            if not isinstance(scope_list, list):
                continue
            # Check if scope only has env-level labels, no app-level
            keys = set()
            for label_ref in scope_list:
                if isinstance(label_ref, dict):
                    label = label_ref.get("label", {})
                    if isinstance(label, dict):
                        keys.add(label.get("key", ""))
            if keys and "app" not in keys:
                return True

        return False

    def _is_ruleset_being_enabled(self, change: dict) -> bool:
        """Check if ruleset is being changed from disabled to enabled."""
        old = change.get("old_value", {})
        new = change.get("new_value", {})
        if isinstance(old, dict) and isinstance(new, dict):
            return old.get("enabled") is False and new.get("enabled") is True
        return False

    def _is_rule_being_disabled(self, change: dict) -> bool:
        """Check if a rule is being disabled."""
        old = change.get("old_value", {})
        new = change.get("new_value", {})
        if isinstance(old, dict) and isinstance(new, dict):
            return old.get("enabled") is not False and new.get("enabled") is False
        return False

    def _get_broad_cidrs(self, change: dict) -> list:
        """Return list of overly broad CIDRs in an IP list change."""
        ip_list = change.get("ip_list", {}) or change.get("new_value", {})
        if not ip_list:
            return []

        broad = []
        for entry in ip_list.get("ip_ranges", []):
            if isinstance(entry, dict):
                from_ip = entry.get("from_ip", "")
                # Check for 0.0.0.0/0 or very broad CIDRs
                if from_ip == "0.0.0.0/0" or from_ip == "::/0":
                    broad.append(from_ip)
                elif "/" in from_ip:
                    try:
                        prefix_len = int(from_ip.split("/")[1])
                        if prefix_len in BROAD_CIDR_PREFIXES:
                            broad.append(from_ip)
                    except (ValueError, IndexError):
                        pass
        return broad

    def _get_services_summary(self, change: dict) -> str:
        """Return a short summary of the services in a rule."""
        rule = change.get("rule", {})
        if not rule:
            return ""

        parts = []
        for svc in rule.get("ingress_services", []):
            if isinstance(svc, dict):
                port = svc.get("port")
                to_port = svc.get("to_port")
                proto = svc.get("proto", 6)
                proto_name = {6: "tcp", 17: "udp"}.get(proto, str(proto))
                if port is not None:
                    if to_port and to_port != port:
                        parts.append(f"{port}-{to_port}/{proto_name}")
                    else:
                        parts.append(f"{port}/{proto_name}")
                elif svc.get("href"):
                    parts.append(svc["href"].split("/")[-1])
        return ", ".join(parts[:5])


# ============================================================
# Change Detector (Stub)
# ============================================================

class ChangeDetector:
    """Detect policy changes between PCE draft and active state.

    Polls the PCE API to compare draft vs active rulesets, rules,
    IP lists, services, label groups, and enforcement boundaries.
    """

    def __init__(self, pce):
        self.pce = pce
        self._last_fingerprints = {}  # For deduplication

    def detect_draft_changes(self) -> list:
        """Poll PCE and return a list of detected changes.

        Each change is a dict suitable for RiskClassifier.classify().

        Returns:
            List of change dicts with keys: change_type, rule, ruleset,
            ip_list, old_value, new_value, scope, href, summary.
        """
        changes = []

        # TODO: Implement draft vs active comparison
        # Steps:
        #   1. Fetch draft rulesets: GET /sec_policy/draft/rule_sets
        #   2. Fetch active rulesets: GET /sec_policy/active/rule_sets
        #   3. Compare and identify additions, modifications, deletions
        #   4. For each ruleset, compare individual rules
        #   5. Fetch and compare IP lists, services, label groups
        #   6. Fetch and compare enforcement boundaries
        #   7. Deduplicate by change fingerprint

        try:
            ruleset_changes = self._compare_rulesets()
            changes.extend(ruleset_changes)
        except Exception:
            log.exception("Failed to detect ruleset changes")

        try:
            ip_list_changes = self._compare_ip_lists()
            changes.extend(ip_list_changes)
        except Exception:
            log.exception("Failed to detect IP list changes")

        try:
            service_changes = self._compare_services()
            changes.extend(service_changes)
        except Exception:
            log.exception("Failed to detect service changes")

        # Deduplicate
        changes = self._deduplicate(changes)

        log.info("Detected %d draft changes", len(changes))
        return changes

    def _compare_rulesets(self) -> list:
        """Compare draft vs active rulesets and their rules.

        Returns list of change dicts for new/modified/deleted rulesets and rules.
        """
        # TODO: Implement
        # draft_rulesets = self.pce.rulesets.get(policy_version="draft")
        # active_rulesets = self.pce.rulesets.get(policy_version="active")
        # ... compare by href, content hash ...
        return []

    def _compare_ip_lists(self) -> list:
        """Compare draft vs active IP lists.

        Returns list of change dicts for new/modified IP lists.
        """
        # TODO: Implement
        # draft_ip_lists = self.pce.ip_lists.get(policy_version="draft")
        # active_ip_lists = self.pce.ip_lists.get(policy_version="active")
        return []

    def _compare_services(self) -> list:
        """Compare draft vs active service definitions.

        Returns list of change dicts for new/modified services.
        """
        # TODO: Implement
        # draft_services = self.pce.services.get(policy_version="draft")
        # active_services = self.pce.services.get(policy_version="active")
        return []

    def _deduplicate(self, changes: list) -> list:
        """Remove duplicate changes using content-based fingerprinting."""
        # TODO: Implement fingerprint-based deduplication
        # For now, return all changes
        return changes

    @staticmethod
    def _extract_scope(ruleset: dict) -> str:
        """Extract a human-readable scope string from a ruleset's scopes."""
        # TODO: Implement scope extraction from ruleset scopes
        # e.g., "app=payments AND env=prod"
        scopes = ruleset.get("scopes", [])
        if not scopes:
            return "unscoped"
        parts = []
        for scope_list in scopes:
            if isinstance(scope_list, list):
                labels = []
                for ref in scope_list:
                    if isinstance(ref, dict):
                        label = ref.get("label", {})
                        if isinstance(label, dict):
                            key = label.get("key", "?")
                            value = label.get("value", "?")
                            labels.append(f"{key}={value}")
                if labels:
                    parts.append(" AND ".join(labels))
        return " | ".join(parts) if parts else "unscoped"


# ============================================================
# Approval Manager (Stub)
# ============================================================

class ApprovalManager:
    """Manage the lifecycle of approval requests.

    Tracks change requests through the state machine:
    DETECTED -> PENDING -> APPROVED/REJECTED/EXPIRED -> PROVISIONED/FAILED
    """

    def __init__(self, config: dict, adapter):
        self.config = config
        self.adapter = adapter
        self.requests = {}  # id -> change request dict
        self._lock = threading.Lock()
        self.timeout_seconds = int(os.environ.get("APPROVAL_TIMEOUT", "604800"))
        self.auto_provision = os.environ.get("AUTO_PROVISION", "false").lower() in ("true", "1", "yes")
        self.auto_approve_low = os.environ.get("AUTO_APPROVE_LOW", "true").lower() in ("true", "1", "yes")
        self.require_all = os.environ.get("REQUIRE_ALL_APPROVERS", "true").lower() in ("true", "1", "yes")

    def create_request(self, change: dict, risk_level: RiskLevel, risk_reasons: list) -> dict:
        """Create a new change request from a detected change.

        Args:
            change: The detected change dict from ChangeDetector.
            risk_level: Classified risk level.
            risk_reasons: List of reasons for the risk classification.

        Returns:
            The created change request dict.
        """
        request_id = f"cr-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"

        scope = change.get("scope", "unknown")
        approvers_needed = self._determine_approvers(scope, risk_level)

        require_approval_levels = self.config.get("require_approval", ["critical", "high", "medium"])
        needs_approval = risk_level.value in require_approval_levels

        # Auto-approve low/info if configured
        if not needs_approval and self.auto_approve_low:
            initial_status = ChangeStatus.APPROVED
        else:
            initial_status = ChangeStatus.DETECTED

        request = {
            "id": request_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "status": initial_status.value,
            "risk_level": risk_level.value,
            "risk_reasons": risk_reasons,
            "change_type": change.get("change_type", "unknown"),
            "ruleset_name": change.get("ruleset_name", ""),
            "ruleset_href": change.get("href", ""),
            "scope": scope,
            "change_summary": change.get("summary", "Policy change detected"),
            "change_detail": change,
            "required_approvals": [
                {"team": a["team"], "status": "pending", "via": self.adapter.name}
                for a in approvers_needed
            ],
            "provisioned": False,
            "provisioned_at": None,
            "provision_result": None,
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=self.timeout_seconds)).isoformat(),
        }

        with self._lock:
            self.requests[request_id] = request

        # Send to approval adapter if approval is needed
        if initial_status == ChangeStatus.DETECTED:
            try:
                self.adapter.send_approval_request(request)
                request["status"] = ChangeStatus.PENDING.value
            except Exception:
                log.exception("Failed to send approval request %s to adapter", request_id)

        log.info("Created change request %s: %s [%s]", request_id, risk_level.value, change.get("summary", ""))
        return request

    def check_status(self, request_id: str) -> Optional[dict]:
        """Check the current status of a change request.

        Returns the request dict or None if not found.
        """
        with self._lock:
            return self.requests.get(request_id)

    def list_pending(self) -> list:
        """Return all requests in PENDING or DETECTED status."""
        with self._lock:
            return [
                r for r in self.requests.values()
                if r["status"] in (ChangeStatus.PENDING.value, ChangeStatus.DETECTED.value)
            ]

    def list_all(self) -> list:
        """Return all tracked change requests."""
        with self._lock:
            return list(self.requests.values())

    def approve(self, request_id: str, approver_team: str = "manual") -> Optional[dict]:
        """Record an approval from an approver team.

        If all required approvals are met, transitions to APPROVED.
        Returns the updated request or None if not found.
        """
        with self._lock:
            req = self.requests.get(request_id)
            if not req or req["status"] not in (ChangeStatus.PENDING.value, ChangeStatus.DETECTED.value):
                return req

            # Mark the specific approver as approved
            for appr in req["required_approvals"]:
                if appr["team"] == approver_team or approver_team == "manual":
                    appr["status"] = "approved"
                    appr["approved_at"] = datetime.now(timezone.utc).isoformat()

            # Check if all approvals are met
            if self.require_all:
                all_approved = all(a["status"] == "approved" for a in req["required_approvals"])
            else:
                all_approved = any(a["status"] == "approved" for a in req["required_approvals"])

            if all_approved:
                req["status"] = ChangeStatus.APPROVED.value
                log.info("Change request %s fully approved", request_id)

            return req

    def reject(self, request_id: str, reason: str = "", rejector_team: str = "manual") -> Optional[dict]:
        """Reject a change request.

        Any single rejection moves the request to REJECTED status.
        Returns the updated request or None if not found.
        """
        with self._lock:
            req = self.requests.get(request_id)
            if not req or req["status"] not in (ChangeStatus.PENDING.value, ChangeStatus.DETECTED.value):
                return req

            req["status"] = ChangeStatus.REJECTED.value
            req["rejection_reason"] = reason
            req["rejected_by"] = rejector_team
            req["rejected_at"] = datetime.now(timezone.utc).isoformat()
            log.info("Change request %s rejected by %s: %s", request_id, rejector_team, reason)
            return req

    def provision(self, request_id: str, pce) -> Optional[dict]:
        """Provision an approved change to the PCE (draft -> active).

        Only works on APPROVED requests.
        Returns the updated request or None if not found.
        """
        with self._lock:
            req = self.requests.get(request_id)
            if not req:
                return None
            if req["status"] != ChangeStatus.APPROVED.value:
                log.warning("Cannot provision %s — status is %s, not approved", request_id, req["status"])
                return req
            req["status"] = ChangeStatus.PROVISIONING.value

        # TODO: Implement actual provisioning
        # Steps:
        #   1. Call PCE provision API: POST /sec_policy (provision draft to active)
        #   2. Verify provisioning succeeded
        #   3. Update request status to PROVISIONED or FAILED

        try:
            log.info("Provisioning change request %s...", request_id)
            # TODO: pce.provision_policy_changes(change_description=req["change_summary"], ...)
            # Stub: mark as provisioned
            with self._lock:
                req["status"] = ChangeStatus.PROVISIONED.value
                req["provisioned"] = True
                req["provisioned_at"] = datetime.now(timezone.utc).isoformat()
                req["provision_result"] = "success"
            log.info("Change request %s provisioned successfully", request_id)
        except Exception as e:
            with self._lock:
                req["status"] = ChangeStatus.FAILED.value
                req["provision_result"] = str(e)
            log.exception("Failed to provision change request %s", request_id)

        return req

    def expire_stale(self):
        """Check for and expire requests that have exceeded the timeout."""
        now = datetime.now(timezone.utc)
        with self._lock:
            for req in self.requests.values():
                if req["status"] in (ChangeStatus.PENDING.value, ChangeStatus.DETECTED.value):
                    expires_at = datetime.fromisoformat(req["expires_at"].replace("Z", "+00:00"))
                    if now >= expires_at:
                        req["status"] = ChangeStatus.EXPIRED.value
                        log.info("Change request %s expired", req["id"])

    def _determine_approvers(self, scope: str, risk_level: RiskLevel) -> list:
        """Determine which teams need to approve based on scope and risk.

        Returns a list of approver dicts from the config.
        """
        approvers = []
        config_approvers = self.config.get("approvers", {})

        # Critical always escalates
        if risk_level == RiskLevel.CRITICAL:
            critical = config_approvers.get("critical", config_approvers.get("default", {}))
            approvers.append(critical)
            return approvers

        # Check scope-specific approvers
        scope_approvers = config_approvers.get("scopes", {})
        matched = False
        for scope_pattern, approver in scope_approvers.items():
            if self._scope_matches(scope, scope_pattern):
                approvers.append(approver)
                matched = True

        if not matched:
            approvers.append(config_approvers.get("default", {"team": "security-team"}))

        # Cross-scope always adds security review
        # TODO: Detect cross-scope from the change details
        cross_scope = config_approvers.get("cross_scope")
        if cross_scope:
            # Will be added when cross-scope detection is implemented
            pass

        return approvers

    @staticmethod
    def _scope_matches(scope: str, pattern: str) -> bool:
        """Check if a scope string matches a pattern.

        Simple substring match for now. Could be enhanced with
        proper label expression parsing.
        """
        # TODO: Implement proper label expression matching
        if not scope or not pattern:
            return False
        return pattern.lower() in scope.lower()


# ============================================================
# Approval Adapters
# ============================================================

class BaseAdapter:
    """Base class for approval system adapters."""

    name = "base"

    def send_approval_request(self, request: dict):
        """Send an approval request to the external system.

        Args:
            request: The change request dict to send for approval.
        """
        raise NotImplementedError

    def check_approval_status(self, request: dict) -> Optional[str]:
        """Poll the external system for approval status.

        Returns: "approved", "rejected", or None if still pending.
        """
        raise NotImplementedError


class WebhookAdapter(BaseAdapter):
    """Send approval requests via generic webhook POST.

    Expects callbacks at POST /api/approve/{id} or /api/reject/{id}.
    """

    name = "webhook"

    def __init__(self):
        self.webhook_url = os.environ.get("WEBHOOK_URL", "")
        self.callback_token = os.environ.get("WEBHOOK_CALLBACK_TOKEN", "")

    def send_approval_request(self, request: dict):
        """POST the change request to the configured webhook URL."""
        if not self.webhook_url:
            log.warning("WEBHOOK_URL not set, skipping webhook notification for %s", request["id"])
            return

        # TODO: Implement webhook POST
        # import requests as req_lib
        # payload = {
        #     "id": request["id"],
        #     "risk_level": request["risk_level"],
        #     "risk_reasons": request["risk_reasons"],
        #     "change_summary": request["change_summary"],
        #     "scope": request["scope"],
        #     "callback_approve": f"/api/approve/{request['id']}",
        #     "callback_reject": f"/api/reject/{request['id']}",
        # }
        # resp = req_lib.post(self.webhook_url, json=payload, timeout=10)
        # resp.raise_for_status()
        log.info("Webhook: would notify %s about %s", self.webhook_url, request["id"])

    def check_approval_status(self, request: dict) -> Optional[str]:
        """Webhook adapter relies on callbacks, not polling."""
        return None


class SlackAdapter(BaseAdapter):
    """Send approval requests to Slack channels with interactive buttons.

    Requires SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET.
    """

    name = "slack"

    def __init__(self):
        self.bot_token = os.environ.get("SLACK_BOT_TOKEN", "")
        self.signing_secret = os.environ.get("SLACK_SIGNING_SECRET", "")

    def send_approval_request(self, request: dict):
        """Post an interactive message to the Slack channel for the scope owner."""
        if not self.bot_token:
            log.warning("SLACK_BOT_TOKEN not set, skipping Slack notification for %s", request["id"])
            return

        # TODO: Implement Slack message posting
        # Use Slack Web API: chat.postMessage with Block Kit blocks
        # Include: risk badge, change summary, approve/reject buttons
        # Channel determined from request's required_approvals -> scope config -> slack_channel
        log.info("Slack: would post approval request %s", request["id"])

    def check_approval_status(self, request: dict) -> Optional[str]:
        """Slack adapter uses interactive callbacks, not polling."""
        return None


class ServiceNowAdapter(BaseAdapter):
    """Create Change Requests in ServiceNow via Table API.

    Requires SNOW_INSTANCE, SNOW_USER, SNOW_PASSWORD.
    """

    name = "servicenow"

    def __init__(self):
        self.instance = os.environ.get("SNOW_INSTANCE", "")
        self.user = os.environ.get("SNOW_USER", "")
        self.password = os.environ.get("SNOW_PASSWORD", "")

    def send_approval_request(self, request: dict):
        """Create a Change Request in ServiceNow."""
        if not self.instance:
            log.warning("SNOW_INSTANCE not set, skipping ServiceNow CR for %s", request["id"])
            return

        # TODO: Implement ServiceNow CR creation
        # POST https://{instance}.service-now.com/api/now/table/change_request
        # Fields: short_description, description, category, risk_level, assignment_group
        log.info("ServiceNow: would create CR for %s", request["id"])

    def check_approval_status(self, request: dict) -> Optional[str]:
        """Poll ServiceNow for CR status."""
        # TODO: Implement CR status polling
        # GET https://{instance}.service-now.com/api/now/table/change_request/{sys_id}
        # Check approval_status field
        return None


def create_adapter() -> BaseAdapter:
    """Create the appropriate adapter based on APPROVAL_ADAPTER env var."""
    adapter_name = os.environ.get("APPROVAL_ADAPTER", "webhook").lower()
    adapters = {
        "webhook": WebhookAdapter,
        "slack": SlackAdapter,
        "servicenow": ServiceNowAdapter,
    }
    cls = adapters.get(adapter_name, WebhookAdapter)
    log.info("Using approval adapter: %s", cls.name)
    return cls()


# ============================================================
# Dashboard HTML
# ============================================================

def render_dashboard(approval_mgr: ApprovalManager) -> str:
    """Render the main dashboard HTML with tabs for pending, activity, config."""

    all_requests = approval_mgr.list_all()
    pending = [r for r in all_requests if r["status"] in ("pending", "detected")]
    recent = sorted(all_requests, key=lambda r: r["created"], reverse=True)[:50]

    risk_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#22c55e",
        "info": "#6b7280",
    }

    status_colors = {
        "detected": "#93c5fd",
        "pending": "#eab308",
        "approved": "#22c55e",
        "rejected": "#ef4444",
        "expired": "#6b7280",
        "provisioning": "#93c5fd",
        "provisioned": "#22c55e",
        "failed": "#ef4444",
    }

    # Build pending approvals HTML
    pending_html = ""
    if not pending:
        pending_html = '<p style="color:#6b7280;text-align:center;padding:32px;">No pending approvals.</p>'
    for req in sorted(pending, key=lambda r: list(risk_colors.keys()).index(r.get("risk_level", "info"))):
        risk = req.get("risk_level", "info")
        rc = risk_colors.get(risk, "#6b7280")
        approvals_html = ""
        for a in req.get("required_approvals", []):
            icon = "&#10003;" if a["status"] == "approved" else "&#9203;"
            ac = "#22c55e" if a["status"] == "approved" else "#eab308"
            approvals_html += f'<span style="color:{ac};margin-right:12px;">{icon} {a["team"]} ({a["status"]})</span>'

        reasons_html = " ".join(
            f'<span style="background:#1e1e2e;padding:2px 8px;border-radius:4px;font-size:12px;">{r}</span>'
            for r in req.get("risk_reasons", [])
        )

        pending_html += f"""
        <div class="card" style="border-left:4px solid {rc};">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <span class="risk-badge" style="background:{rc}22;color:{rc};">{risk.upper()}</span>
                <code style="color:#6b7280;">{req['id']}</code>
            </div>
            <div style="font-size:15px;margin-bottom:8px;">{req.get('change_summary', '')}</div>
            <div style="font-size:13px;color:#9ca3af;margin-bottom:8px;">Scope: {req.get('scope', 'unknown')} | Type: {req.get('change_type', '')}</div>
            <div style="margin-bottom:8px;">{reasons_html}</div>
            <div style="font-size:13px;">{approvals_html}</div>
            <div style="margin-top:12px;display:flex;gap:8px;">
                <button onclick="apiAction('approve','{req['id']}')" class="btn btn-approve">Approve</button>
                <button onclick="apiAction('reject','{req['id']}')" class="btn btn-reject">Reject</button>
                <button onclick="apiAction('provision','{req['id']}')" class="btn btn-provision">Provision</button>
            </div>
        </div>"""

    # Build recent activity HTML
    activity_html = ""
    if not recent:
        activity_html = '<p style="color:#6b7280;text-align:center;padding:32px;">No recent activity.</p>'
    for req in recent:
        risk = req.get("risk_level", "info")
        rc = risk_colors.get(risk, "#6b7280")
        sc = status_colors.get(req.get("status", ""), "#6b7280")
        activity_html += f"""
        <div style="display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid #313244;">
            <span class="risk-badge" style="background:{rc}22;color:{rc};font-size:11px;">{risk.upper()}</span>
            <div style="flex:1;">
                <div style="font-size:14px;">{req.get('change_summary', '')}</div>
                <div style="font-size:12px;color:#6b7280;">{req.get('scope', '')} | {req.get('created', '')[:19]}</div>
            </div>
            <span style="background:{sc}22;color:{sc};padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;">{req.get('status', '').upper()}</span>
            <code style="font-size:11px;color:#6b7280;">{req['id']}</code>
        </div>"""

    # Build config HTML
    config = approval_mgr.config
    config_yaml = yaml.dump(config, default_flow_style=False) if config else "No configuration loaded."
    config_html = f'<pre style="background:#11111b;padding:16px;border-radius:8px;font-size:13px;overflow:auto;max-height:400px;">{config_yaml}</pre>'

    # Stats
    stats = {
        "total": len(all_requests),
        "pending": len(pending),
        "approved": sum(1 for r in all_requests if r["status"] == "approved"),
        "rejected": sum(1 for r in all_requests if r["status"] == "rejected"),
        "provisioned": sum(1 for r in all_requests if r["status"] == "provisioned"),
    }

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Policy Workflow</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#11111b; color:#cdd6f4; min-height:100vh; }}
        .header {{ background:#1e1e2e; border-bottom:1px solid #313244; padding:16px 32px; display:flex; align-items:center; justify-content:space-between; }}
        .header h1 {{ font-size:20px; font-weight:600; }}
        .container {{ max-width:960px; margin:0 auto; padding:24px 32px; }}
        .stats {{ display:flex; gap:16px; margin-bottom:24px; }}
        .stat {{ background:#1e1e2e; border-radius:8px; padding:16px; flex:1; text-align:center; border:1px solid #313244; }}
        .stat-value {{ font-size:28px; font-weight:700; }}
        .stat-label {{ font-size:12px; color:#6b7280; margin-top:4px; }}
        .tabs {{ display:flex; gap:4px; margin-bottom:24px; border-bottom:1px solid #313244; }}
        .tab {{ padding:10px 20px; cursor:pointer; color:#6b7280; border-bottom:2px solid transparent; font-size:14px; background:none; border-top:none; border-left:none; border-right:none; }}
        .tab.active {{ color:#cdd6f4; border-bottom-color:#93c5fd; }}
        .tab:hover {{ color:#cdd6f4; }}
        .tab-content {{ display:none; }}
        .tab-content.active {{ display:block; }}
        .card {{ background:#1e1e2e; border-radius:12px; padding:20px; margin-bottom:12px; border:1px solid #313244; }}
        .risk-badge {{ display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:700; }}
        code {{ background:#313244; padding:2px 6px; border-radius:4px; font-size:12px; }}
        .btn {{ padding:6px 16px; border-radius:6px; border:none; cursor:pointer; font-size:13px; font-weight:600; }}
        .btn-approve {{ background:#16a34a22; color:#22c55e; border:1px solid #22c55e44; }}
        .btn-approve:hover {{ background:#16a34a44; }}
        .btn-reject {{ background:#dc262622; color:#ef4444; border:1px solid #ef444444; }}
        .btn-reject:hover {{ background:#dc262644; }}
        .btn-provision {{ background:#2563eb22; color:#93c5fd; border:1px solid #93c5fd44; }}
        .btn-provision:hover {{ background:#2563eb44; }}
        .btn-scan {{ background:#7c3aed22; color:#a78bfa; border:1px solid #a78bfa44; }}
        .btn-scan:hover {{ background:#7c3aed44; }}
        pre {{ color:#9ca3af; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Policy Workflow</h1>
        <div style="display:flex;gap:8px;align-items:center;">
            <button onclick="triggerScan()" class="btn btn-scan">Scan Now</button>
            <span style="color:#6b7280;font-size:12px;">Auto-refreshes every 30s</span>
        </div>
    </div>

    <div class="container">
        <div class="stats">
            <div class="stat">
                <div class="stat-value" style="color:#eab308;">{stats['pending']}</div>
                <div class="stat-label">Pending</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color:#22c55e;">{stats['approved']}</div>
                <div class="stat-label">Approved</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color:#ef4444;">{stats['rejected']}</div>
                <div class="stat-label">Rejected</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color:#93c5fd;">{stats['provisioned']}</div>
                <div class="stat-label">Provisioned</div>
            </div>
            <div class="stat">
                <div class="stat-value">{stats['total']}</div>
                <div class="stat-label">Total</div>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="switchTab('pending')">Pending Approvals</button>
            <button class="tab" onclick="switchTab('activity')">Recent Activity</button>
            <button class="tab" onclick="switchTab('config')">Configuration</button>
        </div>

        <div id="tab-pending" class="tab-content active">
            {pending_html}
        </div>
        <div id="tab-activity" class="tab-content">
            {activity_html}
        </div>
        <div id="tab-config" class="tab-content">
            <div class="card">
                <h3 style="margin-bottom:12px;font-size:16px;">Approval Configuration</h3>
                {config_html}
            </div>
            <div class="card">
                <h3 style="margin-bottom:12px;font-size:16px;">Adapter Status</h3>
                <div style="font-size:14px;">
                    <strong>Active adapter:</strong> {os.environ.get('APPROVAL_ADAPTER', 'webhook')}<br>
                    <strong>Auto-provision:</strong> {os.environ.get('AUTO_PROVISION', 'false')}<br>
                    <strong>Auto-approve low/info:</strong> {os.environ.get('AUTO_APPROVE_LOW', 'true')}<br>
                    <strong>Scan interval:</strong> {os.environ.get('SCAN_INTERVAL', '300')}s<br>
                    <strong>Approval timeout:</strong> {int(os.environ.get('APPROVAL_TIMEOUT', '604800')) // 86400}d<br>
                </div>
            </div>
        </div>
    </div>

    <script>
        function switchTab(name) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + name).classList.add('active');
            event.target.classList.add('active');
        }}

        function apiAction(action, id) {{
            if (action === 'reject') {{
                const reason = prompt('Rejection reason:');
                if (reason === null) return;
                fetch('/api/reject/' + id, {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{reason: reason}})
                }}).then(() => location.reload());
            }} else {{
                fetch('/api/' + action + '/' + id, {{method: 'POST'}})
                    .then(() => location.reload());
            }}
        }}

        function triggerScan() {{
            fetch('/api/scan', {{method: 'POST'}}).then(r => r.json()).then(d => {{
                alert('Scan complete: ' + (d.changes_found || 0) + ' changes found');
                location.reload();
            }});
        }}

        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>"""


# ============================================================
# HTTP Server
# ============================================================

# Global references set in main()
_approval_mgr: Optional[ApprovalManager] = None
_change_detector: Optional[ChangeDetector] = None
_pce = None


class WorkflowHandler(BaseHTTPRequestHandler):
    """HTTP handler for the policy workflow dashboard and API."""

    def do_GET(self):
        if self.path == "/":
            self._send_dashboard()
        elif self.path == "/healthz":
            self._send_json(200, {"status": "healthy"})
        elif self.path == "/api/changes":
            requests = _approval_mgr.list_all() if _approval_mgr else []
            self._send_json(200, {"changes": requests, "total": len(requests)})
        elif self.path == "/api/pending":
            pending = _approval_mgr.list_pending() if _approval_mgr else []
            self._send_json(200, {"pending": pending, "total": len(pending)})
        elif self.path == "/api/config":
            config = _approval_mgr.config if _approval_mgr else {}
            self._send_json(200, config)
        elif self.path.startswith("/api/changes/"):
            req_id = self.path.split("/api/changes/")[-1]
            req = _approval_mgr.check_status(req_id) if _approval_mgr else None
            if req:
                self._send_json(200, req)
            else:
                self._send_json(404, {"error": "not found"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path.startswith("/api/approve/"):
            req_id = self.path.split("/api/approve/")[-1]
            body = self._read_body()
            team = body.get("team", "manual") if body else "manual"
            req = _approval_mgr.approve(req_id, approver_team=team) if _approval_mgr else None
            if req:
                # Auto-provision if configured and now approved
                if req["status"] == ChangeStatus.APPROVED.value and _approval_mgr and _approval_mgr.auto_provision:
                    _approval_mgr.provision(req_id, _pce)
                    req = _approval_mgr.check_status(req_id)
                self._send_json(200, req)
            else:
                self._send_json(404, {"error": "not found or not pending"})

        elif self.path.startswith("/api/reject/"):
            req_id = self.path.split("/api/reject/")[-1]
            body = self._read_body()
            reason = body.get("reason", "") if body else ""
            team = body.get("team", "manual") if body else "manual"
            req = _approval_mgr.reject(req_id, reason=reason, rejector_team=team) if _approval_mgr else None
            if req:
                self._send_json(200, req)
            else:
                self._send_json(404, {"error": "not found or not pending"})

        elif self.path.startswith("/api/provision/"):
            req_id = self.path.split("/api/provision/")[-1]
            req = _approval_mgr.provision(req_id, _pce) if _approval_mgr else None
            if req:
                self._send_json(200, req)
            else:
                self._send_json(404, {"error": "not found or not approved"})

        elif self.path == "/api/scan":
            changes_found = 0
            if _change_detector and _approval_mgr:
                try:
                    classifier = RiskClassifier()
                    changes = _change_detector.detect_draft_changes()
                    for change in changes:
                        risk_level, reasons = classifier.classify(change)
                        _approval_mgr.create_request(change, risk_level, reasons)
                    changes_found = len(changes)
                except Exception:
                    log.exception("Scan failed")
                    self._send_json(500, {"error": "scan failed"})
                    return
            self._send_json(200, {"status": "scan complete", "changes_found": changes_found})

        else:
            self._send_json(404, {"error": "not found"})

    def _send_dashboard(self):
        html = render_dashboard(_approval_mgr)
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> Optional[dict]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return None
        try:
            raw = self.rfile.read(content_length)
            return json.loads(raw)
        except Exception:
            return None

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging


# ============================================================
# Background Polling Loop
# ============================================================

def scan_loop(detector: ChangeDetector, approval_mgr: ApprovalManager):
    """Background thread: periodically scan for draft changes and expire stale requests."""
    interval = int(os.environ.get("SCAN_INTERVAL", "300"))
    classifier = RiskClassifier()
    log.info("Change detection loop started (interval=%ds)", interval)

    while True:
        try:
            # Detect changes
            changes = detector.detect_draft_changes()
            for change in changes:
                risk_level, reasons = classifier.classify(change)
                approval_mgr.create_request(change, risk_level, reasons)

            # Expire stale requests
            approval_mgr.expire_stale()

        except Exception:
            log.exception("Error in scan loop")

        time.sleep(interval)


# ============================================================
# Main Entry Point
# ============================================================

def main():
    global _approval_mgr, _change_detector, _pce

    log.info("Starting policy-workflow plugin...")

    # Load approval configuration
    config_path = os.environ.get("APPROVAL_CONFIG", "/data/approval-config.yaml")
    config = load_approval_config(config_path)
    log.info("Approval config loaded from %s", config_path)

    # Create adapter
    adapter = create_adapter()

    # Create approval manager
    _approval_mgr = ApprovalManager(config, adapter)

    # Create PCE client (may fail if PCE is not configured yet)
    try:
        _pce = get_pce()
        log.info("Connected to PCE: %s", _pce.base_url)
    except Exception:
        log.warning("PCE connection not configured — change detection disabled")
        _pce = None

    # Create change detector
    if _pce:
        _change_detector = ChangeDetector(_pce)
    else:
        _change_detector = None

    # Start background scan loop
    if _change_detector:
        scanner = threading.Thread(target=scan_loop, args=(_change_detector, _approval_mgr), daemon=True)
        scanner.start()
    else:
        log.info("Change detection disabled (no PCE connection)")

    # Start HTTP server
    port = int(os.environ.get("HTTP_PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), WorkflowHandler)
    log.info("Dashboard listening on http://0.0.0.0:%d", port)

    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server.serve_forever()
    log.info("Stopped.")


if __name__ == "__main__":
    main()
