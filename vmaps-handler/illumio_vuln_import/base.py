"""ReportProcessorBase — Python port of the illumio-cli vulnerability importer core.

Faithful port of lib/illumio/vulnerabilities/report_processor_base.rb
(illumio-cli 3.0.537), recovered from YARV bytecode. Subclasses implement
`process_report(input_file)` (file parsers) or `download_vuln_data()` (API
pullers) and call `add_vulnerability` / `add_detected_vulnerability`.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .pce_client import PCEClient

# severity (1-5 int or textual level) -> normalized 0-100 PCE score
SEVERITY_TO_SCORE_MAP: Dict[Any, int] = {
    1: 0, 2: 39, 3: 69, 4: 89, 5: 100,
    "info": 0, "low": 39, "medium": 69, "high": 89, "critical": 100, "none": 0,
}

ACTIVE = "active"
FIXED = "fixed"
STATE_MAP = {ACTIVE: ACTIVE, FIXED: FIXED}

VULNERABILITIES_REQ_BATCH_SIZE = 100_000
VULN_DEF_BATCH_SIZE = 1000

# IANA protocol numbers the PCE understands; -1 == unsupported (detection dropped)
_PROTOCOL_NUM = {
    "tcp": 6, "udp": 17, "icmp": 1, "igmp": 2, "ipv4": 4, "rdp": 27, "ipv6": 41,
}


def get_protocol_num(protocol: Optional[str]) -> int:
    if protocol is None:
        return -1
    return _PROTOCOL_NUM.get(str(protocol).lower(), -1)


def get_score(severity: Any) -> int:
    key = severity.lower() if hasattr(severity, "lower") else severity
    if key not in SEVERITY_TO_SCORE_MAP:
        raise ValueError(f"Unknown severity level found => {severity}")
    return SEVERITY_TO_SCORE_MAP[key]


def generate_unique_key(port: Any, proto: Any, ip_address: Any, vulnerability_id: Any) -> str:
    return f"{_s(port)}-{_s(proto)}-{_s(ip_address)}-{_s(vulnerability_id)}"


def _s(v: Any) -> str:
    return "" if v is None else str(v)


class ReportProcessorBase:
    def __init__(
        self,
        xorg_id: int,
        input_file: Optional[str] = None,
        debug: bool = False,
        pce_version: str = "24.2.0",
    ) -> None:
        self.xorg_id = int(xorg_id)
        self.debug = debug
        self.pce_version = pce_version

        self.report: Dict[str, Any] = {}
        self.vulnerabilities: Dict[str, Dict[str, Any]] = {}
        self.detected_vulnerabilities: List[Dict[str, Any]] = []
        self._detected_vulnerabilities_map: Dict[str, Dict[str, Any]] = {}

        self._processed_ips: set = set()
        self._ips_not_associated_with_workloads: set = set()
        self._scanned_ips: List[str] = []

        if input_file is not None:
            self.process_report(input_file)
        else:
            self.download_vuln_data()

    # -- abstract hooks ----------------------------------------------------

    def process_report(self, input_file: str) -> None:
        raise NotImplementedError(f"{type(self).__name__}.process_report is abstract")

    def download_vuln_data(self) -> None:
        raise NotImplementedError(f"{type(self).__name__}.download_vuln_data is abstract")

    # -- helpers -----------------------------------------------------------

    def debug_puts(self, msg: str) -> None:
        if self.debug:
            print(msg)

    @property
    def _pce_major(self) -> int:
        return int(str(self.pce_version).split(".")[0])

    @property
    def _supports_incremental_upload(self) -> bool:
        # PCE >= 20.2 supports incremental upload (and thus the `state` field).
        return _ver_float(self.pce_version) >= 20.2

    # -- collection API (called by subclasses) -----------------------------

    def add_vulnerability(self, vuln_id: str, score: int, name: str, cve_ids: List[str]) -> None:
        # first writer wins (matches Ruby ||=)
        self.vulnerabilities.setdefault(
            vuln_id, {"score": score, "name": name, "cve_ids": cve_ids}
        )

    def add_detected_vulnerability(
        self,
        ip_address: str,
        port: Any,
        protocol: Optional[str],
        vuln_id: str,
        external_data_reference: Any = None,
        state: Optional[str] = None,
    ) -> None:
        version_not_support_incremental = not self._supports_incremental_upload

        # On PCE < 20.2 "fixed" detections can't be expressed; drop them.
        if version_not_support_incremental and state and STATE_MAP.get(state.lower()) == FIXED:
            return

        dv: Dict[str, Any] = {"ip_address": ip_address}

        if port not in (None, ""):
            dv["port"] = int(port)

        if protocol:
            parsed_protocol = get_protocol_num(protocol)
            if parsed_protocol == -1:
                print(
                    f"Row with ip address {ip_address}, port {port}, protocol {protocol} "
                    "is ignored since protocol is unsupported"
                )
            else:
                dv["proto"] = parsed_protocol

        dv["vulnerability"] = {"href": f"/orgs/{self.xorg_id}/vulnerabilities/{vuln_id}"}

        if external_data_reference is not None:
            dv["external_data_reference"] = json.dumps(external_data_reference)

        if state and not version_not_support_incremental:
            dv["state"] = STATE_MAP.get(state.lower())

        key = generate_unique_key(dv.get("port"), dv.get("proto"), dv["ip_address"], vuln_id)
        existing = self._detected_vulnerabilities_map.get(key)
        if existing is not None:
            # active supersedes fixed; otherwise keep the first seen
            if dv.get("state") != FIXED and existing.get("state") == FIXED:
                print(
                    "resolving conflict detected vulnerabilities, drop detected vulnerability: "
                    f"{existing} and keep detected vulnerability: {dv}"
                )
                self._detected_vulnerabilities_map[key] = dv
        else:
            self._detected_vulnerabilities_map[key] = dv

    def add_report_meta_data(
        self,
        reference_id: str,
        name: str,
        report_type: str,
        authoritative: bool,
        scanned_ips: List[str],
    ) -> None:
        self.report.update(
            reference_id=reference_id,
            name=name,
            report_type=report_type,
            authoritative=authoritative,
            scanned_ips=scanned_ips,
        )

    def set_authoritative(self) -> None:
        self.report["authoritative"] = True

    # -- workload association ---------------------------------------------

    def associate_workloads_to_ips(self, ip_to_workload_hrefs: Dict[str, str]):
        """Attach workload hrefs; keep only detections that map to a workload."""
        self._processed_ips = set()
        self._ips_not_associated_with_workloads = set()

        self.debug_puts(f"Total detected_vulnerabilities : {len(self._detected_vulnerabilities_map)}")

        with_workload: List[Dict[str, Any]] = []
        for dv in self._detected_vulnerabilities_map.values():
            ip_address = dv["ip_address"]
            parsed_ip = _normalize_ip(ip_address)
            if parsed_ip in ip_to_workload_hrefs:
                dv["workload"] = {"href": ip_to_workload_hrefs[parsed_ip]}
                with_workload.append(dv)
                self._processed_ips.add(ip_address)
            else:
                self._ips_not_associated_with_workloads.add(ip_address)
        self.detected_vulnerabilities = with_workload

        self.debug_puts(f"   Number of ips belong to workloads   => {len(self._processed_ips)}")
        self.debug_puts(f"   Number of ips not part of workloads => {len(self._ips_not_associated_with_workloads)}")
        return self._processed_ips, self._ips_not_associated_with_workloads

    # -- import to PCE -----------------------------------------------------

    def import_vulnerabilities(self, pce: PCEClient) -> None:
        self.debug_puts(f"PCE Version detection to import vulnerabilities : {self.pce_version}")
        if self._pce_major < 19:
            self._import_vulnerabilities_pre_19_1(pce)
            return

        items = list(self.vulnerabilities.items())
        imported = 0
        for start in range(0, len(items), VULN_DEF_BATCH_SIZE):
            batch = items[start:start + VULN_DEF_BATCH_SIZE]
            vulns = []
            for reference_id, vuln in batch:
                v = dict(vuln)
                v["reference_id"] = reference_id
                vulns.append(v)
            if not vulns:
                continue
            pce.create_vulnerabilities(vulns)
            imported += len(batch)
            print(f"Imported Vulnerabilities : {imported}/{len(self.vulnerabilities)}")
        self.debug_puts(f"Total vulnerabilities imported/updated : {len(self.vulnerabilities)}")

    def _import_vulnerabilities_pre_19_1(self, pce: PCEClient) -> None:
        for reference_id, vuln in self.vulnerabilities.items():
            pce.update_vulnerability(reference_id, vuln)
        self.debug_puts(f"Total vulnerabilities imported/updated : {len(self.vulnerabilities)}")

    def import_report(self, pce: PCEClient, format: Optional[str] = None) -> None:
        reference_id = self.report.pop("reference_id", None)
        self._scanned_ips = self.report.pop("scanned_ips", []) or []
        remaining = list(set(self._scanned_ips) - self._processed_ips)
        authoritative = bool(self.report.get("authoritative"))

        imported = 0
        batch_num = 0
        for start in range(0, len(self.detected_vulnerabilities), VULNERABILITIES_REQ_BATCH_SIZE):
            dv_batch = self.detected_vulnerabilities[start:start + VULNERABILITIES_REQ_BATCH_SIZE]
            self.report["detected_vulnerabilities"] = dv_batch
            if authoritative:
                scanned = list({dv["ip_address"] for dv in dv_batch})
                take = VULNERABILITIES_REQ_BATCH_SIZE - len(scanned)
                if take > 0:
                    scanned += remaining[:take]
                    remaining = remaining[take:]
                self.report["scanned_ips"] = scanned
            else:
                self.report["scanned_ips"] = []

            pce.update_vulnerability_report(reference_id, self.report)
            batch_num += 1
            imported += len(dv_batch)
            print(
                f"Batch Num: {batch_num}; Imported Detected Vulnerabilities : "
                f"{imported}/{len(self.detected_vulnerabilities)}"
            )

        # authoritative reports also flush scanned IPs that had no detections
        if authoritative and remaining:
            for start in range(0, len(remaining), VULNERABILITIES_REQ_BATCH_SIZE):
                self.report["detected_vulnerabilities"] = []
                self.report["scanned_ips"] = remaining[start:start + VULNERABILITIES_REQ_BATCH_SIZE]
                pce.update_vulnerability_report(reference_id, self.report)

        if format == "api":
            self.report["detected_vulnerabilities"] = []
            self.report["scanned_ips"] = []
            self.report["exported_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            pce.update_vulnerability_report(reference_id, self.report)

    # -- orchestration -----------------------------------------------------

    def run_import(self, pce: PCEClient, format: Optional[str] = None) -> None:
        """End-to-end: associate workloads, push vuln defs, then the report."""
        ip_map = pce.build_ip_to_workload_href()
        self.associate_workloads_to_ips(ip_map)
        self.import_vulnerabilities(pce)
        self.import_report(pce, format=format)
        self.display_final_status()

    def display_final_status(self) -> None:
        print("Summary:")
        print("Processed the report with the following details : ")
        print("Report meta data => ")
        print(f"  Name          : {self.report.get('name')}")
        print(f"  Report Type   : {self.report.get('report_type')}")
        print(f"  Authoritative : {self.report.get('authoritative')}")
        if len(self._scanned_ips) < 100:
            print(f"  Scanned IPs   : {self._scanned_ips}")
        else:
            print(f"  Total Scanned IPs   : {len(self._scanned_ips)}")
        print("Stats : ")
        print(f"   Number of vulnerabilities           => {len(self.vulnerabilities)} ")
        print(f"   Number of detected vulnerabilities (active and fixed)  => {len(self.detected_vulnerabilities)} ")


def _ver_float(ver: str) -> float:
    parts = str(ver).split(".")
    try:
        return float(f"{parts[0]}.{parts[1]}") if len(parts) >= 2 else float(parts[0])
    except (ValueError, IndexError):
        return 0.0


def _normalize_ip(addr: str) -> str:
    try:
        return str(ipaddress.ip_address(str(addr).strip()))
    except ValueError:
        return str(addr).strip()
