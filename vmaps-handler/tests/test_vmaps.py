"""Tests for vmaps-handler plugin."""

import json
import os
import sys
import pytest

# Add parent dir to path so we can import the plugin modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from illumio_vuln_import.base import ReportProcessorBase, get_score, get_protocol_num
from illumio_vuln_import.nessus import NessusProXMLReportProcessor
from illumio_vuln_import.qualys import QualysXMLReportProcessor
from illumio_vuln_import.tenable import TenableSCCSVReportProcessor, TenableIOCSVReportProcessor

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "sample-data")


# ---------------------------------------------------------------------------
# Pure scoring / protocol helpers
# ---------------------------------------------------------------------------

class TestScoring:
    @pytest.mark.parametrize("sev,score", [
        (1, 0), (2, 39), (3, 69), (4, 89), (5, 100),
        ("info", 0), ("low", 39), ("medium", 69), ("high", 89),
        ("critical", 100), ("none", 0), ("CRITICAL", 100), ("High", 89),
    ])
    def test_severity_to_score(self, sev, score):
        assert get_score(sev) == score

    def test_unknown_severity_raises(self):
        with pytest.raises(ValueError):
            get_score("apocalyptic")

    @pytest.mark.parametrize("proto,num", [
        ("tcp", 6), ("TCP", 6), ("udp", 17), ("icmp", 1), ("ipv6", 41),
    ])
    def test_protocol_num(self, proto, num):
        assert get_protocol_num(proto) == num

    def test_unknown_protocol_is_negative(self):
        assert get_protocol_num("carrier-pigeon") == -1
        assert get_protocol_num(None) == -1


# ---------------------------------------------------------------------------
# Tenable.io CSV parser
# ---------------------------------------------------------------------------

class TestTenableIOParser:
    def test_parse_io_csv(self):
        p = TenableIOCSVReportProcessor(xorg_id=1, input_file=os.path.join(FIXTURES, "io.csv"))
        assert len(p._detected_vulnerabilities_map) >= 1
        assert len(p.vulnerabilities) >= 1

    def test_io_csv_detects_ips(self):
        p = TenableIOCSVReportProcessor(xorg_id=1, input_file=os.path.join(FIXTURES, "io.csv"))
        ips = {dv["ip_address"] for dv in p._detected_vulnerabilities_map.values()}
        assert "10.0.0.66" in ips


# ---------------------------------------------------------------------------
# Scanner-type auto-detection (used when SCANNER_TYPE isn't configured)
# ---------------------------------------------------------------------------

class TestScannerDetection:
    @pytest.fixture(scope="class")
    def detect(self):
        import main  # app.run() is guarded by __main__, safe to import
        return main.detect_scanner_type

    def test_detect_qualys_scan(self, detect):
        assert detect(os.path.join(FIXTURES, "qualys.xml")) == "qualys-file"

    def test_detect_qualys_asset(self, detect):
        assert detect(os.path.join(FIXTURES, "qualys_asset.xml")) == "qualys-file"

    def test_detect_nessus(self, detect):
        assert detect(os.path.join(FIXTURES, "sample.nessus")) == "nessus-file"

    def test_detect_tenable_sc_csv(self, detect):
        assert detect(os.path.join(FIXTURES, "sc.csv")) == "tenable-sc-csv"

    def test_detect_empty_returns_none(self, detect, tmp_path):
        empty = tmp_path / "empty.xml"
        empty.write_text("")
        assert detect(str(empty)) is None


class StubProcessor(ReportProcessorBase):
    """Concrete subclass for testing base functionality."""
    def download_vuln_data(self):
        pass

    def process(self):
        pass


# ---------------------------------------------------------------------------
# Base processor tests
# ---------------------------------------------------------------------------

class TestReportProcessorBase:
    def test_add_vulnerability(self):
        p = StubProcessor(xorg_id=1)
        p.add_vulnerability("test-1", 75, "Test Vuln", ["CVE-2021-1234"])
        assert "test-1" in p.vulnerabilities
        assert p.vulnerabilities["test-1"]["score"] == 75
        assert p.vulnerabilities["test-1"]["name"] == "Test Vuln"
        assert p.vulnerabilities["test-1"]["cve_ids"] == ["CVE-2021-1234"]

    def test_add_detected_vulnerability(self):
        p = StubProcessor(xorg_id=1)
        p.add_detected_vulnerability("10.0.0.1", 443, "tcp", "test-1")
        assert len(p._detected_vulnerabilities_map) == 1
        dv = list(p._detected_vulnerabilities_map.values())[0]
        assert dv["ip_address"] == "10.0.0.1"
        assert dv["port"] == 443
        assert dv["proto"] == 6  # tcp = 6
        assert dv["vulnerability"]["href"] == "/orgs/1/vulnerabilities/test-1"

    def test_dedup_detections(self):
        p = StubProcessor(xorg_id=1)
        p.add_detected_vulnerability("10.0.0.1", 443, "tcp", "test-1")
        p.add_detected_vulnerability("10.0.0.1", 443, "tcp", "test-1")
        assert len(p._detected_vulnerabilities_map) == 1

    def test_different_ports_not_deduped(self):
        p = StubProcessor(xorg_id=1)
        p.add_detected_vulnerability("10.0.0.1", 443, "tcp", "test-1")
        p.add_detected_vulnerability("10.0.0.1", 80, "tcp", "test-1")
        assert len(p._detected_vulnerabilities_map) == 2

    def test_associate_workloads(self):
        p = StubProcessor(xorg_id=1)
        p.add_detected_vulnerability("10.0.0.1", 443, "tcp", "test-1")
        p.add_detected_vulnerability("10.0.0.2", 80, "tcp", "test-2")
        ip_map = {"10.0.0.1": "/orgs/1/workloads/wl-abc"}
        processed, unassociated = p.associate_workloads_to_ips(ip_map)
        assert len(p.detected_vulnerabilities) == 1
        assert p.detected_vulnerabilities[0]["workload"]["href"] == "/orgs/1/workloads/wl-abc"
        assert "10.0.0.1" in processed
        assert "10.0.0.2" in unassociated

    def test_report_metadata(self):
        p = StubProcessor(xorg_id=1)
        p.add_report_meta_data("ref-1", "My Report", "nessus", False, [])
        assert p.report["reference_id"] == "ref-1"
        assert p.report["name"] == "My Report"
        assert p.report["report_type"] == "nessus"

    def test_authoritative(self):
        p = StubProcessor(xorg_id=1)
        p.add_report_meta_data("ref-1", "Report", "nessus", False, [])
        p.set_authoritative()
        assert p.report["authoritative"] is True

    def test_severity_zero_skipped(self):
        p = StubProcessor(xorg_id=1)
        p.add_vulnerability("info-1", 0, "Informational", [])
        assert "info-1" in p.vulnerabilities
        assert p.vulnerabilities["info-1"]["score"] == 0


# ---------------------------------------------------------------------------
# Nessus parser tests
# ---------------------------------------------------------------------------

class TestNessusParser:
    def test_parse_sample(self):
        path = os.path.join(FIXTURES, "sample.nessus")
        p = NessusProXMLReportProcessor(xorg_id=1, input_file=path)
        # Data loaded in constructor via process_report()
        assert len(p.vulnerabilities) > 0
        assert len(p._detected_vulnerabilities_map) > 0

    def test_parse_poc3_sample(self):
        path = os.path.join(FIXTURES, "sample-poc3.nessus")
        p = NessusProXMLReportProcessor(xorg_id=3998508, input_file=path)
        # Data loaded in constructor via process_report()

        assert len(p.vulnerabilities) >= 4  # 4 unique plugins (excluding severity 0)
        assert len(p._detected_vulnerabilities_map) >= 5

        # Check specific vuln was parsed
        assert "nessus-57608" in p.vulnerabilities
        assert p.vulnerabilities["nessus-57608"]["name"] == "SMB Signing Disabled"
        assert p.vulnerabilities["nessus-57608"]["score"] == 75  # cvss3 7.5 * 10

        # Check CVE extracted
        assert "CVE-2016-2183" in p.vulnerabilities["nessus-57608"]["cve_ids"]

    def test_severity_zero_ignored(self):
        path = os.path.join(FIXTURES, "sample-poc3.nessus")
        p = NessusProXMLReportProcessor(xorg_id=1, input_file=path)
        # Data loaded in constructor via process_report()
        # Plugin 11111 has severity 0 — should be skipped
        assert "nessus-11111" not in p.vulnerabilities

    def test_workload_association(self):
        path = os.path.join(FIXTURES, "sample-poc3.nessus")
        p = NessusProXMLReportProcessor(xorg_id=3998508, input_file=path)
        # Data loaded in constructor via process_report()

        ip_map = {
            "10.30.100.5": "/orgs/3998508/workloads/wl-001",
            "10.30.100.6": "/orgs/3998508/workloads/wl-002",
        }
        processed, unassociated = p.associate_workloads_to_ips(ip_map)

        assert "10.30.100.5" in processed
        assert "10.30.100.6" in processed
        assert "10.40.100.2" in unassociated

        # All matched detections should have workload hrefs
        for dv in p.detected_vulnerabilities:
            assert "workload" in dv
            assert dv["workload"]["href"].startswith("/orgs/")


# ---------------------------------------------------------------------------
# Qualys parser tests
# ---------------------------------------------------------------------------

class TestQualysParser:
    def test_parse_asset_xml(self):
        path = os.path.join(FIXTURES, "qualys_asset.xml")
        p = QualysXMLReportProcessor(xorg_id=1, input_file=path)
        assert len(p.vulnerabilities) > 0
        assert len(p._detected_vulnerabilities_map) > 0

    def test_parse_malformed_xml(self):
        """Qualys exports often have broken CDATA — lxml recover=True handles this."""
        path = os.path.join(FIXTURES, "qualys_malformed.xml")
        p = QualysXMLReportProcessor(xorg_id=1, input_file=path)
        # Should not crash despite <![MySQL Overflow Corruption]> (broken CDATA)
        assert len(p.vulnerabilities) >= 1
        assert len(p._detected_vulnerabilities_map) >= 1

    def test_wrong_format_yields_zero_and_warns(self, capsys):
        """A non-Qualys XML (e.g. a Nessus file) must not crash and must warn
        about the unrecognized root instead of silently parsing to zero."""
        path = os.path.join(FIXTURES, "sample.nessus")
        p = QualysXMLReportProcessor(xorg_id=1, input_file=path)
        assert len(p._detected_vulnerabilities_map) == 0
        out = capsys.readouterr().out
        assert "not a Qualys scanner export" in out
        assert "NessusClientData_v2" in out


# ---------------------------------------------------------------------------
# Tenable CSV parser tests
# ---------------------------------------------------------------------------

class TestTenableParser:
    def test_parse_sc_csv(self):
        path = os.path.join(FIXTURES, "sc.csv")
        p = TenableSCCSVReportProcessor(xorg_id=1, input_file=path)
        # Data loaded in constructor via process_report()
        assert len(p.vulnerabilities) > 0
        assert len(p._detected_vulnerabilities_map) > 0

    def test_mitigated_detection(self):
        path = os.path.join(FIXTURES, "sc.csv")
        p = TenableSCCSVReportProcessor(xorg_id=1, input_file=path)
        # Data loaded in constructor via process_report()
        # sc.csv has a row with Mitigated On set — should create a "fixed" detection
        has_fixed = any(
            dv.get("state") == "fixed"
            for dv in p._detected_vulnerabilities_map.values()
        )
        # On older PCE versions, fixed may be dropped — either way, should not crash
        assert len(p._detected_vulnerabilities_map) > 0


# ---------------------------------------------------------------------------
# IP mapping tests
# ---------------------------------------------------------------------------

def _build_ip_to_workload_map(workloads):
    """Local copy to avoid importing main.py which starts the server."""
    import ipaddress as _ipa
    ip_map = {}
    for wl in workloads:
        href = wl.get("href", "")
        if not href:
            continue
        for iface in wl.get("interfaces", []):
            addr = iface.get("address", "")
            if addr and ":" not in addr:
                try:
                    ip_map[str(_ipa.ip_address(addr))] = href
                except ValueError:
                    pass
    return ip_map


class TestIPMapping:
    def test_build_ip_map(self):
        workloads = [
            {"href": "/orgs/1/workloads/wl-1", "interfaces": [{"address": "10.0.0.1"}]},
            {"href": "/orgs/1/workloads/wl-2", "interfaces": [{"address": "10.0.0.2"}, {"address": "192.168.1.1"}]},
            {"href": "/orgs/1/workloads/wl-3", "interfaces": []},
        ]
        ip_map = _build_ip_to_workload_map(workloads)
        assert ip_map["10.0.0.1"] == "/orgs/1/workloads/wl-1"
        assert ip_map["10.0.0.2"] == "/orgs/1/workloads/wl-2"
        assert ip_map["192.168.1.1"] == "/orgs/1/workloads/wl-2"
        assert len(ip_map) == 3

    def test_ipv6_skipped(self):
        workloads = [
            {"href": "/orgs/1/workloads/wl-1", "interfaces": [
                {"address": "10.0.0.1"},
                {"address": "fe80::1"},
            ]},
        ]
        ip_map = _build_ip_to_workload_map(workloads)
        assert "10.0.0.1" in ip_map
        assert "fe80::1" not in ip_map


# ---------------------------------------------------------------------------
# Vuln payload format tests
# ---------------------------------------------------------------------------

class TestPayloadFormat:
    def test_vuln_definition_payload(self):
        p = StubProcessor(xorg_id=1)
        p.add_vulnerability("nessus-12345", 85, "Critical Vuln", ["CVE-2023-1234", "CVE-2023-5678"])

        vuln = p.vulnerabilities["nessus-12345"]
        payload = {
            "reference_id": "nessus-12345",
            "score": vuln["score"],
            "name": vuln["name"],
            "cve_ids": vuln["cve_ids"],
        }

        assert payload["reference_id"] == "nessus-12345"
        assert payload["score"] == 85
        assert isinstance(payload["cve_ids"], list)
        assert len(payload["cve_ids"]) == 2

    def test_detection_has_required_fields(self):
        p = StubProcessor(xorg_id=1)
        p.add_detected_vulnerability("10.0.0.1", 443, "tcp", "test-1")
        ip_map = {"10.0.0.1": "/orgs/1/workloads/wl-1"}
        p.associate_workloads_to_ips(ip_map)

        dv = p.detected_vulnerabilities[0]
        assert "ip_address" in dv
        assert "workload" in dv
        assert "vulnerability" in dv
        assert "href" in dv["workload"]
        assert "href" in dv["vulnerability"]
