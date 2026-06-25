"""End-to-end import orchestration tests for vmaps-handler.

These exercise run_import() with a fake PCE client so the full pipeline
(parse -> upload vuln defs -> fetch workloads -> match IPs -> upload report)
is covered without a live PCE. This is where the real-world bugs lived
(reference_id in body, silent zero-detection, IP mismatch), so it gets the
most coverage.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main  # app.run() is guarded by __main__, safe to import

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "sample-data")

# IPs present in sample-data/qualys.xml (the canonical Qualys scan export).
QUALYS_SCAN_IPS = [
    "10.0.0.66", "10.0.0.67", "10.0.0.68", "10.0.0.69", "10.0.0.70",
    "10.0.0.71", "10.0.0.72", "10.0.0.73", "10.0.0.74", "10.0.0.75",
    "10.0.0.76", "10.0.0.77", "10.0.0.78", "10.0.0.79", "10.0.1.27",
]


class FakePCEClient:
    """Records calls and returns canned responses, mimicking VulnPCEClient."""

    def __init__(self, org_id=1, workloads=None, vuln_status=201, report_status=204):
        self.org_id = org_id
        self._workloads = workloads if workloads is not None else []
        self.vuln_status = vuln_status
        self.report_status = report_status
        self.posted_vulns = []          # list of batches
        self.put_reports = []           # list of (reference_id, body)
        self.get_workloads_calls = 0

    def post_vulnerabilities(self, vulns):
        self.posted_vulns.append(vulns)
        return self.vuln_status, "ok"

    def put_report(self, reference_id, report_body):
        self.put_reports.append((reference_id, report_body))
        if self.report_status in (200, 201, 204):
            return self.report_status, "ok"
        return self.report_status, "schema validation error"

    def get_workloads(self):
        self.get_workloads_calls += 1
        return self._workloads


def workloads_for(ips, org=1):
    """Build PCE-style workload dicts mapping each IP to a workload href."""
    return [
        {"href": f"/orgs/{org}/workloads/wl-{i}", "interfaces": [{"address": ip}]}
        for i, ip in enumerate(ips)
    ]


def qualys_path():
    return os.path.join(FIXTURES, "qualys.xml")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestImportSuccess:
    def test_full_import_all_matched(self):
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS))
        result = main.run_import(client, "qualys-file", qualys_path())

        assert result["status"] == "success"
        assert result["error"] is None
        assert result["vulns_defined"] == 32
        assert result["detections_total"] == 129
        assert result["detections_matched"] == 129
        assert result["detections_dropped"] == 0
        assert result.get("warning") is None

    def test_vuln_defs_uploaded(self):
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS))
        main.run_import(client, "qualys-file", qualys_path())
        assert len(client.posted_vulns) == 1          # one batch (<1000)
        assert len(client.posted_vulns[0]) == 32
        # payload shape
        v = client.posted_vulns[0][0]
        assert {"reference_id", "score", "name", "cve_ids"} <= set(v)

    def test_report_uploaded_once(self):
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS))
        main.run_import(client, "qualys-file", qualys_path())
        assert len(client.put_reports) == 1
        ref, body = client.put_reports[0]
        assert len(body["detected_vulnerabilities"]) == 129
        assert len(body["scanned_ips"]) >= 1

    def test_reference_id_stripped_from_body(self):
        """Regression: the PCE rejects reference_id inside the PUT body (HTTP 406)."""
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS))
        main.run_import(client, "qualys-file", qualys_path())
        _, body = client.put_reports[0]
        assert "reference_id" not in body


# ---------------------------------------------------------------------------
# Partial / no matches
# ---------------------------------------------------------------------------

class TestImportMatching:
    def test_no_overlapping_ips_drops_all(self):
        # Workloads on a different subnet than the scan.
        client = FakePCEClient(workloads=workloads_for(["192.168.1.1", "192.168.1.2"]))
        result = main.run_import(client, "qualys-file", qualys_path())
        assert result["detections_total"] == 129
        assert result["detections_matched"] == 0
        assert result["detections_dropped"] == 129
        assert len(client.put_reports) == 0          # nothing to upload
        assert result["status"] == "success"

    def test_partial_match(self):
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS[:3]))
        result = main.run_import(client, "qualys-file", qualys_path())
        assert 0 < result["detections_matched"] < 129
        assert result["detections_dropped"] == 129 - result["detections_matched"]
        assert len(client.put_reports) == 1

    def test_no_workloads_at_all(self):
        client = FakePCEClient(workloads=[])
        result = main.run_import(client, "qualys-file", qualys_path())
        assert result["detections_matched"] == 0
        assert len(client.put_reports) == 0
        assert result["status"] == "success"


# ---------------------------------------------------------------------------
# Zero-detection / bad input (Jeff's failure modes)
# ---------------------------------------------------------------------------

class TestImportZeroDetections:
    def test_wrong_format_file_warns_no_upload(self):
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS))
        # Feed a Nessus file to the qualys scanner.
        result = main.run_import(client, "qualys-file", os.path.join(FIXTURES, "sample.nessus"))
        assert result["detections_total"] == 0
        assert result.get("warning")
        assert "0 detections" in result["warning"]
        assert len(client.put_reports) == 0
        assert result["status"] == "success"

    def test_missing_file_errors_or_warns(self):
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS))
        result = main.run_import(client, "qualys-file", os.path.join(FIXTURES, "does-not-exist.xml"))
        assert result["detections_total"] == 0
        assert len(client.put_reports) == 0


# ---------------------------------------------------------------------------
# Upload failures
# ---------------------------------------------------------------------------

class TestImportUploadFailures:
    def test_report_http_406_sets_error(self):
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS), report_status=406)
        result = main.run_import(client, "qualys-file", qualys_path())
        assert result["status"] == "error"
        assert result["error"]
        assert "406" in result["error"]

    def test_report_http_200_ok(self):
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS), report_status=200)
        result = main.run_import(client, "qualys-file", qualys_path())
        assert result["status"] == "success"

    def test_unknown_scanner_type_errors(self):
        client = FakePCEClient(workloads=workloads_for(QUALYS_SCAN_IPS))
        result = main.run_import(client, "bogus-scanner", qualys_path())
        assert result["status"] == "error"
        assert result["error"]


# ---------------------------------------------------------------------------
# Latest-file selection
# ---------------------------------------------------------------------------

class TestLatestImportFile:
    def test_prefers_matching_extension(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "IMPORT_DIR", str(tmp_path))
        (tmp_path / "a.nessus").write_text("x")
        (tmp_path / "b.xml").write_text("y")
        # qualys-file prefers .xml even though .nessus may sort/mtime differently
        assert main._latest_import_file("qualys-file").endswith("b.xml")
        assert main._latest_import_file("nessus-file").endswith("a.nessus")

    def test_empty_dir_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "IMPORT_DIR", str(tmp_path))
        assert main._latest_import_file("qualys-file") is None

    def test_missing_dir_returns_none(self, monkeypatch):
        monkeypatch.setattr(main, "IMPORT_DIR", "/no/such/dir")
        assert main._latest_import_file() is None

    def test_falls_back_to_any_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "IMPORT_DIR", str(tmp_path))
        (tmp_path / "only.csv").write_text("x")
        # qualys-file prefers .xml; none present -> fall back to the csv
        assert main._latest_import_file("qualys-file").endswith("only.csv")


# ---------------------------------------------------------------------------
# Scanner-type detection — extra cases beyond test_vmaps.py
# ---------------------------------------------------------------------------

class TestDetectExtra:
    def test_tenable_io_csv(self, tmp_path):
        f = tmp_path / "io.csv"
        f.write_text("Plugin ID,Name,IP Address,Port,Protocol,Risk,CVSS Base Score,CVSS3 Base Score,CVE,Vulnerability State\n")
        assert main.detect_scanner_type(str(f)) == "tenable-io-csv"

    def test_tenable_sc_csv(self, tmp_path):
        f = tmp_path / "sc.csv"
        f.write_text("Plugin,Plugin Name,IP Address,Port,Protocol,Severity,CVSS V2 Base Score,CVSS V3 Base Score,CVE\n")
        assert main.detect_scanner_type(str(f)) == "tenable-sc-csv"

    def test_unknown_xml_root_uses_ext_fallback(self, tmp_path):
        f = tmp_path / "weird.xml"
        f.write_text('<?xml version="1.0"?><SomethingElse><x/></SomethingElse>')
        # Unknown root, but .xml extension -> qualys-file (parser will then warn)
        assert main.detect_scanner_type(str(f)) == "qualys-file"

    def test_unknown_no_ext_returns_none(self, tmp_path):
        f = tmp_path / "mystery"
        f.write_text("just some text\n")
        assert main.detect_scanner_type(str(f)) is None

    def test_nonexistent_returns_none(self):
        assert main.detect_scanner_type("/no/such/file.xml") is None

    def test_bom_prefixed_xml(self, tmp_path):
        f = tmp_path / "bom.xml"
        f.write_bytes(b"\xef\xbb\xbf<?xml version='1.0'?><SCAN><IP value='1.1.1.1'/></SCAN>")
        assert main.detect_scanner_type(str(f)) == "qualys-file"


# ---------------------------------------------------------------------------
# IP map building — extra cases
# ---------------------------------------------------------------------------

class FakeRequest:
    def __init__(self, json=None, query=None, body=b""):
        self.json = json or {}
        self.query = query or {}
        self.body = body


@pytest.fixture
def pce_env(monkeypatch):
    for k, v in {
        "PCE_HOST": "pce.example.com", "PCE_PORT": "443", "PCE_ORG_ID": "1",
        "PCE_API_KEY": "api_x", "PCE_API_SECRET": "secret_x",
    }.items():
        monkeypatch.setenv(k, v)
    # never touch the real PCE or persist state during handler tests
    monkeypatch.setattr(main, "VulnPCEClient", lambda **kw: type("C", (), {"org_id": 1})())
    monkeypatch.setattr(main.app, "update_state", lambda *a, **k: None)


class TestImportHandler:
    """POST /api/import — the entry point Jeff hit with no SCANNER_TYPE set."""

    def test_autodetect_when_no_scanner_type(self, tmp_path, monkeypatch, pce_env):
        # A qualys file sitting in the imports dir, no SCANNER_TYPE configured.
        import shutil
        shutil.copy(qualys_path(), tmp_path / "scan.xml")
        monkeypatch.setattr(main, "IMPORT_DIR", str(tmp_path))
        monkeypatch.setattr(main, "SCANNER_TYPE", "")
        monkeypatch.setattr(main, "IMPORT_FILE", "")

        captured = {}
        monkeypatch.setattr(main, "run_import",
                            lambda client, st, f: captured.update(scanner_type=st, file=f) or {"status": "success"})

        result = main.trigger_import(FakeRequest(json={}))
        assert captured["scanner_type"] == "qualys-file"   # auto-detected
        assert captured["file"].endswith("scan.xml")
        assert result["status"] == "success"

    def test_helpful_error_when_undetectable(self, tmp_path, monkeypatch, pce_env):
        monkeypatch.setattr(main, "IMPORT_DIR", str(tmp_path))   # empty dir
        monkeypatch.setattr(main, "SCANNER_TYPE", "")
        monkeypatch.setattr(main, "IMPORT_FILE", "")
        out = main.trigger_import(FakeRequest(json={}))
        # handlers return (body, status) on error
        body, status = out if isinstance(out, tuple) else (out, 200)
        assert status == 400
        assert "scanner type" in body["error"].lower()

    def test_explicit_scanner_type_respected(self, tmp_path, monkeypatch, pce_env):
        monkeypatch.setattr(main, "IMPORT_DIR", str(tmp_path))
        monkeypatch.setattr(main, "SCANNER_TYPE", "")
        captured = {}
        monkeypatch.setattr(main, "run_import",
                            lambda client, st, f: captured.update(st=st) or {"status": "success"})
        main.trigger_import(FakeRequest(json={"scanner_type": "nessus-file", "import_file": "/data/imports/x.nessus"}))
        assert captured["st"] == "nessus-file"


class TestUploadHandler:
    """POST /api/upload — returns the detected type so the UI can use it."""

    def test_upload_reports_detected_type(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "IMPORT_DIR", str(tmp_path))
        with open(qualys_path(), "rb") as fh:
            body = fh.read()
        result = main.upload_file(FakeRequest(query={"filename": "scan.xml"}, body=body))
        assert result["detected_scanner_type"] == "qualys-file"
        assert result["size"] == len(body)
        assert os.path.exists(os.path.join(str(tmp_path), "scan.xml"))

    def test_upload_strips_path_traversal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "IMPORT_DIR", str(tmp_path))
        main.upload_file(FakeRequest(query={"filename": "../../etc/evil"}, body=b"x"))
        # written inside IMPORT_DIR as basename, not outside it
        assert os.path.exists(os.path.join(str(tmp_path), "evil"))


class TestIPMap:
    def test_multi_interface(self):
        wls = [{"href": "/x", "interfaces": [{"address": "10.0.0.1"}, {"address": "10.0.0.2"}]}]
        m = main.build_ip_to_workload_map(wls)
        assert m == {"10.0.0.1": "/x", "10.0.0.2": "/x"}

    def test_public_ip_mapped(self):
        wls = [{"href": "/x", "interfaces": [{"address": "10.0.0.1", "public_ip": "1.2.3.4"}]}]
        m = main.build_ip_to_workload_map(wls)
        assert m["1.2.3.4"] == "/x"

    def test_ipv6_skipped(self):
        wls = [{"href": "/x", "interfaces": [{"address": "fe80::1"}, {"address": "10.0.0.1"}]}]
        m = main.build_ip_to_workload_map(wls)
        assert m == {"10.0.0.1": "/x"}

    def test_workload_without_href_skipped(self):
        wls = [{"interfaces": [{"address": "10.0.0.1"}]}]
        assert main.build_ip_to_workload_map(wls) == {}

    def test_malformed_address_skipped(self):
        wls = [{"href": "/x", "interfaces": [{"address": "not-an-ip"}, {"address": "10.0.0.1"}]}]
        assert main.build_ip_to_workload_map(wls) == {"10.0.0.1": "/x"}
