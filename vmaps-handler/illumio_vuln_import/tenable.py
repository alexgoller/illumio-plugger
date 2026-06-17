"""Tenable CSV report processors (port of the Tenable CSV processor family).

  * TenableSCCSVReportProcessor  - Tenable.sc (SecurityCenter) CSV export
  * TenableIOCSVReportProcessor  - Tenable.io CSV export

Both normalize their native columns to the generic detected-vulnerability
records. The live REST pullers (Tenable.sc /rest/analysis, Tenable.io async
/vulns/export) are documented in docs/illumio-vulnerability-import-api.md.

Note: Tenable plugin IDs are Nessus plugin IDs, so vuln ids are `nessus-<id>`,
matching the original tool (so Nessus-file and Tenable imports share vuln defs).
"""

from __future__ import annotations

import csv
import json
import os
import time
from typing import Dict, Iterator, List, Optional

from .base import ACTIVE, FIXED, ReportProcessorBase, get_score
from .scanner_http import ScannerAPIError, make_session, resolve

# generic normalized column set both Tenable processors map into
_GENERIC_HEADERS = {
    "plugin_id": "Plugin",
    "plugin_name": "Plugin Name",
    "ip_address": "IP Address",
    "port": "Port",
    "protocol": "Protocol",
    "severity": "Severity",
    "base_score": "CVSS V2 Base Score",
    "cvssv3_base_score": "CVSS V3 Base Score",
    "cve": "CVE",
    "state": "State",
}


class _TenableCSVBase(ReportProcessorBase):
    # subclasses set these
    HEADERS: Dict[str, str] = {}
    REQUIRED_COLUMNS: List[str] = []
    REPORT_TYPE = "tenable"
    DEFAULT_REPORT_NAME: Optional[str] = None
    DEFAULT_REFERENCE_ID: Optional[str] = None

    def __init__(self, xorg_id, input_file=None, debug=False, pce_version="24.2.0"):
        self._report_name = self.DEFAULT_REPORT_NAME
        self._reference_id = self.DEFAULT_REFERENCE_ID
        super().__init__(xorg_id, input_file, debug, pce_version)

    def process_report(self, input_file: str) -> None:
        self.debug_puts(f"Input File: {input_file}")
        ilowd = os.environ.get("ILOWD")
        if ilowd and not os.path.isfile(input_file):
            input_file = f"{ilowd}/{input_file}"
        if not os.path.isfile(input_file):
            raise ValueError("Invalid file path.")

        with open(input_file, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            headers = set(reader.fieldnames or [])
            for col in self.REQUIRED_COLUMNS:
                if col not in headers:
                    print(
                        "Invalid file. It is missing some required columns. "
                        f"Required Cols: {self.REQUIRED_COLUMNS}"
                    )
                    raise SystemExit(1)

            scanned_ips = set()
            for row in reader:
                ip_address = row.get(self.HEADERS["ip_address"])
                scanned_ips.add(ip_address)
                self._process_vuln_data(row)

        self.debug_puts(f"Total ips processed: {len(scanned_ips)}")
        report_name = self._report_name or os.path.splitext(os.path.basename(input_file))[0]
        reference_id = self._reference_id or f"{self.REPORT_TYPE}-{''.join(report_name.split())}"
        self.add_report_meta_data(reference_id, report_name, self.REPORT_TYPE, False, list(scanned_ips))

    # subclasses implement state derivation
    def _row_state(self, row: dict) -> Optional[str]:
        raise NotImplementedError

    def _process_vuln_data(self, row: dict) -> None:
        self._emit(
            plugin_id=row.get(self.HEADERS["plugin_id"]),
            plugin_name=row.get(self.HEADERS["plugin_name"]),
            ip=row.get(self.HEADERS["ip_address"]),
            port=row.get(self.HEADERS["port"]),
            protocol=row.get(self.HEADERS["protocol"]),
            severity=row.get(self.HEADERS["severity"]),
            cvss_v2=row.get(self.HEADERS["base_score"]),
            cvss_v3=row.get(self.HEADERS["cvssv3_base_score"]),
            cve=row.get(self.HEADERS["cve"]),
            state=self._row_state(row),
        )

    def _emit(self, *, plugin_id, plugin_name, ip, port, protocol, severity,
              cvss_v2, cvss_v3, cve, state) -> None:
        """Shared scoring + record emission (Tenable plugin == Nessus plugin)."""
        if get_score(severity) == 0:
            return

        vuln_id = f"nessus-{plugin_id}"

        if isinstance(cve, (list, tuple)):
            cve_ids = [c for c in cve if c]
        else:
            cve_ids = cve.split(",") if cve else []

        cvss3 = (str(cvss_v3) if cvss_v3 is not None else "").strip()
        cvss2 = (str(cvss_v2) if cvss_v2 is not None else "").strip()
        if cvss3:
            score = int(float(cvss3) * 10)
        elif cvss2:
            score = int(float(cvss2) * 10)
        else:
            score = get_score(severity)

        self.add_vulnerability(vuln_id, score, plugin_name, cve_ids)
        self.add_detected_vulnerability(ip, port, protocol, vuln_id, state=state)


class TenableSCCSVReportProcessor(_TenableCSVBase):
    REPORT_TYPE = "tenable-sc"
    HEADERS = {
        "plugin_id": "Plugin",
        "plugin_name": "Plugin Name",
        "ip_address": "IP Address",
        "port": "Port",
        "protocol": "Protocol",
        "severity": "Severity",
        "base_score": "CVSS V2 Base Score",
        "cvssv3_base_score": "CVSS V3 Base Score",
        "cve": "CVE",
        "mitigated_on": "Mitigated On",
    }
    REQUIRED_COLUMNS = [
        "Plugin", "Plugin Name", "IP Address", "Port", "Protocol",
        "Severity", "CVSS V2 Base Score", "CVSS V3 Base Score", "CVE",
    ]

    def __init__(self, xorg_id, input_file=None, debug=False, pce_version="24.2.0", mitigated=False):
        self.mitigated = mitigated
        if mitigated:
            self.REQUIRED_COLUMNS = self.REQUIRED_COLUMNS + ["Mitigated On"]
        super().__init__(xorg_id, input_file, debug, pce_version)

    def _row_state(self, row: dict) -> str:
        explicit = row.get("State")
        if explicit:
            return explicit
        mitigated_on = (row.get(self.HEADERS["mitigated_on"]) or "").strip()
        return ACTIVE if mitigated_on == "" else FIXED


class TenableIOCSVReportProcessor(_TenableCSVBase):
    REPORT_TYPE = "tenable-io"
    HEADERS = {
        "plugin_id": "Plugin ID",
        "plugin_name": "Name",
        "ip_address": "IP Address",
        "port": "Port",
        "protocol": "Protocol",
        "severity": "Risk",
        "base_score": "CVSS Base Score",
        "cvssv3_base_score": "CVSS3 Base Score",
        "cve": "CVE",
        "state": "Vulnerability State",
    }
    REQUIRED_COLUMNS = [
        "Plugin ID", "Name", "IP Address", "Port", "Protocol",
        "Risk", "CVSS Base Score", "CVSS3 Base Score", "CVE",
    ]
    _STATE_MAP = {"new": ACTIVE, "resurfaced": ACTIVE, "active": ACTIVE, "fixed": FIXED}

    def _row_state(self, row: dict) -> Optional[str]:
        raw = row.get(self.HEADERS["state"])
        if not raw:
            return None
        return self._STATE_MAP.get(raw.lower())


# ---------------------------------------------------------------------------
# Live scanner-API pullers (download_vuln_data)
# ---------------------------------------------------------------------------

class _TenableAPIBase(_TenableCSVBase):
    """Shared plumbing for the Tenable API processors (no input file)."""

    HEADERS = _GENERIC_HEADERS  # satisfies _TenableCSVBase attribute expectations

    def _row_state(self, row):  # not used (API classes don't parse CSV rows)
        return None

    def _track_scanned(self, ip) -> None:
        if ip:
            self._scanned_ips_seen.add(ip)


class TenableSCAPIReportProcessor(_TenableAPIBase):
    """Pull vulnerabilities from Tenable.sc (SecurityCenter) /rest/analysis."""

    REPORT_TYPE = "tenable-sc"
    DEFAULT_REPORT_NAME = "tenable-sc-api"
    DEFAULT_REFERENCE_ID = "tenable-sc-api"

    CUMULATIVE = "cumulative"   # active findings
    PATCHED = "patched"         # fixed findings
    VALID_SEVERITIES = {"1", "2", "3", "4"}

    def __init__(
        self, xorg_id, debug=False, pce_version="24.2.0", *,
        host=None, user_name=None, password=None, access_key=None, secret_key=None,
        page_size=1000, verify_cert=True, severities=None, filter_ips=None,
        since=None, until=None, enable_proxy=False, proxies=None, session=None,
    ):
        self._scanned_ips_seen = set()
        self._host = host or os.environ.get("TSC_HOST")
        self._user_name = user_name or os.environ.get("TSC_USER_NAME")
        self._password = password or os.environ.get("TSC_PASSWORD")
        self._access_key = access_key or os.environ.get("TSC_ACCESS_KEY")
        self._secret_key = secret_key or os.environ.get("TSC_SECRET_KEY")
        self._filter_ips = filter_ips or os.environ.get("TSC_FILTER_IPS")
        self._page_size = int(page_size) if page_size and int(page_size) > 0 else 1000
        self._verify_cert = verify_cert
        self._since = since
        self._until = until
        self._token = None
        self._cookie = None
        self._session = session or make_session(verify=verify_cert,
                                                proxies=proxies if enable_proxy else None)

        if severities:
            sev = severities.split(",") if isinstance(severities, str) else list(severities)
            sev = [str(s).strip() for s in sev]
            for s in sev:
                if s not in self.VALID_SEVERITIES:
                    raise ValueError("invalid severity input in Tenable-sc report api upload")
            self._severities = sev
        else:
            self._severities = ["1", "2", "3", "4"]

        super().__init__(xorg_id, input_file=None, debug=debug, pce_version=pce_version)

    # -- orchestration -----------------------------------------------------

    def download_vuln_data(self) -> None:
        self._host = resolve(self._host, "TSC_HOST", "Enter Security Center API Hostname: ")
        if "://" in self._host:
            self._host = self._host.split("://", 1)[1]

        if self._access_key and self._secret_key:
            self.debug_puts("Using API key auth for Tenable.sc")
        else:
            self._create_api_session()

        for source_type in (self.CUMULATIVE, self.PATCHED):
            for result in self._iter_results(source_type):
                self._track_scanned(result.get("ip"))
                self._emit_result(result, source_type)

        self.add_report_meta_data(
            self._reference_id, self._report_name, self.REPORT_TYPE, False,
            list(self._scanned_ips_seen),
        )

    def _create_api_session(self) -> None:
        self._user_name = resolve(self._user_name, "TSC_USER_NAME", "Enter User Name: ")
        self._password = resolve(self._password, "TSC_PASSWORD", "Enter Password: ", secret=True)
        body = {"username": self._user_name, "password": self._password, "releaseSession": False}
        resp = self._session.post(
            f"https://{self._host}/rest/token",
            json=body, headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            raise ScannerAPIError(f"Tenable.sc /rest/token failed: HTTP {resp.status_code}",
                                  resp.status_code, resp.text)
        data = resp.json()["response"]
        self._token = str(data.get("token"))
        set_cookie = resp.headers.get("Set-Cookie", "")
        # last cookie's first attribute (mirrors Ruby split(",").last.split(";").first)
        self._cookie = set_cookie.split(",")[-1].strip().split(";")[0] if set_cookie else None

    # -- pagination --------------------------------------------------------

    def _iter_results(self, source_type) -> Iterator[dict]:
        offset = 0
        total = None
        while total is None or offset < total:
            body = self._analysis_request_body(source_type, offset)
            resp = self._session.post(
                f"https://{self._host}/rest/analysis",
                data=json.dumps(body),
                headers=self._auth_headers(),
            )
            if resp.status_code != 200:
                raise ScannerAPIError(f"Tenable.sc /rest/analysis failed: HTTP {resp.status_code}",
                                      resp.status_code, resp.text)
            response = resp.json()["response"]
            total = int(response.get("totalRecords", 0))
            returned = int(response.get("returnedRecords", 0))
            results = response.get("results", []) or []
            for r in results:
                yield r
            if returned <= 0:
                break
            offset += returned

    def _auth_headers(self) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._access_key and self._secret_key:
            headers["X-apikey"] = f"accesskey={self._access_key}; secretkey={self._secret_key};"
        else:
            headers["X-SecurityCenter"] = self._token or ""
            if self._cookie:
                headers["Cookie"] = self._cookie
        return headers

    def _analysis_request_body(self, source_type, offset) -> dict:
        filters = [{
            "id": "severity", "filterName": "severity", "operator": "=",
            "type": "vuln", "isPredefined": True, "value": ",".join(self._severities),
        }]
        if self._since is not None:
            until = self._until if self._until is not None else int(time.time())
            name = "lastMitigated" if source_type == self.PATCHED else "firstSeen"
            filters.append({
                "id": name, "filterName": name, "operator": "=", "type": "vuln",
                "isPredefined": True, "value": f"{int(self._since)}-{int(until)}",
            })
        if self._filter_ips:
            filters.append({"filterName": "ip", "operator": "=", "value": self._filter_ips})
        return {
            "query": {
                "type": "vuln", "tool": "vulndetails", "sourceType": source_type,
                "startOffset": offset, "endOffset": offset + self._page_size,
                "filters": filters, "vulnTool": "vulndetails",
            },
            "sourceType": source_type, "type": "vuln",
        }

    # -- mapping (pure, unit-testable) -------------------------------------

    def _emit_result(self, result: dict, source_type: str) -> None:
        severity = (result.get("severity") or {}).get("name")
        self._emit(
            plugin_id=result.get("pluginID"),
            plugin_name=result.get("pluginName"),
            ip=result.get("ip"),
            port=result.get("port"),
            protocol=result.get("protocol"),
            severity=severity,
            cvss_v2=result.get("baseScore"),
            cvss_v3=result.get("cvssV3BaseScore"),
            cve=result.get("cve"),
            state=ACTIVE if source_type == self.CUMULATIVE else FIXED,
        )


class TenableIOAPIReportProcessor(_TenableAPIBase):
    """Pull vulnerabilities from Tenable.io via the async vuln-export workflow."""

    REPORT_TYPE = "tenable-io"
    DEFAULT_REPORT_NAME = "tenable-io-api"
    DEFAULT_REFERENCE_ID = "tenable-io-api"

    IO_API_STATE_MAP = {"open": ACTIVE, "reopened": ACTIVE, "fixed": FIXED}

    def __init__(
        self, xorg_id, debug=False, pce_version="24.2.0", *,
        host=None, access_key=None, secret_key=None, page_size=1000, verify_cert=True,
        on_premise=False, since=None, enable_proxy=False, proxies=None, session=None,
        poll_interval=10, max_polls=360,
    ):
        self._scanned_ips_seen = set()
        self._host = host or os.environ.get("TIO_HOST")
        self._access_key = access_key or os.environ.get("TIO_ACCESS_KEY")
        self._secret_key = secret_key or os.environ.get("TIO_SECRET_KEY")
        self._page_size = int(page_size) if page_size and int(page_size) > 0 else 1000
        self._on_premise = on_premise
        self._since = since
        self._poll_interval = poll_interval
        self._max_polls = max_polls
        self._export_uuid = None
        self._session = session or make_session(verify=verify_cert,
                                                proxies=proxies if enable_proxy else None)
        super().__init__(xorg_id, input_file=None, debug=debug, pce_version=pce_version)

    def download_vuln_data(self) -> None:
        if self._on_premise:
            self._host = resolve(self._host, "TIO_HOST", "Enter Tenable IO Hostname: ")
        else:
            self._host = self._host or "cloud.tenable.com"
        if "://" in self._host:
            self._host = self._host.split("://", 1)[1]
        self._access_key = resolve(self._access_key, "TIO_ACCESS_KEY",
                                   "Enter Tenable IO Access Key: ", secret=True)
        self._secret_key = resolve(self._secret_key, "TIO_SECRET_KEY",
                                   "Enter Tenable IO Secret Key: ", secret=True)

        self._export_uuid = self._create_export_request()
        chunks = self._wait_for_chunks(self._export_uuid)
        for chunk_id in chunks:
            for vuln in self._get_chunk(self._export_uuid, chunk_id):
                self._track_scanned(self._vuln_ip(vuln))
                self._emit_vuln(vuln)

        self.add_report_meta_data(
            self._reference_id, self._report_name, self.REPORT_TYPE, False,
            list(self._scanned_ips_seen),
        )

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json", "Accept": "application/json",
            "X-ApiKeys": f"accessKey={self._access_key}; secretKey={self._secret_key};",
        }

    def _create_export_request(self) -> str:
        filters = {"severity": ["low", "medium", "high", "critical"]}
        if self._since is not None:
            filters["state"] = ["open", "reopened", "fixed"]
            filters["since"] = int(self._since)
        body = {"num_assets": self._page_size, "filters": filters}
        while True:
            resp = self._session.post(f"https://{self._host}/vulns/export",
                                      data=json.dumps(body), headers=self._headers())
            if resp.status_code == 200:
                return resp.json()["export_uuid"]
            if resp.status_code == 429:
                time.sleep(int(resp.headers.get("retry-after", "1")))
                continue
            raise ScannerAPIError(f"Tenable.io /vulns/export failed: HTTP {resp.status_code}",
                                  resp.status_code, resp.text)

    def _wait_for_chunks(self, uuid: str) -> List[int]:
        for _ in range(self._max_polls):
            resp = self._session.get(f"https://{self._host}/vulns/export/{uuid}/status",
                                     headers=self._headers())
            if resp.status_code == 429:
                time.sleep(int(resp.headers.get("retry-after", "1")))
                continue
            if resp.status_code != 200:
                raise ScannerAPIError(f"Tenable.io export status failed: HTTP {resp.status_code}",
                                      resp.status_code, resp.text)
            body = resp.json()
            status = body.get("status")
            if status == "FINISHED":
                if body.get("chunks_failed") or body.get("chunks_cancelled"):
                    raise ScannerAPIError("Tenable.io export had failed/cancelled chunks")
                return body.get("chunks_available", []) or []
            if status == "ERROR":
                raise ScannerAPIError("Tenable.io export status ERROR")
            time.sleep(self._poll_interval)
        raise ScannerAPIError("Tenable.io export timed out waiting for FINISHED")

    def _get_chunk(self, uuid: str, chunk_id: int) -> list:
        resp = self._session.get(
            f"https://{self._host}/vulns/export/{uuid}/chunks/{chunk_id}",
            headers={"Accept": "application/json",
                     "X-ApiKeys": f"accessKey={self._access_key}; secretKey={self._secret_key};"},
        )
        if resp.status_code != 200:
            raise ScannerAPIError(f"Tenable.io chunk {chunk_id} failed: HTTP {resp.status_code}",
                                  resp.status_code, resp.text)
        return resp.json()

    # -- mapping (pure, unit-testable) -------------------------------------

    @staticmethod
    def _vuln_ip(vuln: dict) -> Optional[str]:
        asset = vuln.get("asset", {}) or {}
        return asset.get("ipv4") or asset.get("ipv6")

    def _emit_vuln(self, vuln: dict) -> None:
        plugin = vuln.get("plugin", {}) or {}
        port = vuln.get("port", {}) or {}
        state = vuln.get("state")
        mapped_state = self.IO_API_STATE_MAP.get(state.lower()) if state else None
        self._emit(
            plugin_id=plugin.get("id"),
            plugin_name=plugin.get("name"),
            ip=self._vuln_ip(vuln),
            port=port.get("port"),
            protocol=port.get("protocol"),
            severity=vuln.get("severity"),
            cvss_v2=plugin.get("cvss_base_score"),
            cvss_v3=plugin.get("cvss3_base_score"),
            cve=plugin.get("cve"),
            state=mapped_state,
        )
