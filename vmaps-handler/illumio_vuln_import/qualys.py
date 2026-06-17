"""Qualys XML report processor (port of QualysXMLReportProcessor).

Handles both Qualys report layouts:
  * Scan Data Report  (//IP > CAT > {INFO,SERVICE,VULN})
  * Asset Data Report (//ASSET_DATA_REPORT, //VULN_DETAILS + //HOST)

The live Qualys-API puller (QualysAPIProcessor) is implemented at the bottom of
this module; see docs/illumio-vulnerability-import-api.md for the API details.
"""

from __future__ import annotations

import os
from typing import Optional
from xml.etree import ElementTree as ET

from .base import ACTIVE, FIXED, ReportProcessorBase, get_score
from .scanner_http import ScannerAPIError, make_session, resolve


class QualysXMLReportProcessor(ReportProcessorBase):
    def process_report(self, input_file: str) -> None:
        self.debug_puts(f"Input File: {input_file}")

        ilowd = os.environ.get("ILOWD")
        if ilowd and not os.path.isfile(input_file):
            input_file = f"{ilowd}/{input_file}"

        rep_file_name = os.path.splitext(os.path.basename(input_file))[0]
        try:
            root = ET.parse(input_file).getroot()
            # Ruby's `//ASSET_DATA_REPORT` is root-inclusive; ElementTree's
            # `.//` is descendant-only, so check the root element explicitly.
            asset_data = root.tag == "ASSET_DATA_REPORT" or bool(root.findall(".//ASSET_DATA_REPORT"))
            if asset_data:
                self._process_asset_data_report(root, rep_file_name)
            else:
                self._process_scan_data_report(root, rep_file_name)
        except Exception as e:  # noqa: BLE001
            print("Failed parsing the file.")
            print(repr(e))
            raise SystemExit(1)

    # -- Scan Data Report --------------------------------------------------

    def _process_scan_data_report(self, root, rep_file_name) -> None:
        ip_nodes = root.findall(".//IP")
        self.debug_puts(f"Total ips to process: {len(ip_nodes)}")

        scanned_ips = set()
        for ip_node in ip_nodes:
            ip_address = ip_node.get("value")
            scanned_ips.add(ip_address)
            self.debug_puts(str(ip_address))
            for child in list(ip_node):
                name = (child.tag or "").lower()
                if name == "infos":
                    continue  # not processed in scan-data reports (matches Ruby)
                elif name == "services":
                    self._process_vuln_data(ip_address, child, "SERVICE")
                elif name == "vulns":
                    self._process_vuln_data(ip_address, child, "VULN")

        self._process_report_meta_data(root, scanned_ips, rep_file_name)

    def _process_vuln_data(self, ip_address, parent_node, node_name) -> None:
        for category in parent_node.findall(".//CAT"):
            port = category.get("port")
            protocol = category.get("protocol")
            for info in category.findall(f".//{node_name}"):
                number = info.get("number") or ""
                vuln_id = ("qualys-" + number)
                vuln_id = _gsub(vuln_id, "%_>", "-").replace("/", "-")

                title_el = info.find(".//TITLE")
                title = title_el.text if title_el is not None else None

                cve_ids = []
                for cve in info.findall(".//CVE_ID_LIST//CVE_ID"):
                    id_el = cve.find(".//ID")
                    if id_el is not None and id_el.text:
                        cve_ids.append(id_el.text)

                severity = int(info.get("severity", "0") or "0")
                self.add_vulnerability(vuln_id, get_score(severity), title, cve_ids)
                self.add_detected_vulnerability(ip_address, port, protocol, vuln_id)

    def _process_report_meta_data(self, root, scanned_ips, rep_file_name) -> None:
        scan = root.find(".//SCAN")
        header = self._get_header_data(root)
        reference_id = (scan.get("value") if scan is not None else rep_file_name) or rep_file_name
        for ch in "/.:":
            reference_id = reference_id.replace(ch, "_")
        title = header.get("TITLE") or rep_file_name
        self.add_report_meta_data(reference_id, title, "qualys", False, list(scanned_ips))

    @staticmethod
    def _get_header_data(root) -> dict:
        header_info = {}
        header = root.find(".//HEADER")
        if header is not None:
            for el in list(header):
                key = el.get("value")
                if key is not None:
                    header_info[key] = (el.text or "")
        return header_info

    # -- Asset Data Report -------------------------------------------------

    def _process_asset_data_report(self, root, rep_file_name) -> None:
        vuln_nodes = root.findall(".//VULN_DETAILS")
        if not vuln_nodes:
            print(
                f"Error: Vulnerability details not found in Asset Data Report {rep_file_name}. "
                "Adjust settings in Qualys and generate report again."
            )
            raise SystemExit(1)

        self.debug_puts(f"Total vulnerabilities to process: {len(vuln_nodes)}")
        for node in vuln_nodes:
            cve_ids = []
            for cve in node.findall(".//CVE_ID_LIST//CVE_ID"):
                id_el = cve.find(".//ID")
                if id_el is not None and id_el.text:
                    cve_ids.append(id_el.text)

            severity = int(_text(node.find(".//SEVERITY"), "0") or "0")
            cvss3 = _text(node.find(".//CVSS3_SCORE/CVSS3_BASE"))
            cvss = _text(node.find(".//CVSS_SCORE/CVSS_BASE"))
            if cvss3 and cvss3 != "-":
                score = int(float(cvss3) * 10)
            elif cvss and cvss != "-":
                score = int(float(cvss) * 10)
            else:
                score = get_score(severity)

            title = _text(node.find(".//TITLE"))
            # RE-NOTE: faithful to the original illumio-cli, which keys the vuln
            # definition on VULN_DETAILS@id (e.g. "38173") but keys the detection
            # below on "qid_"+QID (e.g. "qid_38173"). If your Qualys export has
            # @id == bare QID these will NOT match and the detection references a
            # missing vuln class. Set ILO_QUALYS_QID_PREFIX=1 to align them.
            ref = node.get("id")
            if os.environ.get("ILO_QUALYS_QID_PREFIX") == "1":
                ref = "qid_" + ref
            self.add_vulnerability(ref, score, title, cve_ids)

        scanned_ips = set()
        for host in root.findall(".//HOST"):
            ip_address = _text(host.find(".//IP"))
            scanned_ips.add(ip_address)
            for vinfo in host.findall(".//VULN_INFO"):
                port = _text(vinfo.find(".//PORT")) or None
                protocol = _text(vinfo.find(".//PROTOCOL")) or None
                qid = _text(vinfo.find(".//QID"))
                vuln_id = "qid_" + qid
                self.add_detected_vulnerability(ip_address, port, protocol, vuln_id)

        self.add_report_meta_data(
            rep_file_name, rep_file_name, "Qualys - Asset Data Report", False, list(scanned_ips)
        )


def _text(el, default=None):
    if el is None:
        return default
    return el.text if el.text is not None else default


def _gsub(s: str, chars: str, repl: str) -> str:
    out = []
    for c in s:
        out.append(repl if c in chars else c)
    return "".join(out)


# ---------------------------------------------------------------------------
# Live Qualys VM API puller (download_vuln_data)
# ---------------------------------------------------------------------------


class QualysAPIProcessor(QualysXMLReportProcessor):
    """Pull detections from the Qualys VM API (host/vm/detection + knowledge_base).

    Session auth (cookie). Detections are fetched page by page; for each page the
    referenced QIDs are looked up in the Knowledge Base (batches of 300) to build
    the vulnerability definitions, then detections for known QIDs are emitted.
    """

    SEVERITIES = {"1", "2", "3", "4", "5"}
    QID_BATCH = 300
    # Qualys detection STATUS -> PCE state
    STATE_MAP = {"active": ACTIVE, "new": ACTIVE, "re-opened": ACTIVE, "fixed": FIXED}

    SESSION_PATH = "/api/2.0/fo/session/"
    DETECTION_PATH = "/api/2.0/fo/asset/host/vm/detection/"
    KB_PATH = "/api/2.0/fo/knowledge_base/vuln/"

    def __init__(
        self, xorg_id, debug=False, pce_version="24.2.0", *,
        host=None, user_name=None, password=None, page_size=1000,
        scanned_after=None, severities=None, verify_cert=True,
        enable_proxy=False, proxies=None, session=None,
        user_agent="illumio-vuln-import/0.1",
    ):
        self._host = host or os.environ.get("QAP_HOST")
        self._user_name = user_name or os.environ.get("QAP_USER_NAME")
        self._password = password or os.environ.get("QAP_PASSWORD")
        self._trunc_limit = str(page_size)
        self._scanned_after = scanned_after
        self._cookie = None
        self._user_agent = user_agent
        self._seen_qids = set()
        self._missing_qids = set()
        self._scanned_ips_seen = set()
        self._session = session or make_session(verify=verify_cert,
                                                proxies=proxies if enable_proxy else None,
                                                user_agent=user_agent)

        if severities:
            sev = severities.split(",") if isinstance(severities, str) else list(severities)
            sev = [str(s).strip() for s in sev]
            for s in sev:
                if s not in self.SEVERITIES:
                    raise ValueError("invalid severity input in Qualys report api upload")
            self._severities = sev
        else:
            self._severities = None

        super().__init__(xorg_id, input_file=None, debug=debug, pce_version=pce_version)

    # -- orchestration -----------------------------------------------------

    def download_vuln_data(self) -> None:
        self._host = resolve(self._host, "QAP_HOST", "Host FQDN: ")
        self._user_name = resolve(self._user_name, "QAP_USER_NAME", "Username: ")
        self._password = resolve(self._password, "QAP_PASSWORD", "Password: ", secret=True)

        self._login()
        try:
            form = self._initial_detection_form()
            while form is not None:
                form = self._request_detections(form)
            if self._missing_qids:
                print(
                    "knowledge base info for following qids "
                    f"{sorted(self._missing_qids)} are missing in Qualys knowledge base, "
                    "detected vulnerabilities on these qids will not be uploaded to the PCE"
                )
            self.add_report_meta_data("qualys-api", "qualys-api", "qualys", False,
                                      list(self._scanned_ips_seen))
        finally:
            self._logout()

    # -- session -----------------------------------------------------------

    def _login(self) -> None:
        resp = self._session.post(
            f"https://{self._host}{self.SESSION_PATH}",
            data={"action": "login", "username": self._user_name, "password": self._password},
            headers={"X-Requested-With": self._user_agent},
        )
        if resp.status_code != 200:
            raise ScannerAPIError(f"Qualys login failed: HTTP {resp.status_code}",
                                  resp.status_code, resp.text)
        set_cookie = resp.headers.get("Set-Cookie")
        if not set_cookie:
            raise ScannerAPIError("Qualys login returned no cookie")
        self._cookie = set_cookie.split(";")[0]

    def _logout(self) -> None:
        if not self._cookie:
            return
        self._session.post(
            f"https://{self._host}{self.SESSION_PATH}",
            data={"action": "logout"},
            headers={"X-Requested-With": self._user_agent, "Cookie": self._cookie},
        )

    # -- detections (paginated) -------------------------------------------

    def _initial_detection_form(self) -> dict:
        form = {"action": "list", "truncation_limit": self._trunc_limit, "output_format": "XML"}
        if self._scanned_after:
            form["detection_processed_after"] = self._scanned_after
            form["status"] = "New, Active, Re-Opened, Fixed"
        else:
            form["status"] = "New, Active, Re-Opened"
        if self._severities:
            form["severities"] = ", ".join(self._severities)
        return form

    def _request_detections(self, form: dict) -> Optional[dict]:
        resp = self._session.post(
            f"https://{self._host}{self.DETECTION_PATH}",
            data=form,
            headers={"X-Requested-With": self._user_agent, "Cookie": self._cookie},
        )
        if resp.status_code != 200:
            raise ScannerAPIError(f"Qualys detection list failed: HTTP {resp.status_code}",
                                  resp.status_code, resp.text)
        root = ET.fromstring(resp.content)
        self._process_detection_page(root)
        return self._next_form_from(root)

    @staticmethod
    def _next_form_from(root) -> Optional[dict]:
        url_nodes = root.findall(".//URL")
        if not url_nodes or not (url_nodes[0].text or ""):
            return None
        query = url_nodes[0].text.split("?", 1)[1]
        form = {}
        for pair in query.split("&"):
            k, _, v = pair.partition("=")
            form[k] = v
        return form

    # -- mapping (pure, unit-testable) -------------------------------------

    def _process_detection_page(self, root) -> None:
        detections = []  # (ip, port, proto, qid, status)
        new_qids = []
        for host in root.findall(".//HOST"):
            ip = _text(host.find(".//IP"))
            self._scanned_ips_seen.add(ip)
            for d in host.findall(".//DETECTION"):
                qid = _text(d.find(".//QID"))
                port = _text(d.find(".//PORT")) or None
                proto = _text(d.find(".//PROTOCOL")) or None
                status = _text(d.find(".//STATUS")) or ""
                if qid not in self._seen_qids:
                    new_qids.append(qid)
                    self._seen_qids.add(qid)
                detections.append((ip, port, proto, qid, status))

        for start in range(0, len(new_qids), self.QID_BATCH):
            self._get_qid_data(new_qids[start:start + self.QID_BATCH])

        for ip, port, proto, qid, status in detections:
            vuln_id = "qid_" + qid
            if vuln_id in self.vulnerabilities:
                self.add_detected_vulnerability(
                    ip, port, proto, vuln_id, state=self.STATE_MAP.get(status.lower())
                )
            else:
                self._missing_qids.add(vuln_id)

    def _get_qid_data(self, qids: list) -> None:
        resp = self._session.post(
            f"https://{self._host}{self.KB_PATH}",
            data={"action": "list", "ids": ", ".join(qids)},
            headers={"X-Requested-With": self._user_agent, "Cookie": self._cookie},
        )
        if resp.status_code != 200:
            raise ScannerAPIError(f"Qualys knowledge base failed: HTTP {resp.status_code}",
                                  resp.status_code, resp.text)
        self._parse_qid_data(ET.fromstring(resp.content))

    def _parse_qid_data(self, root) -> None:
        for vuln in root.findall(".//VULN"):
            qid = _text(vuln.find(".//QID"))
            title = _text(vuln.find(".//TITLE"))
            severity = int(_text(vuln.find(".//SEVERITY_LEVEL"), "0") or "0")
            cvss_v3 = _text(vuln.find(".//CVSS_V3/BASE"))
            cvss = _text(vuln.find(".//CVSS/BASE"))
            if cvss_v3:
                score = int(float(cvss_v3) * 10)
            elif cvss:
                score = int(float(cvss) * 10)
            else:
                score = get_score(severity)
            cve_ids = [_text(c.find(".//ID")) for c in vuln.findall(".//CVE_LIST/CVE")]
            cve_ids = [c for c in cve_ids if c]
            self.add_vulnerability("qid_" + qid, score, title, cve_ids)
