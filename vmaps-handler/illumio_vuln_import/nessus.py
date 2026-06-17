"""Nessus .nessus XML report processor (port of NessusProXMLReportProcessor)."""

from __future__ import annotations

import os
try:
    from lxml import etree as _lxml_etree
    def _parse_xml(source):
        parser = _lxml_etree.XMLParser(recover=True)
        return _lxml_etree.parse(source, parser)
except ImportError:
    from xml.etree import ElementTree as _stdlib_et
    def _parse_xml(source):
        return _stdlib_et.parse(source)

from xml.etree import ElementTree as ET

from .base import ReportProcessorBase


class NessusProXMLReportProcessor(ReportProcessorBase):
    """Parses a Nessus Pro `.nessus` XML export into PCE vulnerability records."""

    def process_report(self, input_file: str) -> None:
        self.debug_puts(f"Input File: {input_file}")

        ilowd = os.environ.get("ILOWD")
        if ilowd and not os.path.isfile(input_file):
            input_file = f"{ilowd}/{input_file}"

        tree = _parse_xml(input_file)
        root = tree.getroot()
        report_node = root.find(".//Report")
        if report_node is None:
            raise ValueError("No <Report> element found in Nessus file")

        host_nodes = report_node.findall(".//ReportHost")
        self.debug_puts(f"Total ips to process: {len(host_nodes)}")

        try:
            scanned_ips = set()
            for host_node in host_nodes:
                host_properties = self._get_host_data(host_node)
                ip_address = host_properties.get("host-ip")
                scanned_ips.add(ip_address)
                self.debug_puts(str(ip_address))
                self._process_vuln_data(ip_address, host_node)
            self._process_report_meta_data(report_node, scanned_ips)
        except Exception as e:  # noqa: BLE001 - mirrors Ruby `rescue StandardError`
            print("Failed parsing the file.")
            print(repr(e))
            raise SystemExit(1)

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _get_host_data(host_node) -> dict:
        props = {}
        hp = host_node.find(".//HostProperties")
        if hp is not None:
            for tag in hp:
                name = tag.get("name")
                if name is not None:
                    props[name] = tag.text
        return props

    def _process_report_meta_data(self, report_node, scanned_ips) -> None:
        name = report_node.get("name", "")
        reference_id = "nessus-" + "".join(name.split())
        self.add_report_meta_data(reference_id, name, "nessus", False, list(scanned_ips))

    def _process_vuln_data(self, ip_address, host_node) -> None:
        for item in host_node.findall(".//ReportItem"):
            severity = int(item.get("severity", "0") or "0")
            if severity == 0:
                continue

            vuln_id = "nessus-" + item.get("pluginID", "")

            cve_ids = [cve.text for cve in item.findall(".//cve") if cve.text]

            cvss3 = item.find(".//cvss3_base_score")
            cvss = item.find(".//cvss_base_score")
            if cvss3 is not None and cvss3.text:
                score = int(float(cvss3.text) * 10)
            elif cvss is not None and cvss.text:
                score = int(float(cvss.text) * 10)
            else:
                score = self._score_from_severity(severity)

            self.add_vulnerability(vuln_id, score, item.get("pluginName"), cve_ids)
            self.add_detected_vulnerability(ip_address, item.get("port"), item.get("protocol"), vuln_id)

    @staticmethod
    def _score_from_severity(severity: int) -> int:
        from .base import get_score
        return get_score(severity)
