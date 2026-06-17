"""Minimal Illumio PCE REST client for the vulnerability-map import feature.

Reconstructed from illumio-cli 3.0.537. Only the endpoints the vulnerability
import touches are implemented:

    POST /api/v2/orgs/:xorg_id/vulnerabilities                       (create vuln defs)
    PUT  /api/v2/orgs/:xorg_id/vulnerabilities/:reference_id         (pre-19.1 fallback)
    PUT  /api/v2/orgs/:xorg_id/vulnerability_reports/:reference_id   (report + detections)
    GET  /api/v2/orgs/:xorg_id/workloads                             (ip -> workload href)

Auth is HTTP Basic with an API key (api_key_id:api_key_secret), exactly as the
Ruby client does (`request.basic_auth(...)`). Async is requested via the
`Prefer: Respond-Async` header, mirroring the original.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests


class PCEError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.body = body


class PCEClient:
    """Thin wrapper over the Illumio PCE v2 API used by the vuln importer."""

    def __init__(
        self,
        host: str,
        org_id: int,
        api_key_id: str,
        api_key_secret: str,
        port: int = 443,
        api_version: str = "v2",
        verify: bool | str = True,
        timeout: int = 60,
        user_agent: str = "illumio-vuln-import/0.1",
    ) -> None:
        self.host = host
        self.org_id = int(org_id)
        self.port = port
        self.api_version = api_version
        self.timeout = timeout
        self.base_url = f"https://{host}:{port}/api/{api_version}"

        self._session = requests.Session()
        self._session.auth = (api_key_id, api_key_secret)  # HTTP Basic
        self._session.verify = verify
        self._session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": user_agent}
        )

    # -- low-level ---------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _request(self, method: str, path: str, *, async_: bool = False, **kwargs: Any) -> requests.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        if async_:
            headers["Prefer"] = "Respond-Async"
        resp = self._session.request(
            method, self._url(path), headers=headers, timeout=self.timeout, **kwargs
        )
        if resp.status_code >= 400:
            raise PCEError(
                f"{method} {path} failed: HTTP {resp.status_code}",
                status=resp.status_code,
                body=resp.text,
            )
        return resp

    # -- vulnerability endpoints ------------------------------------------

    def create_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> Any:
        """POST a batch (<=1000) of vulnerability definitions (schema vulnerabilities_post)."""
        path = f"/orgs/{self.org_id}/vulnerabilities"
        resp = self._request("POST", path, data=json.dumps(vulns))
        return _maybe_json(resp)

    def update_vulnerability(self, reference_id: str, vuln: Dict[str, Any]) -> Any:
        """PUT a single vulnerability definition (PCE < 19.1; schema vulnerabilities_put)."""
        path = f"/orgs/{self.org_id}/vulnerabilities/{reference_id}"
        resp = self._request("PUT", path, data=json.dumps(vuln))
        return _maybe_json(resp)

    def update_vulnerability_report(self, reference_id: str, report: Dict[str, Any]) -> Any:
        """PUT a vulnerability report incl. detected_vulnerabilities (schema vulnerability_reports_put)."""
        path = f"/orgs/{self.org_id}/vulnerability_reports/{reference_id}"
        resp = self._request("PUT", path, data=json.dumps(report))
        return _maybe_json(resp)

    # -- workloads (to associate detections to workload hrefs) -------------

    def get_workloads(self, max_results: int = 100000) -> List[Dict[str, Any]]:
        """GET the workload collection (single page up to max_results)."""
        path = f"/orgs/{self.org_id}/workloads"
        resp = self._request("GET", path, params={"max_results": max_results})
        return _maybe_json(resp) or []

    def build_ip_to_workload_href(
        self, workloads: Optional[Iterable[Dict[str, Any]]] = None
    ) -> Dict[str, str]:
        """Map every workload interface IP (normalized) to that workload's href.

        The PCE's detected_vulnerability schema requires workload.href, so only
        detections whose IP matches a workload interface get uploaded.
        """
        if workloads is None:
            workloads = self.get_workloads()
        ip_to_href: Dict[str, str] = {}
        for wl in workloads:
            href = wl.get("href")
            if not href:
                continue
            for iface in wl.get("interfaces", []) or []:
                addr = iface.get("address")
                if not addr:
                    continue
                ip_to_href[_normalize_ip(addr)] = href
            # public_ip is sometimes the only routable address
            pub = wl.get("public_ip")
            if pub:
                ip_to_href.setdefault(_normalize_ip(pub), href)
        return ip_to_href


def _normalize_ip(addr: str) -> str:
    try:
        return str(ipaddress.ip_address(addr.strip()))
    except ValueError:
        return addr.strip()


def _maybe_json(resp: requests.Response) -> Any:
    if not resp.content:
        return None
    ctype = resp.headers.get("Content-Type", "")
    if "json" in ctype:
        try:
            return resp.json()
        except ValueError:
            return None
    return None
