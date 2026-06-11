#!/usr/bin/env python3
"""
vcenter-sync -- Bi-directional sync between VMware vCenter VM inventory and
Illumio PCE.

Imports VMs as unmanaged workloads with labels derived from vCenter tags and
folder hierarchy.  Optionally pushes Illumio labels back as vCenter custom
tags.

Modes:
  - analytics (default): Read-only -- discover VMs, show what labels WOULD be
    derived and what workloads WOULD be created, without touching the PCE.
  - import: Create/update unmanaged workloads on the PCE from vCenter VMs.
  - export: Push Illumio labels to vCenter as tags on matched VMs.
  - bidirectional: Both import and export.

NOTE: This plugin is UNTESTED against a live vCenter instance.
"""

import json
import logging
import os
import signal
import ssl
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import requests
from illumio import PolicyComputeEngine
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
log = logging.getLogger("vcenter-sync")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
VCENTER_HOST = os.environ.get("VCENTER_HOST", "")
VCENTER_USER = os.environ.get("VCENTER_USER", "")
VCENTER_PASSWORD = os.environ.get("VCENTER_PASSWORD", "")
VCENTER_PORT = int(os.environ.get("VCENTER_PORT", "443"))

MODE = os.environ.get("MODE", "analytics").lower()
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "3600"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

FOLDER_TO_LABEL = os.environ.get("FOLDER_TO_LABEL", "true").lower() in ("true", "1", "yes")
POWER_STATE_FILTER = os.environ.get("POWER_STATE_FILTER", "all").lower()  # all | poweredOn | poweredOff
SKIP_TEMPLATES = os.environ.get("SKIP_TEMPLATES", "true").lower() in ("true", "1", "yes")

# Tag-to-label mapping: vCenter tag category name -> Illumio label key
DEFAULT_TAG_MAPPING = {
    "Application": "app",
    "Environment": "env",
    "Role": "role",
    "Location": "loc",
}
TAG_MAPPING = DEFAULT_TAG_MAPPING.copy()
_tm = os.environ.get("TAG_MAPPING", "").strip()
if _tm:
    try:
        TAG_MAPPING = json.loads(_tm)
    except json.JSONDecodeError:
        log.warning("Invalid TAG_MAPPING JSON, using defaults")

# Folder-to-label mapping pattern: which folder depth maps to which label key
# Default: depth 0 (first folder under /vm/) = env, depth 1 = role
DEFAULT_FOLDER_MAPPING = {"0": "env", "1": "role"}
FOLDER_MAPPING = DEFAULT_FOLDER_MAPPING.copy()
_fm = os.environ.get("FOLDER_MAPPING", "").strip()
if _fm:
    try:
        FOLDER_MAPPING = json.loads(_fm)
    except json.JSONDecodeError:
        log.warning("Invalid FOLDER_MAPPING JSON, using defaults")

STATE_FILE = os.environ.get("STATE_FILE", "/data/vcenter_sync_state.json")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
sync_state = {
    "last_sync": None,
    "last_sync_duration": 0,
    "sync_count": 0,
    "syncing": False,
    "error": None,
    "mode": MODE,
    "vcenter_status": "unknown",
    "vms": [],
    "tag_mapping": {},
    "folder_mapping": {},
    "sync_results": {
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "errors": 0,
        "tags_pushed": 0,
        "details": [],
    },
    "summary": {
        "total_vms": 0,
        "powered_on": 0,
        "powered_off": 0,
        "suspended": 0,
        "matched": 0,
        "vcenter_only": 0,
        "illumio_only": 0,
        "with_tags": 0,
        "with_folder_labels": 0,
    },
    "sync_history": [],
}

label_cache = {}       # href -> {key, value}
label_href_map = {}    # (key, value) -> href

# ---------------------------------------------------------------------------
# PCE helpers
# ---------------------------------------------------------------------------


def get_pce():
    pce = PolicyComputeEngine(
        url=os.environ["PCE_HOST"],
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ["PCE_API_KEY"],
        password=os.environ["PCE_API_SECRET"],
    )
    verify = os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() != "true"
    pce.set_tls_settings(verify=verify)
    return pce


def fetch_labels(pce):
    global label_cache, label_href_map
    try:
        resp = pce.get("/labels")
        labels = resp.json() if resp.status_code == 200 else []
        cache = {}
        href_map = {}
        for lbl in labels:
            href = lbl.get("href", "")
            key = lbl.get("key", "")
            value = lbl.get("value", "")
            if href:
                cache[href] = {"key": key, "value": value}
                href_map[(key, value)] = href
        label_cache = cache
        label_href_map = href_map
        log.info("Loaded %d labels from PCE", len(cache))
    except Exception as e:
        log.warning("Failed to fetch labels: %s", e)


def resolve_workload_labels(wl):
    """Resolve a workload's label hrefs to {key: value} dict."""
    result = {}
    for lbl in wl.get("labels", []):
        href = lbl.get("href", "")
        if href in label_cache:
            cached = label_cache[href]
            result[cached["key"]] = cached["value"]
    return result


def get_workload_ips(wl):
    """Extract all IP addresses from a workload."""
    return [iface["address"] for iface in wl.get("interfaces", []) if iface.get("address")]


def ensure_label(pce, key, value):
    """Ensure a label exists on the PCE.  Return its href or empty string."""
    global label_href_map
    existing = label_href_map.get((key, value))
    if existing:
        return existing
    try:
        resp = pce.post("/labels", json={"key": key, "value": value})
        if resp.status_code in (200, 201):
            href = resp.json().get("href", "")
            if href:
                label_href_map[(key, value)] = href
                label_cache[href] = {"key": key, "value": value}
            return href
    except Exception as e:
        log.warning("Failed to create label %s:%s -- %s", key, value, e)
    return ""


# ---------------------------------------------------------------------------
# vCenter pyVmomi connection
# ---------------------------------------------------------------------------


def connect_vcenter():
    """Connect to vCenter via pyVmomi and return the ServiceInstance."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    si = SmartConnect(
        host=VCENTER_HOST,
        user=VCENTER_USER,
        pwd=VCENTER_PASSWORD,
        port=VCENTER_PORT,
        sslContext=context,
    )
    return si


def get_folder_path(vm):
    """Walk the parent chain of a VM to build its folder path segments.

    Returns a list of folder names between the root ``vm`` folder and the VM
    itself (excluding the datacenter-level ``vm`` folder and the datacenter
    name).
    """
    segments = []
    parent = vm.parent
    while parent:
        if isinstance(parent, vim.Folder):
            # Stop at the root "vm" folder or datacenter
            if parent.name in ("vm", "Datacenters"):
                break
            segments.append(parent.name)
        elif isinstance(parent, vim.Datacenter):
            break
        parent = getattr(parent, "parent", None)
    segments.reverse()
    return segments


def collect_vms(si):
    """Discover all VMs via pyVmomi container view.

    Returns a list of dicts with basic VM properties.
    """
    content = si.RetrieveContent()
    container = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.VirtualMachine], True,
    )
    vms = container.view
    container.Destroy()

    results = []
    for vm in vms:
        try:
            if SKIP_TEMPLATES and vm.config and vm.config.template:
                continue

            power = str(vm.runtime.powerState) if vm.runtime else "unknown"
            if POWER_STATE_FILTER != "all" and power != POWER_STATE_FILTER:
                continue

            # Primary IP
            primary_ip = ""
            all_ips = []
            if vm.guest:
                primary_ip = vm.guest.ipAddress or ""
                if vm.guest.net:
                    for nic in vm.guest.net:
                        if nic.ipConfig and nic.ipConfig.ipAddress:
                            for ip_entry in nic.ipConfig.ipAddress:
                                addr = ip_entry.ipAddress or ""
                                if addr and ":" not in addr:  # skip IPv6
                                    all_ips.append(addr)
            if primary_ip and primary_ip not in all_ips:
                all_ips.insert(0, primary_ip)
            if not all_ips and primary_ip:
                all_ips = [primary_ip]

            os_name = ""
            annotation = ""
            if vm.config:
                os_name = vm.config.guestFullName or ""
                annotation = vm.config.annotation or ""

            moref = vm._moId if hasattr(vm, "_moId") else str(vm).split(":")[-1].rstrip("'")

            folder_segments = get_folder_path(vm)

            results.append({
                "name": vm.name,
                "moref": moref,
                "power_state": power,
                "primary_ip": primary_ip,
                "all_ips": all_ips,
                "os": os_name,
                "annotation": annotation,
                "folder_path": "/".join(folder_segments),
                "folder_segments": folder_segments,
                "tags": {},         # populated later from REST API
                "tag_labels": {},   # derived labels from tags
                "folder_labels": {},  # derived labels from folder path
                "derived_labels": {},  # merged final labels
            })
        except Exception as e:
            log.warning("Error reading VM %s: %s", getattr(vm, "name", "?"), e)

    return results


# ---------------------------------------------------------------------------
# vSphere REST API -- tag reading / writing
# ---------------------------------------------------------------------------


class VCenterRESTClient:
    """Thin wrapper around the vSphere REST API for tag operations."""

    def __init__(self, host, user, password, port=443):
        self.base_url = f"https://{host}"
        self.user = user
        self.password = password
        self.session_id = None
        self.headers = {}
        self._categories_cache = {}   # id -> {name, id}
        self._tags_cache = {}         # id -> {name, category_id, category_name}

    def login(self):
        try:
            resp = requests.post(
                f"{self.base_url}/api/session",
                auth=(self.user, self.password),
                verify=False, timeout=30,
            )
            if resp.status_code in (200, 201):
                self.session_id = resp.json()
                self.headers = {"vmware-api-session-id": self.session_id}
                return True
            log.warning("vCenter REST login failed: HTTP %d", resp.status_code)
            return False
        except Exception as e:
            log.warning("vCenter REST login error: %s", e)
            return False

    def logout(self):
        if self.session_id:
            try:
                requests.delete(
                    f"{self.base_url}/api/session",
                    headers=self.headers, verify=False, timeout=10,
                )
            except Exception:
                pass
            self.session_id = None
            self.headers = {}

    # -- Categories & Tags --

    def load_categories(self):
        """Fetch all tag categories and cache them."""
        try:
            resp = requests.get(
                f"{self.base_url}/api/cis/tagging/category",
                headers=self.headers, verify=False, timeout=30,
            )
            if resp.status_code != 200:
                return
            category_ids = resp.json()
            for cid in category_ids:
                detail = requests.get(
                    f"{self.base_url}/api/cis/tagging/category/{cid}",
                    headers=self.headers, verify=False, timeout=15,
                )
                if detail.status_code == 200:
                    data = detail.json()
                    self._categories_cache[cid] = {
                        "id": cid,
                        "name": data.get("name", ""),
                    }
            log.info("Loaded %d vCenter tag categories", len(self._categories_cache))
        except Exception as e:
            log.warning("Failed to load tag categories: %s", e)

    def load_tags(self):
        """Fetch all tags and cache them."""
        try:
            resp = requests.get(
                f"{self.base_url}/api/cis/tagging/tag",
                headers=self.headers, verify=False, timeout=30,
            )
            if resp.status_code != 200:
                return
            tag_ids = resp.json()
            for tid in tag_ids:
                detail = requests.get(
                    f"{self.base_url}/api/cis/tagging/tag/{tid}",
                    headers=self.headers, verify=False, timeout=15,
                )
                if detail.status_code == 200:
                    data = detail.json()
                    cat_id = data.get("category_id", "")
                    cat_name = self._categories_cache.get(cat_id, {}).get("name", "")
                    self._tags_cache[tid] = {
                        "id": tid,
                        "name": data.get("name", ""),
                        "category_id": cat_id,
                        "category_name": cat_name,
                    }
            log.info("Loaded %d vCenter tags", len(self._tags_cache))
        except Exception as e:
            log.warning("Failed to load tags: %s", e)

    def get_vm_tags(self, moref):
        """Get tags attached to a VM by its managed-object reference ID."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/cis/tagging/tag-association?action=list-attached-tags",
                headers=self.headers, verify=False, timeout=15,
                json={"object_id": {"id": moref, "type": "VirtualMachine"}},
            )
            if resp.status_code != 200:
                return {}
            tag_ids = resp.json()
            tags = {}  # category_name -> tag_name
            for tid in tag_ids:
                tag_info = self._tags_cache.get(tid)
                if tag_info:
                    cat_name = tag_info["category_name"]
                    tags[cat_name] = tag_info["name"]
            return tags
        except Exception as e:
            log.debug("Failed to get tags for VM %s: %s", moref, e)
            return {}

    # -- Tag writing (export mode) --

    def ensure_category(self, category_name):
        """Create a tag category if it doesn't exist.  Return category ID."""
        for cid, info in self._categories_cache.items():
            if info["name"] == category_name:
                return cid
        try:
            resp = requests.post(
                f"{self.base_url}/api/cis/tagging/category",
                headers=self.headers, verify=False, timeout=15,
                json={
                    "name": category_name,
                    "description": f"Managed by Illumio Plugger",
                    "cardinality": "SINGLE",
                    "associable_types": ["VirtualMachine"],
                },
            )
            if resp.status_code in (200, 201):
                cid = resp.json()
                self._categories_cache[cid] = {"id": cid, "name": category_name}
                log.info("Created vCenter tag category: %s", category_name)
                return cid
        except Exception as e:
            log.warning("Failed to create category %s: %s", category_name, e)
        return ""

    def ensure_tag(self, category_id, tag_name):
        """Create a tag if it doesn't exist.  Return tag ID."""
        for tid, info in self._tags_cache.items():
            if info["category_id"] == category_id and info["name"] == tag_name:
                return tid
        try:
            resp = requests.post(
                f"{self.base_url}/api/cis/tagging/tag",
                headers=self.headers, verify=False, timeout=15,
                json={
                    "name": tag_name,
                    "description": f"Synced from Illumio",
                    "category_id": category_id,
                },
            )
            if resp.status_code in (200, 201):
                tid = resp.json()
                cat_name = self._categories_cache.get(category_id, {}).get("name", "")
                self._tags_cache[tid] = {
                    "id": tid,
                    "name": tag_name,
                    "category_id": category_id,
                    "category_name": cat_name,
                }
                log.info("Created vCenter tag: %s / %s", cat_name, tag_name)
                return tid
        except Exception as e:
            log.warning("Failed to create tag %s: %s", tag_name, e)
        return ""

    def attach_tag(self, tag_id, moref):
        """Attach a tag to a VM."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/cis/tagging/tag-association/{tag_id}?action=attach",
                headers=self.headers, verify=False, timeout=15,
                json={"object_id": {"id": moref, "type": "VirtualMachine"}},
            )
            return resp.status_code in (200, 204)
        except Exception as e:
            log.debug("Failed to attach tag %s to %s: %s", tag_id, moref, e)
            return False

    def detach_tag(self, tag_id, moref):
        """Detach a tag from a VM."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/cis/tagging/tag-association/{tag_id}?action=detach",
                headers=self.headers, verify=False, timeout=15,
                json={"object_id": {"id": moref, "type": "VirtualMachine"}},
            )
            return resp.status_code in (200, 204)
        except Exception as e:
            log.debug("Failed to detach tag %s from %s: %s", tag_id, moref, e)
            return False


# ---------------------------------------------------------------------------
# Label derivation
# ---------------------------------------------------------------------------


def derive_tag_labels(vm_tags):
    """Convert vCenter tags to Illumio label suggestions via TAG_MAPPING.

    vm_tags: {category_name: tag_name, ...}
    Returns: {illumio_key: value, ...}
    """
    labels = {}
    for category_name, tag_name in vm_tags.items():
        illumio_key = TAG_MAPPING.get(category_name)
        if illumio_key:
            labels[illumio_key] = tag_name.lower().replace(" ", "-")
    return labels


def derive_folder_labels(folder_segments):
    """Convert folder path segments to Illumio label suggestions via FOLDER_MAPPING.

    folder_segments: ["Production", "WebServers"]
    Returns: {illumio_key: value, ...}
    """
    labels = {}
    for depth_str, illumio_key in FOLDER_MAPPING.items():
        try:
            depth = int(depth_str)
        except ValueError:
            continue
        if depth < len(folder_segments):
            labels[illumio_key] = folder_segments[depth].lower().replace(" ", "-")
    return labels


def merge_labels(tag_labels, folder_labels):
    """Merge tag-derived and folder-derived labels.  Tag labels take precedence."""
    merged = dict(folder_labels)
    merged.update(tag_labels)
    return merged


# ---------------------------------------------------------------------------
# Match engine
# ---------------------------------------------------------------------------


def build_matches(vm_list, workloads):
    """Match vCenter VMs to Illumio workloads.

    Returns (matched, vcenter_only, illumio_only) where:
      - matched: list of {vm, workload, match_type} for VMs found in both
      - vcenter_only: VMs with no corresponding workload (candidates for import)
      - illumio_only: workloads with no corresponding vCenter VM
    """
    # Index workloads by IP and hostname
    wl_by_ip = {}
    wl_by_hostname = {}
    for wl in workloads:
        hostname = (wl.get("hostname") or wl.get("name") or "").lower()
        if hostname:
            wl_by_hostname[hostname] = wl
        for iface in wl.get("interfaces", []):
            ip = iface.get("address", "")
            if ip:
                wl_by_ip[ip] = wl

    matched = []
    vcenter_only = []
    matched_wl_hrefs = set()

    for vm in vm_list:
        matched_wl = None
        match_type = ""

        # Try IP match first
        for ip in vm["all_ips"]:
            if ip in wl_by_ip:
                matched_wl = wl_by_ip[ip]
                match_type = "ip"
                break

        # Fallback to hostname match
        if not matched_wl:
            vm_name_lower = vm["name"].lower()
            if vm_name_lower in wl_by_hostname:
                matched_wl = wl_by_hostname[vm_name_lower]
                match_type = "hostname"

        if matched_wl:
            matched.append({
                "vm": vm,
                "workload": matched_wl,
                "match_type": match_type,
            })
            matched_wl_hrefs.add(matched_wl.get("href", ""))
        else:
            vcenter_only.append(vm)

    illumio_only = [wl for wl in workloads if wl.get("href", "") not in matched_wl_hrefs]

    return matched, vcenter_only, illumio_only


# ---------------------------------------------------------------------------
# Sync logic
# ---------------------------------------------------------------------------


def run_sync(pce, si, rest_client):
    """Full sync cycle."""
    with state_lock:
        if sync_state["syncing"]:
            return
        sync_state["syncing"] = True

    start_time = time.time()

    try:
        log.info("Starting sync (mode=%s)...", MODE)

        fetch_labels(pce)

        # ---- vCenter discovery ----
        vc_status = "unknown"
        vm_list = []
        try:
            vm_list = collect_vms(si)
            vc_status = "connected"
            log.info("Discovered %d VMs from vCenter", len(vm_list))
        except Exception as e:
            log.error("Failed to collect VMs: %s", e)
            vc_status = f"error: {str(e)[:80]}"

        # ---- Tag enrichment via REST API ----
        tags_enriched = 0
        if rest_client and vm_list:
            try:
                if rest_client.login():
                    rest_client.load_categories()
                    rest_client.load_tags()
                    for vm in vm_list:
                        vm["tags"] = rest_client.get_vm_tags(vm["moref"])
                        vm["tag_labels"] = derive_tag_labels(vm["tags"])
                        if vm["tags"]:
                            tags_enriched += 1
                    log.info("Enriched %d VMs with tag data", tags_enriched)
                else:
                    log.warning("vCenter REST API login failed; proceeding without tags")
            except Exception as e:
                log.warning("Tag enrichment failed: %s", e)

        # ---- Folder-based label derivation ----
        folder_enriched = 0
        if FOLDER_TO_LABEL:
            for vm in vm_list:
                vm["folder_labels"] = derive_folder_labels(vm["folder_segments"])
                if vm["folder_labels"]:
                    folder_enriched += 1

        # ---- Merge derived labels ----
        for vm in vm_list:
            vm["derived_labels"] = merge_labels(vm["tag_labels"], vm["folder_labels"])

        # ---- Fetch PCE workloads ----
        try:
            resp = pce.get("/workloads", params={"max_results": 10000})
            workloads = resp.json() if resp.status_code == 200 else []
        except Exception as e:
            log.error("Failed to fetch workloads: %s", e)
            workloads = []
        if not isinstance(workloads, list):
            workloads = []
        log.info("Fetched %d workloads from PCE", len(workloads))

        # ---- Match engine ----
        matched, vcenter_only, illumio_only = build_matches(vm_list, workloads)
        log.info("Match results: %d matched, %d vcenter-only, %d illumio-only",
                 len(matched), len(vcenter_only), len(illumio_only))

        # ---- Build summary ----
        power_counts = Counter(vm["power_state"] for vm in vm_list)
        summary = {
            "total_vms": len(vm_list),
            "powered_on": power_counts.get("poweredOn", 0),
            "powered_off": power_counts.get("poweredOff", 0),
            "suspended": power_counts.get("suspended", 0),
            "matched": len(matched),
            "vcenter_only": len(vcenter_only),
            "illumio_only": len(illumio_only),
            "with_tags": tags_enriched,
            "with_folder_labels": folder_enriched,
        }

        # ---- Execute sync actions ----
        sync_results = {
            "created": 0,
            "updated": 0,
            "skipped": 0,
            "errors": 0,
            "tags_pushed": 0,
            "details": [],
        }

        do_import = MODE in ("import", "bidirectional")
        do_export = MODE in ("export", "bidirectional")

        # -- Import: create unmanaged workloads for vcenter_only VMs --
        if do_import:
            for vm in vcenter_only:
                if not vm["all_ips"]:
                    sync_results["skipped"] += 1
                    sync_results["details"].append({
                        "vm": vm["name"], "action": "skip",
                        "reason": "no IP address",
                    })
                    continue

                # Resolve label hrefs
                label_hrefs = []
                for key, value in vm["derived_labels"].items():
                    href = ensure_label(pce, key, value)
                    if href:
                        label_hrefs.append({"href": href})

                interfaces = []
                for i, ip in enumerate(vm["all_ips"]):
                    interfaces.append({
                        "address": ip,
                        "friendly_name": f"eth{i}",
                    })

                body = {
                    "name": vm["name"],
                    "hostname": vm["name"],
                    "interfaces": interfaces,
                    "service_provider": "vcenter",
                    "description": f"Imported from vCenter: {VCENTER_HOST}",
                    "labels": label_hrefs,
                }

                try:
                    resp = pce.post("/workloads", json=body)
                    if resp.status_code in (200, 201):
                        sync_results["created"] += 1
                        sync_results["details"].append({
                            "vm": vm["name"], "action": "created",
                            "labels": vm["derived_labels"],
                        })
                    else:
                        sync_results["errors"] += 1
                        sync_results["details"].append({
                            "vm": vm["name"], "action": "error",
                            "reason": f"HTTP {resp.status_code}",
                        })
                except Exception as e:
                    sync_results["errors"] += 1
                    sync_results["details"].append({
                        "vm": vm["name"], "action": "error",
                        "reason": str(e),
                    })

            # Update labels on matched workloads if labels changed
            for match in matched:
                vm = match["vm"]
                wl = match["workload"]
                current_labels = resolve_workload_labels(wl)
                desired_labels = vm["derived_labels"]

                if not desired_labels:
                    sync_results["skipped"] += 1
                    continue

                # Check if labels need updating
                needs_update = False
                for key, value in desired_labels.items():
                    if current_labels.get(key) != value:
                        needs_update = True
                        break

                if not needs_update:
                    sync_results["skipped"] += 1
                    continue

                # Build new labels list: keep existing labels, override where derived
                new_label_hrefs = []
                keys_set = set()
                for key, value in desired_labels.items():
                    href = ensure_label(pce, key, value)
                    if href:
                        new_label_hrefs.append({"href": href})
                        keys_set.add(key)
                # Keep existing labels for keys we don't override
                for lbl in wl.get("labels", []):
                    href = lbl.get("href", "")
                    cached = label_cache.get(href)
                    if cached and cached["key"] not in keys_set:
                        new_label_hrefs.append({"href": href})

                wl_href = wl.get("href", "")
                if not wl_href:
                    continue

                try:
                    resp = pce.put(wl_href, json={"labels": new_label_hrefs})
                    if resp.status_code in (200, 204):
                        sync_results["updated"] += 1
                        sync_results["details"].append({
                            "vm": vm["name"], "action": "updated",
                            "labels": desired_labels,
                        })
                    else:
                        sync_results["errors"] += 1
                        sync_results["details"].append({
                            "vm": vm["name"], "action": "error",
                            "reason": f"PUT {resp.status_code}",
                        })
                except Exception as e:
                    sync_results["errors"] += 1
                    sync_results["details"].append({
                        "vm": vm["name"], "action": "error",
                        "reason": str(e),
                    })

        # -- Export: push Illumio labels to vCenter as tags --
        if do_export and rest_client:
            reverse_tag_map = {v: k for k, v in TAG_MAPPING.items()}
            for match in matched:
                vm = match["vm"]
                wl = match["workload"]
                wl_labels = resolve_workload_labels(wl)

                if not wl_labels:
                    continue

                tags_attached = 0
                for illumio_key, value in wl_labels.items():
                    category_name = reverse_tag_map.get(illumio_key)
                    if not category_name:
                        continue

                    # Check if tag already matches
                    current_tag = vm["tags"].get(category_name, "")
                    normalized_value = value.lower().replace(" ", "-")
                    if current_tag.lower().replace(" ", "-") == normalized_value:
                        continue

                    cat_id = rest_client.ensure_category(category_name)
                    if not cat_id:
                        continue
                    tag_id = rest_client.ensure_tag(cat_id, value)
                    if not tag_id:
                        continue
                    if rest_client.attach_tag(tag_id, vm["moref"]):
                        tags_attached += 1

                if tags_attached > 0:
                    sync_results["tags_pushed"] += tags_attached
                    sync_results["details"].append({
                        "vm": vm["name"], "action": "tags_pushed",
                        "count": tags_attached,
                    })

        # ---- Build VM detail list for dashboard ----
        vm_details = []
        matched_vm_names = {m["vm"]["name"] for m in matched}
        for vm in vm_list:
            match_status = "matched" if vm["name"] in matched_vm_names else "unmatched"
            vm_details.append({
                "name": vm["name"],
                "primary_ip": vm["primary_ip"],
                "all_ips": vm["all_ips"],
                "power_state": vm["power_state"],
                "os": vm["os"],
                "folder_path": vm["folder_path"],
                "tags": vm["tags"],
                "tag_labels": vm["tag_labels"],
                "folder_labels": vm["folder_labels"],
                "derived_labels": vm["derived_labels"],
                "match_status": match_status,
            })

        # ---- Tag mapping summary ----
        tag_mapping_summary = {}
        for category_name, illumio_key in TAG_MAPPING.items():
            values_found = Counter()
            for vm in vm_list:
                tag_val = vm["tags"].get(category_name)
                if tag_val:
                    values_found[tag_val] += 1
            tag_mapping_summary[category_name] = {
                "illumio_key": illumio_key,
                "total_vms": sum(values_found.values()),
                "unique_values": len(values_found),
                "top_values": values_found.most_common(10),
            }

        # ---- Folder mapping summary ----
        folder_mapping_summary = {}
        for depth_str, illumio_key in FOLDER_MAPPING.items():
            values_found = Counter()
            try:
                depth = int(depth_str)
            except ValueError:
                continue
            for vm in vm_list:
                if depth < len(vm["folder_segments"]):
                    values_found[vm["folder_segments"][depth]] += 1
            folder_mapping_summary[f"depth_{depth_str} -> {illumio_key}"] = {
                "illumio_key": illumio_key,
                "total_vms": sum(values_found.values()),
                "unique_values": len(values_found),
                "top_values": values_found.most_common(10),
            }

        # ---- Persist and update global state ----
        duration = round(time.time() - start_time, 2)
        now_iso = datetime.now(timezone.utc).isoformat()

        sync_entry = {
            "timestamp": now_iso,
            "duration": duration,
            "total_vms": len(vm_list),
            "matched": len(matched),
            "vcenter_only": len(vcenter_only),
            "created": sync_results["created"],
            "updated": sync_results["updated"],
            "skipped": sync_results["skipped"],
            "errors": sync_results["errors"],
            "tags_pushed": sync_results["tags_pushed"],
        }

        with state_lock:
            sync_state["last_sync"] = now_iso
            sync_state["last_sync_duration"] = duration
            sync_state["sync_count"] += 1
            sync_state["syncing"] = False
            sync_state["error"] = None
            sync_state["vcenter_status"] = vc_status
            sync_state["vms"] = vm_details
            sync_state["tag_mapping"] = tag_mapping_summary
            sync_state["folder_mapping"] = folder_mapping_summary
            sync_state["sync_results"] = sync_results
            sync_state["summary"] = summary
            sync_state["sync_history"] = (sync_state["sync_history"] + [sync_entry])[-20:]

        save_state()

        log.info("Sync #%d complete in %.1fs: %d VMs, %d matched, %d created, %d updated, %d errors",
                 sync_state["sync_count"], duration, len(vm_list),
                 len(matched), sync_results["created"], sync_results["updated"],
                 sync_results["errors"])

    except Exception as e:
        log.exception("Sync failed")
        with state_lock:
            sync_state["error"] = str(e)
            sync_state["syncing"] = False


def poller_loop(pce, si, rest_client):
    while True:
        try:
            run_sync(pce, si, rest_client)
        except Exception:
            log.exception("Sync loop error")
        time.sleep(SYNC_INTERVAL)


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


def save_state():
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with state_lock:
            data = {
                "last_sync": sync_state.get("last_sync"),
                "sync_count": sync_state.get("sync_count", 0),
                "summary": sync_state.get("summary", {}),
            }
        with open(STATE_FILE, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        log.warning("Failed to save state: %s", e)


def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
            log.info("Loaded persisted state: sync_count=%d", data.get("sync_count", 0))
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("Failed to load state: %s", e)


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vCenter Sync</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}</script>
<style>
body{background:#11111b;color:#cdd6f4;font-family:system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#11111b}
::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
.tab-btn{cursor:pointer;padding:8px 16px;font-size:14px;font-weight:500;border-radius:8px 8px 0 0;border:1px solid transparent;color:#6c7086;transition:all .2s}
.tab-btn:hover{color:#cdd6f4;background:rgba(49,50,68,0.5)}
.tab-btn.active{color:#89b4fa;background:#1e1e2e;border-color:#313244;border-bottom-color:#1e1e2e}
.tab-panel{display:none}
.tab-panel.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeIn .3s ease-out}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.syncing-indicator{animation:pulse 2s infinite}
.lbl-tag{display:inline-block;font-size:0.7rem;padding:2px 6px;border-radius:3px;margin:1px}
</style>
</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-6">

<!-- Header -->
<div class="flex items-center justify-between mb-6 fade-in">
  <div>
    <h1 class="text-2xl font-bold text-white flex items-center gap-2">
      <svg class="w-7 h-7 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/></svg>
      vCenter Sync
    </h1>
    <div class="flex items-center gap-2 mt-1">
      <span id="status-dot" class="w-2.5 h-2.5 rounded-full bg-gray-500"></span>
      <span id="status-text" class="text-sm text-gray-400">Loading...</span>
    </div>
  </div>
  <div class="flex items-center gap-3">
    <span id="mode-badge" class="text-xs px-3 py-1 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30 font-medium"></span>
    <div id="vc-status" class="text-sm"></div>
    <button onclick="triggerSync()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Sync Now</button>
    <a id="export-link" href="/api/export/json" class="bg-dark-700 hover:bg-dark-800 text-gray-300 px-4 py-1.5 rounded text-sm border border-gray-600 inline-block no-underline">Export</a>
  </div>
</div>

<!-- Untested banner -->
<div class="bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-3 mb-6 text-sm text-amber-300">
  <strong>Untested:</strong> This plugin has not been validated against a live vCenter instance.
</div>

<!-- Stats -->
<div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-vms" class="text-3xl font-bold text-blue-400">--</div>
    <div class="text-sm text-gray-500 mt-1">Total VMs</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-matched" class="text-3xl font-bold text-green-400">--</div>
    <div class="text-sm text-gray-500 mt-1">Matched</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-unmanaged" class="text-3xl font-bold text-purple-400">--</div>
    <div class="text-sm text-gray-500 mt-1">vCenter Only</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-tags" class="text-3xl font-bold text-yellow-400">--</div>
    <div class="text-sm text-gray-500 mt-1">Tags Synced</div>
  </div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div id="stat-duration" class="text-3xl font-bold text-red-400">--</div>
    <div class="text-sm text-gray-500 mt-1">Last Duration</div>
  </div>
</div>

<!-- Tabs -->
<div class="mb-0 flex border-b border-gray-700" id="tab-bar">
  <button class="tab-btn active" onclick="showTab('inventory')">VM Inventory</button>
  <button class="tab-btn" onclick="showTab('mapping')">Tag Mapping</button>
  <button class="tab-btn" onclick="showTab('results')">Sync Results</button>
  <button class="tab-btn" onclick="showTab('config')">Configuration</button>
</div>

<!-- Tab: VM Inventory -->
<div id="tab-inventory" class="tab-panel active bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Power State Distribution</h3>
      <div style="height:220px"><canvas id="chart-power"></canvas></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Match Distribution</h3>
      <div style="height:220px"><canvas id="chart-match"></canvas></div>
    </div>
  </div>
  <div class="flex items-center justify-between mb-4">
    <h2 class="text-lg font-semibold text-white">VM Inventory</h2>
    <div class="flex items-center gap-3">
      <select id="vm-filter" onchange="renderVMs()" class="bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white">
        <option value="all">All</option>
        <option value="matched">Matched</option>
        <option value="unmatched">Unmatched</option>
        <option value="poweredOn">Powered On</option>
        <option value="poweredOff">Powered Off</option>
      </select>
      <input type="text" id="vm-search" placeholder="Search name, IP..." oninput="renderVMs()" class="bg-dark-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-500 w-64">
    </div>
  </div>
  <div class="overflow-x-auto max-h-[600px] overflow-y-auto">
    <table class="w-full text-sm">
      <thead class="sticky top-0 bg-dark-800 z-10"><tr class="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
        <th class="px-3 py-2">VM Name</th>
        <th class="px-3 py-2">IPs</th>
        <th class="px-3 py-2">Power</th>
        <th class="px-3 py-2">OS</th>
        <th class="px-3 py-2">vCenter Tags</th>
        <th class="px-3 py-2">Derived Labels</th>
        <th class="px-3 py-2">Status</th>
      </tr></thead>
      <tbody id="vm-table-body"></tbody>
    </table>
  </div>
  <div id="vm-footer" class="mt-3 text-xs text-gray-500"></div>
</div>

<!-- Tab: Tag Mapping -->
<div id="tab-mapping" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <h2 class="text-lg font-semibold text-white mb-4">Tag Category Mapping</h2>
  <div id="tag-mapping-container" class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6"></div>
  <h2 class="text-lg font-semibold text-white mb-4">Folder Path Mapping</h2>
  <div id="folder-mapping-container" class="grid grid-cols-1 lg:grid-cols-2 gap-4"></div>
</div>

<!-- Tab: Sync Results -->
<div id="tab-results" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-4">
      <div id="res-created" class="text-2xl font-bold text-green-400">--</div>
      <div class="text-xs text-gray-500">Created</div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-4">
      <div id="res-updated" class="text-2xl font-bold text-blue-400">--</div>
      <div class="text-xs text-gray-500">Updated</div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-4">
      <div id="res-skipped" class="text-2xl font-bold text-gray-400">--</div>
      <div class="text-xs text-gray-500">Skipped</div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-4">
      <div id="res-errors" class="text-2xl font-bold text-red-400">--</div>
      <div class="text-xs text-gray-500">Errors</div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-4">
      <div id="res-tags" class="text-2xl font-bold text-yellow-400">--</div>
      <div class="text-xs text-gray-500">Tags Pushed</div>
    </div>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Sync History</h3>
      <div style="height:260px"><canvas id="chart-history"></canvas></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Per-VM Sync Detail</h3>
      <div class="max-h-[260px] overflow-y-auto">
        <table class="w-full text-sm">
          <thead class="sticky top-0 bg-dark-900"><tr class="text-left text-xs text-gray-500 uppercase border-b border-gray-700">
            <th class="px-3 py-2">VM</th>
            <th class="px-3 py-2">Action</th>
            <th class="px-3 py-2">Detail</th>
          </tr></thead>
          <tbody id="detail-table-body"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- Tab: Configuration -->
<div id="tab-config" class="tab-panel bg-dark-800 rounded-b-xl border border-t-0 border-gray-700 p-6 mb-8">
  <h2 class="text-lg font-semibold text-white mb-4">Configuration</h2>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Current Settings</h3>
      <div id="config-settings" class="space-y-2"></div>
    </div>
    <div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <h3 class="text-sm font-semibold text-gray-400 mb-3">Tag Category -> Illumio Key</h3>
      <div id="config-tag-mapping" class="space-y-2"></div>
      <h3 class="text-sm font-semibold text-gray-400 mb-3 mt-4">Folder Depth -> Illumio Key</h3>
      <div id="config-folder-mapping" class="space-y-2"></div>
    </div>
  </div>
</div>

<!-- Footer -->
<div class="text-center text-xs text-gray-600 py-4">
  vCenter Sync &mdash; Powered by Illumio Plugger &mdash; Auto-refreshes every 15s
</div>

</div>

<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\/plugins\/[^/]+\/ui/);return m?m[0]:''})();
let stateData=null;
let charts={};
let currentTab='inventory';

function timeAgo(ts){
  if(!ts)return '--';
  const d=(Date.now()-new Date(ts).getTime())/1000;
  if(d<60)return 'just now';
  if(d<3600)return Math.floor(d/60)+'m ago';
  if(d<86400)return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}

function labelsHtml(labels){
  if(!labels||!Object.keys(labels).length)return '<span class="text-gray-600">--</span>';
  return Object.entries(labels).map(([k,v])=>'<span class="lbl-tag bg-blue-900/30 text-blue-300 border border-blue-800/30">'+k+':'+v+'</span>').join(' ');
}

function tagsHtml(tags){
  if(!tags||!Object.keys(tags).length)return '<span class="text-gray-600">--</span>';
  return Object.entries(tags).map(([cat,val])=>'<span class="lbl-tag bg-orange-900/30 text-orange-300 border border-orange-800/30">'+cat+':'+val+'</span>').join(' ');
}

function powerBadge(p){
  if(p==='poweredOn')return '<span class="px-2 py-0.5 rounded text-xs font-medium bg-green-900/30 text-green-400 border border-green-800/30">On</span>';
  if(p==='poweredOff')return '<span class="px-2 py-0.5 rounded text-xs font-medium bg-red-900/30 text-red-400 border border-red-800/30">Off</span>';
  return '<span class="px-2 py-0.5 rounded text-xs font-medium bg-yellow-900/30 text-yellow-400 border border-yellow-800/30">'+p+'</span>';
}

function matchBadge(s){
  if(s==='matched')return '<span class="px-2 py-0.5 rounded text-xs font-medium bg-green-900/30 text-green-400 border border-green-800/30">Matched</span>';
  return '<span class="px-2 py-0.5 rounded text-xs font-medium bg-yellow-900/30 text-yellow-400 border border-yellow-800/30">Unmatched</span>';
}

function actionBadge(a){
  const map={
    created:{c:'#a6e3a1',l:'Created'},
    updated:{c:'#89b4fa',l:'Updated'},
    skip:{c:'#6c7086',l:'Skipped'},
    error:{c:'#f38ba8',l:'Error'},
    tags_pushed:{c:'#f9e2af',l:'Tags Pushed'},
  };
  const info=map[a]||{c:'#6c7086',l:a};
  return '<span class="px-2 py-0.5 rounded text-xs font-medium" style="background:'+info.c+'22;color:'+info.c+';border:1px solid '+info.c+'44">'+info.l+'</span>';
}

// Tabs
function showTab(name){
  currentTab=name;
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  const panel=document.getElementById('tab-'+name);
  if(panel)panel.classList.add('active');
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  const btns=document.querySelectorAll('.tab-btn');
  const tabMap={inventory:0,mapping:1,results:2,config:3};
  if(tabMap[name]!==undefined&&btns[tabMap[name]])btns[tabMap[name]].classList.add('active');
}

// Charts
function initCharts(){
  charts.power=new Chart(document.getElementById('chart-power'),{
    type:'doughnut',
    data:{labels:['Powered On','Powered Off','Suspended'],datasets:[{data:[0,0,0],backgroundColor:['#a6e3a1','#f38ba8','#f9e2af'],borderWidth:0}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'55%',plugins:{legend:{position:'bottom',labels:{color:'#a6adc8',font:{size:11}}}}}
  });
  charts.match=new Chart(document.getElementById('chart-match'),{
    type:'doughnut',
    data:{labels:['Matched','vCenter Only','Illumio Only'],datasets:[{data:[0,0,0],backgroundColor:['#a6e3a1','#89b4fa','#fab387'],borderWidth:0}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'55%',plugins:{legend:{position:'bottom',labels:{color:'#a6adc8',font:{size:11}}}}}
  });
  charts.history=new Chart(document.getElementById('chart-history'),{
    type:'line',
    data:{labels:[],datasets:[
      {label:'Total VMs',data:[],borderColor:'#89b4fa',backgroundColor:'#89b4fa22',fill:true,tension:0.3,pointRadius:3},
      {label:'Created',data:[],borderColor:'#a6e3a1',backgroundColor:'#a6e3a122',fill:false,tension:0.3,pointRadius:2},
      {label:'Updated',data:[],borderColor:'#f9e2af',backgroundColor:'#f9e2af22',fill:false,tension:0.3,pointRadius:2},
      {label:'Errors',data:[],borderColor:'#f38ba8',backgroundColor:'#f38ba822',fill:false,tension:0.3,pointRadius:2},
    ]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#9ca3af',usePointStyle:true,font:{size:11}}}},scales:{x:{grid:{color:'#31324422'},ticks:{color:'#6b7280',font:{size:10}}},y:{grid:{color:'#31324422'},ticks:{color:'#6b7280'},beginAtZero:true}}}
  });
}

function renderAll(data){
  if(!data)return;
  stateData=data;

  // Header status
  const dot=document.getElementById('status-dot');
  const syncing=data.syncing;
  dot.className='w-2.5 h-2.5 rounded-full '+(syncing?'bg-yellow-500 syncing-indicator':data.error?'bg-red-500':'bg-green-500');
  document.getElementById('status-text').textContent=(syncing?'Syncing... ':'')+'Sync #'+(data.sync_count||0)+' · '+timeAgo(data.last_sync)+(data.error?' · Error: '+data.error:'');
  document.getElementById('mode-badge').textContent=data.mode||'analytics';

  const vcSt=data.vcenter_status||'unknown';
  const vcOk=vcSt==='connected';
  document.getElementById('vc-status').innerHTML='<span class="px-2 py-0.5 rounded text-xs '+(vcOk?'bg-green-900/50 text-green-400':'bg-red-900/50 text-red-400')+'">vCenter: '+vcSt+'</span>';

  // Stats
  const s=data.summary||{};
  const sr=data.sync_results||{};
  document.getElementById('stat-vms').textContent=s.total_vms||0;
  document.getElementById('stat-matched').textContent=s.matched||0;
  document.getElementById('stat-unmanaged').textContent=s.vcenter_only||0;
  document.getElementById('stat-tags').textContent=sr.tags_pushed||0;
  document.getElementById('stat-duration').textContent=(data.last_sync_duration||0)+'s';

  // Export link
  document.getElementById('export-link').href=BASE+'/api/export/json';

  // Charts
  charts.power.data.datasets[0].data=[s.powered_on||0,s.powered_off||0,s.suspended||0];
  charts.power.update('none');
  charts.match.data.datasets[0].data=[s.matched||0,s.vcenter_only||0,s.illumio_only||0];
  charts.match.update('none');

  const history=data.sync_history||[];
  charts.history.data.labels=history.map(h=>new Date(h.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}));
  charts.history.data.datasets[0].data=history.map(h=>h.total_vms);
  charts.history.data.datasets[1].data=history.map(h=>h.created);
  charts.history.data.datasets[2].data=history.map(h=>h.updated);
  charts.history.data.datasets[3].data=history.map(h=>h.errors);
  charts.history.update('none');

  renderVMs();
  renderMapping(data);
  renderResults(data);
  renderConfig(data);
}

function renderVMs(){
  if(!stateData)return;
  const search=(document.getElementById('vm-search').value||'').toLowerCase();
  const filter=document.getElementById('vm-filter').value;
  let vms=stateData.vms||[];

  if(filter==='matched')vms=vms.filter(v=>v.match_status==='matched');
  else if(filter==='unmatched')vms=vms.filter(v=>v.match_status==='unmatched');
  else if(filter==='poweredOn')vms=vms.filter(v=>v.power_state==='poweredOn');
  else if(filter==='poweredOff')vms=vms.filter(v=>v.power_state==='poweredOff');

  if(search){
    vms=vms.filter(v=>{
      const s=(v.name||'').toLowerCase()+' '+(v.primary_ip||'')+' '+(v.all_ips||[]).join(' ')+' '+Object.entries(v.derived_labels||{}).map(([k,val])=>k+':'+val).join(' ');
      return s.includes(search);
    });
  }

  const shown=vms.slice(0,500);
  document.getElementById('vm-table-body').innerHTML=shown.map(v=>`
    <tr class="border-b border-gray-700/30 hover:bg-dark-700/30">
      <td class="px-3 py-2"><code class="text-xs">${v.name||'--'}</code></td>
      <td class="px-3 py-2 text-xs text-gray-400 font-mono">${v.all_ips?v.all_ips.slice(0,3).join(', '):'--'}</td>
      <td class="px-3 py-2">${powerBadge(v.power_state)}</td>
      <td class="px-3 py-2 text-xs text-gray-500 max-w-[120px] truncate" title="${v.os||''}">${v.os||'--'}</td>
      <td class="px-3 py-2">${tagsHtml(v.tags)}</td>
      <td class="px-3 py-2">${labelsHtml(v.derived_labels)}</td>
      <td class="px-3 py-2">${matchBadge(v.match_status)}</td>
    </tr>
  `).join('')||'<tr><td colspan="7" class="px-3 py-4 text-center text-gray-600">No VMs discovered yet</td></tr>';
  document.getElementById('vm-footer').textContent='Showing '+shown.length+' of '+vms.length+' VMs';
}

function renderMapping(data){
  const tm=data.tag_mapping||{};
  const entries=Object.entries(tm);
  document.getElementById('tag-mapping-container').innerHTML=entries.length?entries.map(([cat,info])=>{
    const topVals=(info.top_values||[]).slice(0,8);
    return `<div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <div class="flex items-center justify-between mb-3">
        <div>
          <span class="text-sm font-semibold text-orange-400">${cat}</span>
          <span class="text-gray-600 mx-2">-></span>
          <span class="text-sm font-semibold text-blue-400">${info.illumio_key}</span>
        </div>
        <span class="text-xs text-gray-500">${info.total_vms} VMs, ${info.unique_values} values</span>
      </div>
      <div class="space-y-1">${topVals.map(([val,count])=>`
        <div class="flex justify-between text-xs bg-dark-700/50 rounded px-3 py-1">
          <code class="text-gray-300">${val}</code>
          <span class="text-gray-500">${count}</span>
        </div>
      `).join('')}</div>
    </div>`;
  }).join(''):'<div class="col-span-2 text-gray-600 text-sm">No tag data yet. Tags will appear after first sync.</div>';

  const fm=data.folder_mapping||{};
  const fEntries=Object.entries(fm);
  document.getElementById('folder-mapping-container').innerHTML=fEntries.length?fEntries.map(([key,info])=>{
    const topVals=(info.top_values||[]).slice(0,8);
    return `<div class="bg-dark-900 rounded-xl border border-gray-700 p-5">
      <div class="flex items-center justify-between mb-3">
        <div>
          <span class="text-sm font-semibold text-purple-400">${key}</span>
        </div>
        <span class="text-xs text-gray-500">${info.total_vms} VMs, ${info.unique_values} values</span>
      </div>
      <div class="space-y-1">${topVals.map(([val,count])=>`
        <div class="flex justify-between text-xs bg-dark-700/50 rounded px-3 py-1">
          <code class="text-gray-300">${val}</code>
          <span class="text-gray-500">${count}</span>
        </div>
      `).join('')}</div>
    </div>`;
  }).join(''):'<div class="col-span-2 text-gray-600 text-sm">No folder mapping data yet.</div>';
}

function renderResults(data){
  const sr=data.sync_results||{};
  document.getElementById('res-created').textContent=sr.created||0;
  document.getElementById('res-updated').textContent=sr.updated||0;
  document.getElementById('res-skipped').textContent=sr.skipped||0;
  document.getElementById('res-errors').textContent=sr.errors||0;
  document.getElementById('res-tags').textContent=sr.tags_pushed||0;

  const details=sr.details||[];
  document.getElementById('detail-table-body').innerHTML=details.length?details.slice(0,200).map(d=>{
    let detail='';
    if(d.reason)detail=d.reason;
    else if(d.labels)detail=Object.entries(d.labels).map(([k,v])=>k+':'+v).join(', ');
    else if(d.count)detail=d.count+' tags';
    return `<tr class="border-b border-gray-700/30">
      <td class="px-3 py-2"><code class="text-xs">${d.vm||'--'}</code></td>
      <td class="px-3 py-2">${actionBadge(d.action)}</td>
      <td class="px-3 py-2 text-xs text-gray-500">${detail}</td>
    </tr>`;
  }).join(''):'<tr><td colspan="3" class="px-3 py-4 text-center text-gray-600">No sync activity'+(data.mode==='analytics'?' (analytics mode)':'')+'</td></tr>';
}

function renderConfig(data){
  const cfg=data._config||{};
  const settings=[
    ['vCenter Host',cfg.vcenter_host||'--'],
    ['Mode',data.mode||'analytics'],
    ['Sync Interval',cfg.sync_interval||'--'],
    ['Folder to Label',cfg.folder_to_label||'--'],
    ['Power State Filter',cfg.power_state_filter||'--'],
    ['Skip Templates',cfg.skip_templates||'--'],
    ['PCE Host',cfg.pce_host||'--'],
  ];
  document.getElementById('config-settings').innerHTML=settings.map(([k,v])=>`
    <div class="flex items-center justify-between bg-dark-700/50 rounded px-3 py-2">
      <span class="text-xs text-gray-500">${k}</span>
      <span class="text-xs font-mono text-gray-300">${v}</span>
    </div>
  `).join('');

  const tagMap=cfg.tag_mapping||{};
  document.getElementById('config-tag-mapping').innerHTML=Object.entries(tagMap).map(([cat,key])=>`
    <div class="flex items-center justify-between bg-dark-700/50 rounded px-3 py-2">
      <span class="text-xs text-orange-400 font-mono">${cat}</span>
      <span class="text-xs text-gray-600">-></span>
      <span class="text-xs text-blue-400 font-mono">${key}</span>
    </div>
  `).join('')||'<div class="text-xs text-gray-600">Default mapping</div>';

  const folderMap=cfg.folder_mapping||{};
  document.getElementById('config-folder-mapping').innerHTML=Object.entries(folderMap).map(([depth,key])=>`
    <div class="flex items-center justify-between bg-dark-700/50 rounded px-3 py-2">
      <span class="text-xs text-purple-400 font-mono">depth ${depth}</span>
      <span class="text-xs text-gray-600">-></span>
      <span class="text-xs text-blue-400 font-mono">${key}</span>
    </div>
  `).join('')||'<div class="text-xs text-gray-600">Default folder mapping</div>';
}

async function fetchData(){
  try{
    const resp=await fetch(BASE+'/api/state');
    const data=await resp.json();
    renderAll(data);
  }catch(e){console.error('Fetch failed:',e);}
}

async function triggerSync(){
  try{
    document.getElementById('status-dot').className='w-2.5 h-2.5 rounded-full bg-yellow-500 syncing-indicator';
    document.getElementById('status-text').textContent='Sync triggered...';
    await fetch(BASE+'/api/sync',{method:'POST'});
    setTimeout(fetchData,2000);
  }catch(e){console.error(e);}
}

initCharts();
fetchData();
setInterval(fetchData,15000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class VCenterHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, "")

    def _build_config(self):
        return {
            "vcenter_host": VCENTER_HOST or "(not set)",
            "sync_interval": f"{SYNC_INTERVAL}s",
            "folder_to_label": str(FOLDER_TO_LABEL),
            "power_state_filter": POWER_STATE_FILTER,
            "skip_templates": str(SKIP_TEMPLATES),
            "pce_host": os.environ.get("PCE_HOST", "(not set)"),
            "tag_mapping": TAG_MAPPING,
            "folder_mapping": FOLDER_MAPPING,
        }

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/" or path == "":
            self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")

        elif path == "/healthz":
            with state_lock:
                healthy = sync_state["error"] is None
            status = "healthy" if healthy else "degraded"
            self._send(200, json.dumps({
                "status": status,
                "last_sync": sync_state.get("last_sync"),
                "sync_count": sync_state.get("sync_count", 0),
            }))

        elif path == "/api/state":
            with state_lock:
                data = dict(sync_state)
                data["_config"] = self._build_config()
            self._send(200, json.dumps(data, default=str))

        elif path == "/api/vms":
            with state_lock:
                vms = sync_state.get("vms", [])
            self._send(200, json.dumps(vms, default=str))

        elif path == "/api/mapping":
            with state_lock:
                mapping = {
                    "tag_mapping": sync_state.get("tag_mapping", {}),
                    "folder_mapping": sync_state.get("folder_mapping", {}),
                }
            self._send(200, json.dumps(mapping, default=str))

        elif path == "/api/export/json":
            with state_lock:
                data = dict(sync_state)
                data["_config"] = self._build_config()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition",
                             "attachment; filename=vcenter-sync-export.json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data, default=str, indent=2).encode())

        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/sync":
            with state_lock:
                if sync_state["syncing"]:
                    self._send(409, json.dumps({"error": "Sync already in progress"}))
                    return
            threading.Thread(
                target=run_sync,
                args=(pce_client, vcenter_si, vcenter_rest),
                daemon=True,
            ).start()
            self._send(200, json.dumps({"status": "sync_triggered"}))

        else:
            self._send(404, json.dumps({"error": "Not found"}))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

pce_client = None
vcenter_si = None
vcenter_rest = None


def main():
    global pce_client, vcenter_si, vcenter_rest

    log.info("vCenter Sync starting...")
    log.info("Config: mode=%s, vcenter_host=%s, sync_interval=%ds",
             MODE, VCENTER_HOST or "(not set)", SYNC_INTERVAL)
    log.info("Folder-to-label: %s, power_state_filter: %s, skip_templates: %s",
             FOLDER_TO_LABEL, POWER_STATE_FILTER, SKIP_TEMPLATES)
    log.info("Tag mapping: %s", json.dumps(TAG_MAPPING))
    log.info("Folder mapping: %s", json.dumps(FOLDER_MAPPING))

    # Load persisted state
    load_state()

    # Connect to PCE
    pce_client = get_pce()
    log.info("Connected to PCE: %s", pce_client.base_url)

    # Connect to vCenter (pyVmomi)
    if VCENTER_HOST:
        try:
            vcenter_si = connect_vcenter()
            log.info("Connected to vCenter: %s", VCENTER_HOST)
        except Exception as e:
            log.error("Failed to connect to vCenter: %s", e)
            with state_lock:
                sync_state["vcenter_status"] = f"connection error: {str(e)[:80]}"
    else:
        log.warning("VCENTER_HOST not configured -- dashboard will show empty")

    # vSphere REST client (for tags)
    if VCENTER_HOST:
        vcenter_rest = VCenterRESTClient(VCENTER_HOST, VCENTER_USER, VCENTER_PASSWORD, VCENTER_PORT)

    # Initial sync
    if vcenter_si:
        run_sync(pce_client, vcenter_si, vcenter_rest)

    # Background poller
    poller = threading.Thread(
        target=poller_loop,
        args=(pce_client, vcenter_si, vcenter_rest),
        daemon=True,
    )
    poller.start()

    # HTTP server
    server = HTTPServer(("0.0.0.0", HTTP_PORT), VCenterHandler)
    log.info("Dashboard listening on http://0.0.0.0:%d", HTTP_PORT)

    def shutdown(sig, frame):
        log.info("Shutting down...")
        save_state()
        if vcenter_si:
            try:
                Disconnect(vcenter_si)
            except Exception:
                pass
        if vcenter_rest:
            vcenter_rest.logout()
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server.serve_forever()
    log.info("Stopped.")


if __name__ == "__main__":
    main()
