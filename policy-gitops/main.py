#!/usr/bin/env python3
"""
policy-gitops — Export Illumio policy to Git, detect drift, provision from Git.

Serves a dashboard on port 8080 with export status, drift report, and
provisioning controls. Sync logic is stubbed — see TODO markers.

PCE connection: PCE_HOST, PCE_PORT, PCE_ORG_ID, PCE_API_KEY, PCE_API_SECRET
Git connection: GIT_REPO_URL, GIT_TOKEN, GIT_BRANCH, GIT_PROVIDER
"""

import json
import logging
import os
import signal
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


# ===================================================================
# PolicySerializer — convert between PCE objects and YAML files
# ===================================================================

class PolicySerializer:
    """Serialize PCE policy objects to/from YAML files."""

    def __init__(self, pce: PolicyComputeEngine):
        self.pce = pce
        self._label_cache = {}  # href -> {key, value}

    def refresh_label_cache(self):
        """Fetch all labels from PCE and cache href -> key/value mapping."""
        try:
            resp = self.pce.get("/labels")
            if resp.status_code == 200:
                for lbl in resp.json():
                    href = lbl.get("href", "")
                    if href:
                        self._label_cache[href] = {
                            "key": lbl.get("key", ""),
                            "value": lbl.get("value", ""),
                        }
                log.info("Cached %d labels", len(self._label_cache))
        except Exception as e:
            log.warning("Failed to fetch labels: %s", e)

    def export_ruleset_to_yaml(self, ruleset: dict) -> dict:
        """Convert a PCE ruleset JSON object to our YAML-friendly dict.

        Args:
            ruleset: Raw ruleset dict from PCE API.

        Returns:
            Dict ready for yaml.dump() in the format defined in DESIGN.md.
        """
        # TODO: Implement full ruleset -> YAML conversion
        #   - Extract name, description, enabled
        #   - Convert scopes from label HREFs to {key: value} using _label_cache
        #   - Convert each rule: consumers, providers, services
        #   - Handle IP list refs, label group refs
        #   - Strip PCE metadata (href, created_at, updated_at, etc.)
        result = {
            "name": ruleset.get("name", "unknown"),
            "description": ruleset.get("description", ""),
            "enabled": ruleset.get("enabled", True),
            "rules": [],
        }
        for rule in ruleset.get("rules", []):
            result["rules"].append({
                "name": rule.get("description", "unnamed"),
                "consumers": [],   # TODO: resolve consumer label HREFs
                "providers": [],   # TODO: resolve provider label HREFs
                "services": [],    # TODO: resolve service HREFs to port/proto
                "enabled": rule.get("enabled", True),
            })
        return result

    def import_yaml_to_ruleset(self, yaml_data: dict) -> dict:
        """Convert a YAML ruleset dict to a PCE API-compatible ruleset payload.

        Args:
            yaml_data: Dict loaded from a YAML file (our format).

        Returns:
            Dict suitable for POST/PUT to PCE /rule_sets endpoint.
        """
        # TODO: Implement full YAML -> PCE ruleset conversion
        #   - Resolve label key:value pairs to HREFs via PCE API
        #   - Resolve service port/proto to service HREFs (or use inline)
        #   - Build scopes array from scope labels
        #   - Build rules array with resolved consumers/providers/services
        #   - Handle extra-scope (cross-scope) rules
        result = {
            "name": yaml_data.get("name", "unknown"),
            "description": yaml_data.get("description", ""),
            "enabled": yaml_data.get("enabled", True),
            "scopes": [],   # TODO: resolve scope labels to HREFs
            "rules": [],    # TODO: convert rules
        }
        return result

    def export_ip_list_to_yaml(self, ip_list: dict) -> dict:
        """Convert a PCE IP list to YAML-friendly dict.

        Args:
            ip_list: Raw IP list dict from PCE API.

        Returns:
            Dict ready for yaml.dump().
        """
        # TODO: Implement IP list export
        #   - Extract name, description, ip_ranges, fqdns
        #   - Strip PCE metadata
        return {
            "name": ip_list.get("name", "unknown"),
            "description": ip_list.get("description", ""),
            "ip_ranges": ip_list.get("ip_ranges", []),
            "fqdns": ip_list.get("fqdns", []),
        }

    def export_service_to_yaml(self, service: dict) -> dict:
        """Convert a PCE service to YAML-friendly dict.

        Args:
            service: Raw service dict from PCE API.

        Returns:
            Dict ready for yaml.dump().
        """
        # TODO: Implement service export
        #   - Extract name, description, service_ports, windows_services
        #   - Strip PCE metadata
        return {
            "name": service.get("name", "unknown"),
            "description": service.get("description", ""),
            "service_ports": service.get("service_ports", []),
        }


# ===================================================================
# ScopeMapper — map rulesets to directory paths based on scope labels
# ===================================================================

class ScopeMapper:
    """Map Illumio RBAC scopes to Git repository directory structure."""

    def __init__(self, serializer: PolicySerializer):
        self.serializer = serializer

    def map_ruleset_to_directory(self, ruleset: dict) -> str:
        """Determine the directory path for a ruleset based on its scope labels.

        Args:
            ruleset: Raw ruleset dict from PCE API (with scopes).

        Returns:
            Relative path under scopes/ (e.g. "scopes/payments-prod" or "scopes/_global").
        """
        # TODO: Implement scope-to-directory mapping
        #   - Read ruleset["scopes"] — array of label arrays
        #   - If empty scopes: return "scopes/_global"
        #   - For each scope, resolve label HREFs to key:value
        #   - Build directory name from app-env labels (e.g. "payments-prod")
        #   - Detect cross-scope rules and place in cross-scope/ subdirectory
        scopes = ruleset.get("scopes", [])
        if not scopes or scopes == [[]]:
            return "scopes/_global"

        # TODO: Resolve labels and build directory name
        return "scopes/_global"

    def resolve_scope_labels(self, scope_dir: str) -> list:
        """Read _scope.yaml from a directory and return label key:value pairs.

        Args:
            scope_dir: Absolute path to a scope directory in the repo.

        Returns:
            List of {key: value} label dicts defining the scope.
        """
        # TODO: Implement scope label resolution
        #   - Read {scope_dir}/_scope.yaml
        #   - Parse labels section
        #   - Return list of label dicts
        scope_file = Path(scope_dir) / "_scope.yaml"
        if scope_file.exists():
            data = yaml.safe_load(scope_file.read_text())
            return data.get("labels", {})
        return []

    def build_codeowners(self, repo_path: Path) -> str:
        """Generate a CODEOWNERS file from all _scope.yaml definitions.

        Args:
            repo_path: Path to the Git repository root.

        Returns:
            CODEOWNERS file content as string.
        """
        # TODO: Implement CODEOWNERS generation
        #   - Walk scopes/ directories
        #   - Read _scope.yaml for each, extract owners
        #   - Generate CODEOWNERS entries per DESIGN.md format
        #   - Include global rules for _global, ip-lists, services
        return "# Auto-generated by policy-gitops — do not edit manually\n"


# ===================================================================
# GitClient — interact with Git repository
# ===================================================================

class GitClient:
    """Manage Git repository operations (clone, pull, commit, push, PR)."""

    def __init__(self, repo_url: str, token: str, branch: str, provider: str,
                 repo_dir: Path):
        self.repo_url = repo_url
        self.token = token
        self.branch = branch
        self.provider = provider
        self.repo_dir = repo_dir
        self.repo = None  # git.Repo instance, set after clone/open

    def clone(self):
        """Clone the repository to repo_dir, or open if already cloned.

        Sets self.repo to a git.Repo instance.
        """
        # TODO: Implement clone/open
        #   - If repo_dir/.git exists, open existing repo
        #   - Otherwise, clone from repo_url with token-based auth
        #   - For HTTPS: embed token in URL or use credential helper
        #   - For SSH: configure SSH key path
        #   - Checkout the configured branch
        log.info("TODO: Clone/open repo %s -> %s", self.repo_url, self.repo_dir)

    def pull(self) -> bool:
        """Pull latest changes from remote.

        Returns:
            True if new changes were pulled, False if already up to date.
        """
        # TODO: Implement pull
        #   - Fetch from origin
        #   - Fast-forward merge
        #   - Return whether HEAD changed
        log.info("TODO: Pull latest from %s/%s", self.repo_url, self.branch)
        return False

    def commit(self, message: str, files: list = None):
        """Stage and commit changes.

        Args:
            message: Commit message.
            files: List of file paths to stage (relative to repo root).
                   If None, stage all changes.
        """
        # TODO: Implement commit
        #   - Stage specified files (or all if None)
        #   - Create commit with message
        #   - Use bot identity for author/committer
        log.info("TODO: Commit: %s", message)

    def push(self):
        """Push commits to remote."""
        # TODO: Implement push
        #   - Push current branch to origin
        #   - Handle authentication
        log.info("TODO: Push to %s/%s", self.repo_url, self.branch)

    def create_pr(self, title: str, body: str, source_branch: str,
                  target_branch: str = None) -> dict:
        """Create a pull/merge request on the Git provider.

        Args:
            title: PR title.
            body: PR description/body.
            source_branch: Branch with changes.
            target_branch: Base branch (defaults to self.branch).

        Returns:
            Dict with PR details (url, number, etc.)
        """
        target = target_branch or self.branch
        # TODO: Implement PR creation
        #   - GitHub: POST /repos/{owner}/{repo}/pulls via requests
        #   - GitLab: POST /projects/{id}/merge_requests
        #   - Bitbucket: POST /repositories/{workspace}/{repo}/pullrequests
        #   - Use self.token for auth
        log.info("TODO: Create PR '%s' (%s -> %s)", title, source_branch, target)
        return {"url": "", "number": 0, "status": "not_implemented"}

    def get_changed_files(self) -> list:
        """Return list of files changed since last sync.

        Returns:
            List of relative file paths that changed.
        """
        # TODO: Implement change detection
        #   - Compare current HEAD with last known sync commit
        #   - Return list of changed file paths
        log.info("TODO: Detect changed files")
        return []


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

        Args:
            pce: Authenticated PCE client.

        Returns:
            List of drift items: [{type, name, status, git_value, pce_value, detail}]
            status is one of: "in_sync", "drift_modified", "git_only", "pce_only"
        """
        # TODO: Implement full drift detection
        #   - Read all YAML files from Git repo (rulesets, IP lists, services)
        #   - Fetch corresponding objects from PCE active policy
        #   - Compare each object field-by-field (ignoring metadata)
        #   - Report additions (git_only), deletions (pce_only), modifications (drift_modified)
        #   - For modifications, include a diff detail string
        drift_items = []

        # TODO: Compare rulesets
        #   - Walk scopes/ directories in repo
        #   - For each YAML file, find matching PCE ruleset
        #   - Compare rules, services, consumers, providers
        log.info("TODO: Compare rulesets between Git and PCE")

        # TODO: Compare IP lists
        #   - Walk ip-lists/ directory in repo
        #   - For each YAML file, find matching PCE IP list
        log.info("TODO: Compare IP lists between Git and PCE")

        # TODO: Compare services
        #   - Walk services/ directory in repo
        #   - For each YAML file, find matching PCE service
        log.info("TODO: Compare services between Git and PCE")

        return drift_items

    def _compare_objects(self, git_obj: dict, pce_obj: dict,
                         ignore_keys: set = None) -> list:
        """Field-level comparison of two objects.

        Args:
            git_obj: Object as represented in Git YAML.
            pce_obj: Object as fetched from PCE (serialized to our format).
            ignore_keys: Set of keys to skip in comparison.

        Returns:
            List of difference strings, empty if objects match.
        """
        # TODO: Implement recursive field comparison
        #   - Walk both dicts recursively
        #   - Report added, removed, and changed fields
        #   - Skip keys in ignore_keys set
        return []


# ===================================================================
# Sync orchestration
# ===================================================================

def run_export(pce: PolicyComputeEngine, serializer: PolicySerializer,
               scope_mapper: ScopeMapper, git_client: GitClient):
    """Export PCE policy to Git repository (PCE -> Git direction).

    Fetches all rulesets, IP lists, and services from the PCE, converts them
    to YAML, writes to the appropriate directories, and commits.
    """
    log.info("Starting export (PCE -> Git)...")
    now = datetime.now(timezone.utc).isoformat()

    try:
        serializer.refresh_label_cache()

        # TODO: Fetch rulesets from PCE
        #   rulesets = pce.get("/rule_sets", params={"representation": "rule_sets_and_rules"}).json()
        #   For each ruleset:
        #     yaml_data = serializer.export_ruleset_to_yaml(ruleset)
        #     directory = scope_mapper.map_ruleset_to_directory(ruleset)
        #     Write yaml_data to {repo_dir}/{directory}/{name}.yaml
        log.info("TODO: Export rulesets")

        # TODO: Fetch IP lists from PCE
        #   ip_lists = pce.get("/ip_lists").json()
        #   For each IP list:
        #     yaml_data = serializer.export_ip_list_to_yaml(ip_list)
        #     Write to {repo_dir}/ip-lists/{name}.yaml
        log.info("TODO: Export IP lists")

        # TODO: Fetch services from PCE
        #   services = pce.get("/services").json()
        #   For each service:
        #     yaml_data = serializer.export_service_to_yaml(service)
        #     Write to {repo_dir}/services/{name}.yaml
        log.info("TODO: Export services")

        # TODO: Commit and push
        #   git_client.commit("policy-gitops: export from PCE at {timestamp}")
        #   git_client.push()
        log.info("TODO: Commit and push export")

        with state_lock:
            app_state["last_export"] = now
            app_state["export_count"] += 1
            # TODO: populate exported_objects counts
            app_state["exported_objects"] = {"rulesets": 0, "ip_lists": 0, "services": 0}
            app_state["last_error"] = None

        log.info("Export complete (stubbed)")

    except Exception as e:
        log.exception("Export failed")
        with state_lock:
            app_state["last_error"] = f"Export failed: {e}"


def run_provision(pce: PolicyComputeEngine, serializer: PolicySerializer,
                  scope_mapper: ScopeMapper, git_client: GitClient):
    """Provision policy from Git to PCE (Git -> PCE direction).

    Reads YAML files from the repo, resolves label/service references,
    creates or updates rulesets on the PCE, and optionally provisions.
    """
    log.info("Starting provision (Git -> PCE)...")
    now = datetime.now(timezone.utc).isoformat()

    try:
        # TODO: Pull latest from Git
        #   git_client.pull()
        log.info("TODO: Pull latest")

        # TODO: Read YAML files from repo
        #   Walk scopes/, ip-lists/, services/ directories
        #   Parse each YAML file
        log.info("TODO: Read YAML files")

        # TODO: For each ruleset YAML:
        #   payload = serializer.import_yaml_to_ruleset(yaml_data)
        #   Check if ruleset exists on PCE (by name match)
        #   If exists: PUT to update
        #   If not: POST to create
        log.info("TODO: Create/update rulesets on PCE")

        # TODO: If AUTO_PROVISION:
        #   pce.post("/sec_policy", json={"update_description": "policy-gitops provision"})
        log.info("TODO: Provision draft -> active")

        provision_entry = {
            "timestamp": now,
            "objects": 0,
            "status": "stubbed",
            "detail": "Provisioning not yet implemented",
        }

        with state_lock:
            app_state["last_provision"] = now
            app_state["provision_count"] += 1
            app_state["provision_history"].append(provision_entry)
            # Keep last 50 entries
            if len(app_state["provision_history"]) > 50:
                app_state["provision_history"] = app_state["provision_history"][-50:]
            app_state["last_error"] = None

        log.info("Provision complete (stubbed)")

    except Exception as e:
        log.exception("Provision failed")
        with state_lock:
            app_state["last_error"] = f"Provision failed: {e}"


def run_drift_check(pce: PolicyComputeEngine, detector: DriftDetector):
    """Run drift detection between Git and PCE."""
    log.info("Running drift detection...")
    now = datetime.now(timezone.utc).isoformat()

    try:
        drift_items = detector.compare_git_vs_pce(pce)

        with state_lock:
            app_state["drift_items"] = drift_items
            app_state["last_drift_check"] = now
            app_state["drift_count"] = len(drift_items)
            app_state["last_error"] = None

        log.info("Drift check complete: %d items", len(drift_items))

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
                app_state["last_error"] = "Sync cycle failed — see logs"

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

        elif path == "/":
            self.send_html(DASHBOARD_HTML)

        else:
            self.send_error(404)

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/api/export":
            # Run export in a background thread so we don't block the HTTP response
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
