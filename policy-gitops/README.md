# Policy GitOps

Export Illumio PCE policy to a Git repository as structured YAML, enforce multi-team change review via pull requests (CODEOWNERS), detect drift between Git and the PCE, and provision approved changes back.

**Status:** Skeleton / Work-in-Progress. The HTTP server and dashboard run, but sync logic is stubbed with TODO markers.

## Design

See [DESIGN.md](DESIGN.md) for the full design document covering:

- Repository structure and YAML format
- Sync modes (export, provision, bidirectional)
- Cross-scope rule workflow with CODEOWNERS
- Drift detection approach

## Files

| File | Purpose |
|------|---------|
| `main.py` | Plugin entrypoint — HTTP server, dashboard, stubbed sync classes |
| `requirements.txt` | Python dependencies (illumio, requests, pyyaml, gitpython) |
| `Dockerfile` | Python 3.12 image with git installed |
| `plugin.yaml` | Plugger install manifest |
| `.plugger/metadata.yaml` | Container metadata for plugger discovery |
| `DESIGN.md` | Full design document |

## Quick Start

```bash
# Build
docker build -t policy-gitops:latest .

# Install and run
plugger install plugin.yaml
plugger start policy-gitops
plugger logs policy-gitops -f
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GIT_REPO_URL` | _(required)_ | Git repository URL (HTTPS or SSH) |
| `GIT_TOKEN` | _(required)_ | Personal access token or SSH key path |
| `GIT_BRANCH` | `main` | Target branch |
| `GIT_PROVIDER` | `github` | `github`, `gitlab`, or `bitbucket` |
| `SYNC_MODE` | `export` | `export`, `provision`, or `bidirectional` |
| `SCAN_INTERVAL` | `3600` | Seconds between sync cycles |
| `AUTO_PROVISION` | `false` | Auto-provision draft to active after Git->PCE sync |
| `DRIFT_ALERT` | `true` | Alert on drift between Git and PCE |
