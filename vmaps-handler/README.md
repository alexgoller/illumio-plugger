# vmaps-handler

[![Plugin](https://img.shields.io/badge/plugger-vmaps--handler-blue)](https://alexgoller.github.io/illumio-plugger/)
[![Version](https://img.shields.io/badge/version-0.1.0-green)]()
[![Mode](https://img.shields.io/badge/mode-daemon-orange)]()

Import vulnerability scan data into Illumio PCE vulnerability maps (vmaps). Supports Nessus, Qualys, and Tenable file imports and live API pulls.

## What Are Vmaps?

Illumio PCE supports **vulnerability maps** (vmaps) that overlay vulnerability data onto the Illumination map. This lets security teams see not just how workloads communicate, but which workloads have known vulnerabilities on which ports. Vmaps turn the PCE from a segmentation tool into a risk-prioritization platform: you can write policy that factors in vulnerability exposure, not just connectivity.

The PCE vulnerability API is undocumented in the public SDK. This plugin was built by reverse-engineering the API endpoints used by the PCE UI and the `illumio-cli` tool (see the [illumio-cli-reverse-engineer](https://github.com/alexgoller/illumio-cli-reverse-engineer) project for details on the methodology).

## Install

```bash
plugger install vmaps-handler
```

## How It Works

The import pipeline has three stages:

```
Parse / Pull          Match to Workloads       Upload to PCE
+-----------+        +------------------+      +-------------+
| Scanner   | -----> | IP-to-workload   | ---> | POST vulns  |
| data      |        | mapping          |      | PUT report  |
+-----------+        +------------------+      +-------------+
```

1. **Parse**: Read vulnerability data from a scan file or pull from a scanner API. Each scanner produces a list of vulnerability definitions and a list of detections (IP + vulnerability + port).
2. **Match**: Fetch all workloads from the PCE and build an IP-to-workload mapping. Match each detection to a managed workload by IP address. Detections that cannot be matched are dropped (the workload is not in the PCE).
3. **Upload**: POST vulnerability definitions in batches of 1,000, then PUT a vulnerability report with the matched detections. The report appears in the PCE UI under vulnerability maps.

## Supported Scanners

### File-Based Import

Upload a scan export file through the dashboard or mount it into the container.

| Scanner Type | Format | Set `SCANNER_TYPE` to |
|---|---|---|
| Nessus Pro | `.nessus` XML | `nessus-file` |
| Qualys | XML export | `qualys-file` |
| Tenable.sc | CSV export | `tenable-sc-csv` |
| Tenable.io | CSV export | `tenable-io-csv` |

### API-Based Import

Connect directly to a scanner API for automated recurring imports.

| Scanner Type | API | Set `SCANNER_TYPE` to |
|---|---|---|
| Qualys | Qualys API | `qualys-api` |
| Tenable.sc | Tenable.sc REST API | `tenable-sc-api` |
| Tenable.io | Tenable.io / cloud.tenable.com | `tenable-io-api` |

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `SCANNER_TYPE` | No | _(empty)_ | Scanner type (see tables above). If empty, waits for manual trigger or file upload. |
| `IMPORT_FILE` | No | _(empty)_ | Path to scan file inside the container. If empty with file scanner, checks `/data/imports/`. |
| `REPORT_NAME` | No | `plugger-vmaps` | Name for the vulnerability report in the PCE. |
| `AUTHORITATIVE` | No | `false` | If `true`, the report is authoritative and replaces previous data for the same IPs. |
| `POLL_INTERVAL` | No | `3600` | Seconds between automatic import runs. |
| `SCANNER_HOST` | No | _(empty)_ | Hostname/URL for API-based scanners. |
| `SCANNER_USER` | No | _(empty)_ | Username for Qualys API or Tenable.sc API. |
| `SCANNER_PASSWORD` | No | _(empty)_ | Password for Qualys API or Tenable.sc API. |
| `SCANNER_ACCESS_KEY` | No | _(empty)_ | Access key for Tenable.io or Tenable.sc API. |
| `SCANNER_SECRET_KEY` | No | _(empty)_ | Secret key for Tenable.io or Tenable.sc API. |
| `PCE_TLS_SKIP_VERIFY` | No | `true` | Skip TLS certificate verification for the PCE. |

PCE connection variables (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`, `PCE_API_SECRET`) are injected automatically by Plugger.

## Usage Examples

### Nessus File Import

Export a `.nessus` file from Nessus Pro, then either upload through the dashboard or configure for automatic import:

```bash
# Option 1: Upload via dashboard UI
plugger install vmaps-handler
plugger run
# Open dashboard, select "Nessus XML", pick file, click "Upload & Import"

# Option 2: Mount file and run automatically
plugger env set vmaps-handler SCANNER_TYPE=nessus-file
plugger env set vmaps-handler IMPORT_FILE=/data/imports/scan.nessus
plugger run
```

### Qualys API (Automated)

```bash
plugger env set vmaps-handler SCANNER_TYPE=qualys-api
plugger env set vmaps-handler SCANNER_HOST=qualysapi.qualys.com
plugger env set vmaps-handler SCANNER_USER=myuser
plugger env set vmaps-handler SCANNER_PASSWORD=mypassword
plugger env set vmaps-handler POLL_INTERVAL=86400   # daily
plugger run
```

### Tenable.io API (Automated)

```bash
plugger env set vmaps-handler SCANNER_TYPE=tenable-io-api
plugger env set vmaps-handler SCANNER_ACCESS_KEY=abc123...
plugger env set vmaps-handler SCANNER_SECRET_KEY=def456...
plugger env set vmaps-handler POLL_INTERVAL=43200   # every 12h
plugger run
```

### Tenable.sc CSV (File)

```bash
plugger env set vmaps-handler SCANNER_TYPE=tenable-sc-csv
# Place CSV exports in the /data/imports/ volume mount
# The plugin picks up the most recent file automatically
plugger run
```

## Dashboard

<!-- TODO: Add screenshot -->

The dashboard provides:

- **Stats bar**: Vulns defined, total detections, matched, dropped, IPs scanned.
- **Last Import**: Scanner type, status, timestamp, duration, and any errors.
- **Upload panel**: Select scanner type, pick a file, and click "Upload & Import" for one-click file imports.
- **Import History**: Rolling list of the last 20 imports with status, match rate, and timing.

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/state` | Current plugin state (last import, history, stats). |
| `POST` | `/api/import` | Trigger an import. Body: `{"scanner_type": "...", "import_file": "..."}`. |
| `POST` | `/api/upload?filename=X` | Upload a scan file. Raw binary body. Returns `{"path": "..."}`. |
| `GET` | `/healthz` | Health check. |

## Pipeline Internals

The parser modules live in `illumio_vuln_import/`:

| Module | Handles |
|---|---|
| `nessus.py` | Nessus Pro XML (`.nessus` files) |
| `qualys.py` | Qualys XML exports and Qualys API |
| `tenable.py` | Tenable.sc CSV, Tenable.io CSV, Tenable.sc API, Tenable.io API |
| `base.py` | Base class for report processors |
| `pce_client.py` | PCE vulnerability API helpers |

Each processor produces two outputs:
- `vulnerabilities`: dict of `{vuln_id: {href, name, score, ...}}` — the vulnerability definitions.
- `detected_vulnerabilities`: list of `{ip_address, vulnerability_id, port, proto}` — where each vulnerability was found.

## Reverse-Engineering Backstory

The Illumio PCE vulnerability API is not covered by the public Python SDK (`illumio`). The endpoints (`POST /api/v2/orgs/:id/vulnerabilities`, `PUT /api/v2/orgs/:id/vulnerability_reports/:ref`) were reverse-engineered by intercepting the traffic between the `illumio-cli` tool and the PCE. The methodology and findings are documented in the [illumio-cli-reverse-engineer](https://github.com/alexgoller/illumio-cli-reverse-engineer) repository.

This plugin uses raw `requests` calls rather than the `illumio` SDK for vulnerability operations, wrapped in the `VulnPCEClient` class.

## Reports

When an import succeeds with matched detections, the plugin publishes a report to the Plugger output bus:

```
Vulnerability import: 142 findings uploaded
Scanner: nessus-file
- Vulnerabilities defined: 87
- Detections matched: 142/310
- IPs scanned: 45
- Duration: 12.3s
```

## Resources

- Memory limit: 512 MB
- CPU limit: 0.5 cores
