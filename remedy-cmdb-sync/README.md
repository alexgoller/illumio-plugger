# Remedy CMDB Sync

> **Status: Untested** — This plugin has not been validated against a live BMC Helix/Remedy instance. The API integration follows BMC Helix CMDB REST API documentation. Please report issues.

Sync BMC Helix/Remedy CMDB configuration items to Illumio labels. Queries CIs via the CMDB REST API, maps CI attributes (business service, environment, location, category) to Illumio labels using configurable rules, and optionally applies labels to PCE workloads.

## Install

```bash
plugger install remedy-cmdb-sync
```

## Modes

- **analytics** (default) — Read-only. Connects to CMDB, discovers CIs, shows what labels would be derived and which PCE workloads match. No changes are made.
- **sync** — Applies derived labels to matching PCE workloads (matched by hostname/IP). Only use after verifying analytics results.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REMEDY_HOST` | _(required)_ | BMC Helix/Remedy server hostname |
| `REMEDY_PORT` | `8443` | Remedy API port |
| `REMEDY_USER` | _(required)_ | Remedy API username |
| `REMEDY_PASSWORD` | _(required)_ | Remedy API password |
| `REMEDY_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for Remedy |
| `REMEDY_CI_CLASS` | `BMC_ComputerSystem` | CMDB CI class to query |
| `REMEDY_NAMESPACE` | `BMC.CORE` | CMDB namespace |
| `REMEDY_DATASET` | `BMC.ASSET` | CMDB dataset ID |
| `REMEDY_QUALIFICATION` | _(empty)_ | Optional CMDB query filter |
| `MODE` | `analytics` | `analytics` or `sync` |
| `SCAN_INTERVAL` | `3600` | Seconds between scans |
| `MAPPING_RULES` | _(built-in)_ | Custom mapping rules as JSON array |

## Default Mapping Rules

| Source Field | Maps To | Logic |
|-------------|---------|-------|
| `Environment` | `env` | Pattern match: prod, dev, test, staging, qa, uat |
| `BusinessService` | `app` | Direct value mapping |
| `Category` | `app` | Fallback if no BusinessService |
| `Site` / `Location` | `loc` | Direct value mapping |
| `ShortDescription` | `role` | Pattern match: web, db, app, dns, mail, etc. |
| `HostName` | `role` | Hostname prefix patterns (lower priority fallback) |

## Custom Mapping Rules

Override defaults via `MAPPING_RULES` env var (JSON array):

```json
[
  {"source": "Environment", "pattern": "(?i)\\bprod\\b", "target": "env", "value": "production", "priority": 10},
  {"source": "BusinessService", "pattern": ".+", "target": "app", "value": "$0", "priority": 10}
]
```

- `source` — CMDB CI attribute name
- `pattern` — Regex to match against the attribute value
- `target` — Illumio label key (role, app, env, loc)
- `value` — Label value (`$0` = matched text, `$1` = first capture group, or literal)
- `priority` — Higher priority rules override lower ones for the same target

## Features

- Queries BMC_ComputerSystem CIs via CMDB REST API with JWT authentication
- Paginated CI fetching (500 per page) for large CMDBs
- Configurable attribute-to-label mapping with regex and priority
- Analytics mode for safe, read-only feasibility analysis
- Sync mode to apply labels to PCE workloads matched by hostname/IP
- Label coverage statistics per label key
- Dashboard with CI browser, match detail, coverage charts
- Creates missing labels automatically during sync
- Preserves existing labels not covered by mapping rules

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/scan` | Current scan state and results |
| POST | `/api/scan/trigger` | Trigger immediate scan |
| GET | `/api/config` | Configuration (no secrets) |
