# VEN Fleet Manager

> **Status: Untested**

Fleet-level VEN management dashboard with enforcement progression tracking, version distribution analysis, compatibility checking, agent health monitoring, and batch enforcement operations. Provides a single pane of glass for managing the transition from idle to full enforcement across your entire workload fleet.

## Install

```bash
plugger install ven-fleet-manager
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL` | `3600` | Seconds between fleet scans (minimum 300) |
| `OFFLINE_THRESHOLD_HOURS` | `24` | Hours offline before flagging as concerning |
| `STALE_HEARTBEAT_HOURS` | `48` | Hours since last heartbeat before flagging as stale |
| `TARGET_VEN_VERSION` | _(auto-detect)_ | Target VEN version for upgrade readiness; empty means auto-detect the latest version in the fleet |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification |

## Features

- **Fleet health score** -- Weighted 0-100 composite score based on online percentage (30%), enforcement coverage (25%), version compliance (20%), heartbeat freshness (15%), and compatibility pass rate (10%)
- **Enforcement pipeline funnel** -- Visual funnel showing workload counts at each stage: Idle (with compatibility sub-states), Visibility Only (with policy readiness), Selective, and Full
- **Batch enforcement progression** -- One-click buttons to progress groups of workloads: idle (compat pass) to visibility, visibility (ready) to selective or full, with dry-run support and safety limits
- **Individual workload progression** -- Per-workload action buttons in the progression table to advance individual workloads through enforcement stages
- **Compatibility checking** -- Analyzes agent health data to determine which idle workloads pass compatibility checks and are safe to progress
- **VEN version distribution** -- Pie chart and detailed table showing version counts, percentage of fleet, OS breakdown per version, and upgrade readiness against a target version
- **Agent health monitoring** -- Tracks online/offline split, stale heartbeats, agent errors, and agent warnings with per-workload detail
- **Enforcement coverage by label** -- Stacked bar charts showing enforcement mode distribution broken down by application label and environment label
- **Progression table** -- Filterable, searchable, sortable table of all workloads with mode, compatibility status, time in current mode, labels, online status, version, and action buttons
- **Data export** -- Full fleet snapshot export as JSON for offline analysis
- **Print-friendly** -- CSS print styles strip dark theme for clean printout

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Interactive dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/state` | Full state: fleet data, scan status, error info |
| GET | `/api/fleet` | Fleet summary and enforcement distribution |
| GET | `/api/progression` | Progression pipeline data (idle/visibility sub-states) |
| GET | `/api/health` | Agent health: online/offline, stale heartbeats, errors |
| GET | `/api/versions` | Version distribution, target version, upgrade readiness |
| GET | `/api/export/json` | Download full fleet snapshot as JSON file |
| POST | `/api/scan` | Trigger an immediate fleet scan |
| POST | `/api/progress` | Batch progression operation (see below) |

### Batch Progression API

```bash
# Dry run -- see what would happen
curl -X POST http://localhost:8080/api/progress \
  -H "Content-Type: application/json" \
  -d '{"filter": "idle_compat_pass", "to_mode": "visibility_only", "dry_run": true}'

# Execute progression
curl -X POST http://localhost:8080/api/progress \
  -H "Content-Type: application/json" \
  -d '{"filter": "idle_compat_pass", "to_mode": "visibility_only", "max_batch": 50}'
```

Available filters: `idle_compat_pass`, `idle_compat_fail`, `idle_compat_unknown`, `idle_all`, `visibility_ready`, `visibility_all`.

Valid progression paths: idle to visibility/selective/full, visibility to selective/full, selective to full.

## Dashboard Tabs

- **Overview** -- Health score gauge, key stats, enforcement pipeline funnel, enforcement distribution doughnut chart, and quick action buttons for batch progression
- **Enforcement Progression** -- Filterable workload table with per-row action buttons, search, and sorting by time in mode
- **Agent Health** -- Online/offline doughnut, version bar chart, offline workload table, stale heartbeat table, and agent error/warning table
- **Versions** -- Version distribution pie chart, upgrade readiness summary, and version detail table with OS breakdown
- **Coverage** -- Enforcement mode by application and environment stacked bar charts, plus unlabeled workload count
