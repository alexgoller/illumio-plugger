# Application Dependency Intelligence

> **Status: Untested**

Transforms PCE traffic flow data into dependency intelligence for business continuity, compliance, resiliency, and change impact analysis. This plugin goes beyond policy visualization (which Illumination already handles) to answer operational questions: What is the blast radius if this database goes down? Are there single points of failure? Do any production apps depend on non-production services? What will this maintenance window affect?

## Install

```bash
plugger install app-dependency-intel
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOOKBACK_DAYS` | `30` | Days of traffic history to analyze for dependencies |
| `MAX_FLOWS` | `200000` | Maximum traffic flows to process per scan |
| `SCAN_INTERVAL` | `3600` | Seconds between analysis runs (minimum 300) |
| `GROUP_BY` | `app,env` | Label keys for application grouping (comma-separated) |
| `HUB_THRESHOLD` | `4` | Minimum consumers to flag a provider as an infrastructure hub |
| `SPOF_THRESHOLD` | `1` | Maximum provider workloads before SPOF warning triggers |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification |

## Features

- **Dependency graph** -- Interactive D3.js force-directed graph showing consumer/provider relationships between applications, color-coded by environment with drag-and-drop node interaction
- **Blast radius calculator** -- Enter any application (e.g. `shareddb|prod`) to see all directly and transitively dependent applications, total affected workloads, and max dependency depth, with concentric-circle visualization
- **Single point of failure (SPOF) detection** -- Identifies provider applications with only one workload but many consumers, ranked by risk level (critical/high/medium)
- **Circular dependency detection** -- DFS-based cycle detection across the full dependency graph, with normalized cycle paths to avoid duplicates
- **Cross-environment compliance** -- Flags production-to-non-production dependencies as critical violations, with environment heatmap matrix showing connection volumes
- **Change impact planner** -- Enter hostnames or IPs of systems going into a maintenance window and get the full list of affected applications, workload counts, risk level, and recommended notifications
- **Infrastructure hub analysis** -- Ranks providers by consumer count, flags applications serving 4+ consumers, with redundancy assessment based on workload count
- **Application resiliency scores** -- 0-100 score per application factoring in SPOF status, circular dependencies, workload count, and dependency depth
- **Data export** -- Full JSON export with all dependency data and analysis results, plus CSV export of dependency pairs for spreadsheet analysis

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Interactive dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/state` | Full state: dependencies, applications, all analysis results |
| GET | `/api/dependencies` | Raw dependency edge list |
| GET | `/api/applications` | Application node list with inbound/outbound counts |
| GET | `/api/spof` | Single points of failure |
| GET | `/api/cycles` | Circular dependencies |
| GET | `/api/cross-env` | Cross-environment violations |
| GET | `/api/infrastructure` | Infrastructure hubs |
| GET | `/api/export/json` | Download full export as JSON file |
| GET | `/api/export/csv` | Download dependency pairs as CSV file |
| POST | `/api/scan` | Trigger an immediate scan |
| POST | `/api/blast-radius` | Calculate blast radius for a target (`{"target": "app\|env"}`) |
| POST | `/api/impact` | Analyze change impact (`{"targets": ["hostname1", "10.0.1.50"]}`) |

## Dashboard Tabs

- **Dependency Graph** -- Force-directed graph with environment color coding (green=prod, blue=dev, yellow=staging, purple=other) and infrastructure hub highlighting
- **Blast Radius** -- Interactive calculator with concentric-circle visualization showing direct (red ring) and transitive (orange ring) impact
- **Resiliency** -- SPOF table, circular dependency list, and per-application resiliency scores
- **Compliance** -- Cross-environment dependency heatmap and violation table sorted by risk
- **Change Impact** -- Multi-target impact planner with risk assessment and notification recommendations
- **Export** -- JSON and CSV download buttons

## How It Works

1. Fetches all workloads and labels from the PCE
2. Queries traffic flows for the configured lookback period using the Illumio SDK async traffic API
3. Groups flows by consumer `app|env` to provider `app|env` pairs, aggregating services and connection volumes
4. Builds an application dependency graph with inbound/outbound edges
5. Runs five analysis engines: SPOF detection, cycle detection, cross-environment compliance, infrastructure hub identification, and resiliency scoring
6. Serves results via an interactive dashboard and REST API
