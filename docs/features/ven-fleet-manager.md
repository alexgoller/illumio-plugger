# VEN Fleet Manager

**Status:** Proposed
**Priority:** High — biggest operational pain at scale
**Complexity:** Medium
**Dependencies:** PCE workloads/VEN API only

## Problem

Customers with 5,000-50,000+ workloads struggle with VEN version sprawl, upgrade orchestration, coverage gaps, and fleet health monitoring. The PCE shows individual VEN status but lacks fleet-level analytics, upgrade planning dashboards, and coverage reports. PeerSpot reviews specifically call out upgrade management as painful.

## Solution

A plugin that provides fleet-level visibility and management for Illumio VEN agents.

## Dashboard Views

### 1. Fleet Overview
- Total workloads, managed vs unmanaged
- Online vs offline percentage
- Enforcement mode distribution (idle / visibility / selective / full)
- VEN version distribution (pie chart + table)

### 2. Version Distribution
- Pie/bar chart of VEN versions across the fleet
- Per-version: count, percentage, OS breakdown
- Highlight: oldest version, newest version, recommended version
- Trend over time (if historical snapshots stored)

### 3. Coverage Gaps
- Workloads in CMDB/cloud inventory that lack VEN pairing
- Requires: integration with cloud provider APIs or CMDB
- Or simpler: workloads with `managed: false` or no agent info
- Grouped by app/env/loc labels

### 4. Upgrade Readiness
- Per-version: which OS versions, known incompatibilities
- Upgrade path recommendations (current → target version)
- Staged rollout planning: upgrade N% per wave
- Pre-flight checks: disk space, connectivity, OS compatibility

### 5. Agent Health
- Offline agents (with duration)
- Stale heartbeats (>24h, >48h, >7d)
- Agent error rates
- Heartbeat latency distribution
- Disconnection trends over time

### 6. License Utilization
- VEN count vs license entitlement
- Trend projection (at current growth, when do we hit the limit?)
- By enforcement mode (full enforcement uses different license tier)

## Data Sources

All from the PCE REST API — no external dependencies:

| Endpoint | Data |
|----------|------|
| `GET /workloads` | Hostname, OS, enforcement mode, managed, labels |
| `GET /workloads/{id}` | Agent details, version, status |
| Workload `agent` field | VEN version, last heartbeat, errors |
| Workload `online` field | Online/offline status |
| `GET /vens` (if available) | Direct VEN endpoint on newer PCEs |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL` | `3600` | Seconds between fleet scans |
| `OFFLINE_THRESHOLD_HOURS` | `24` | Hours offline to flag as concerning |
| `STALE_HEARTBEAT_HOURS` | `48` | Hours since heartbeat to flag as stale |
| `TARGET_VEN_VERSION` | _(auto)_ | Target version for upgrade readiness |
| `STORE_HISTORY` | `true` | Keep historical snapshots for trends |
| `HISTORY_RETENTION_DAYS` | `90` | Days of historical data to keep |

## Report Output

### Fleet Health Score (0-100)
Weighted score based on:
- Online percentage (weight: 30)
- Enforcement coverage (weight: 25)
- Version currency (weight: 20)
- Heartbeat freshness (weight: 15)
- Label coverage (weight: 10)

### Exportable Reports
- JSON report for automation
- CSV for fleet management tools
- Dashboard with print stylesheet for management reporting

## Why This Matters

- **Every large deployment needs this** — 5K+ workloads = fleet management challenges
- **PCE-only data** — no external integrations needed
- **Upgrade planning** — VEN upgrades are the #1 operational pain point
- **License management** — "are we within our entitlement?"
- **Health visibility** — "how healthy is our VEN fleet right now?"
- **Trend tracking** — "is our fleet getting healthier or degrading?"
