# Application Dependency Intelligence

**Status:** Proposed (redesigned)
**Priority:** High — fills a gap Illumio doesn't cover today
**Complexity:** Medium-High
**Dependencies:** PCE traffic flows API, workloads API

## What Illumio Has Today

Illumio Illumination provides **flow maps between label tuples** — great for writing segmentation policy (who should talk to whom). That's its purpose and it does it well.

## What's Missing

The dependency data that Illumio collects is far more valuable than just policy writing. Enterprises need it for:

### 1. Business Continuity Management (BCM)
- "If the payments database goes down, which applications are affected?"
- "What's the blast radius if this network segment is isolated?"
- "Which applications are single points of failure — only one workload serving all consumers?"

### 2. Compliance & Audit
- "Prove that PCI CDE applications don't depend on non-CDE systems"
- "Show me all dependencies crossing environment boundaries (prod → dev)"
- "Which applications depend on systems outside our compliance scope?"

### 3. Resiliency Analysis
- "Which applications have circular dependencies?"
- "What's the critical path — if app A goes down, what's the cascade?"
- "Which applications have redundant communication paths vs single points of failure?"

### 4. Change Impact Analysis
- "If we migrate this database, which 15 applications will be affected?"
- "Before this maintenance window: what depends on these 3 servers?"
- "If we decommission this legacy app, who still talks to it?"

### 5. Architecture Documentation
- "Generate an up-to-date application architecture diagram from real traffic"
- "Show me tier-level dependencies (web → app → db → cache) per application"
- "Document the actual architecture vs the intended architecture"

### 6. Cost & Licensing
- "Which applications use this shared infrastructure (shared DB, message queue)?"
- "How many consumers does each shared service have?" (for license allocation)

## How This Differs from Illumination

| Illumination | This Plugin |
|-------------|-------------|
| Flow-level: IP-to-IP with labels | Dependency-level: app-to-app relationships |
| Used for policy writing | Used for BCM, compliance, resiliency, change management |
| Interactive in PCE GUI | Exportable reports, dashboards, APIs |
| Point-in-time view | Historical trends (did dependencies change?) |
| Per-scope (one app at a time) | Cross-scope (entire organization) |
| No blast radius analysis | Blast radius / impact analysis |
| No redundancy analysis | Single point of failure detection |

## Solution

A plugin that transforms PCE traffic flow data into **dependency intelligence** — structured, queryable, exportable dependency maps with built-in analysis for BCM, compliance, resiliency, and change impact.

## Core Data Model

### Dependency (not flow)

A dependency is a **directional relationship** between two application components:

```json
{
  "consumer": {"app": "payments", "env": "prod", "role": "processing"},
  "provider": {"app": "shareddb", "env": "prod", "role": "db"},
  "services": [
    {"name": "PostgreSQL", "port": 5432, "proto": "tcp"}
  ],
  "strength": "strong",
  "first_seen": "2026-01-15T10:00:00Z",
  "last_seen": "2026-06-07T08:30:00Z",
  "connection_volume": 45230,
  "consumer_workload_count": 3,
  "provider_workload_count": 2,
  "cross_environment": false,
  "cross_application": true,
  "infrastructure": false
}
```

Dependencies are aggregated from flows, deduplicated, and enriched with:
- **Strength**: strong (continuous traffic), moderate (periodic), weak (rare/one-time)
- **Classification**: cross-app, cross-env, infrastructure, intra-scope
- **History**: first/last seen, volume trends

### Application Node

```json
{
  "app": "payments",
  "env": "prod",
  "workload_count": 12,
  "roles": ["web", "processing", "db", "cache"],
  "depends_on": ["shareddb-prod", "messaging-prod", "dns-infra", "monitoring-infra"],
  "depended_by": ["ordering-prod", "frontend-prod"],
  "dependency_count_outbound": 4,
  "dependency_count_inbound": 2,
  "is_infrastructure": false,
  "tier": "tier-1"
}
```

## Analysis Engines

### 1. Blast Radius Analysis
**Input:** A workload, application, or network segment
**Output:** All applications that would be affected if it becomes unavailable

```
POST /api/blast-radius
{"target": "shareddb-prod"}

Response:
{
  "target": "shareddb-prod",
  "directly_affected": ["payments-prod", "ordering-prod", "frontend-prod"],
  "transitively_affected": ["mobile-api-prod"],
  "total_affected_workloads": 47,
  "total_affected_applications": 4,
  "critical_path": true,
  "diagram": "shareddb-prod → payments-prod → mobile-api-prod"
}
```

### 2. Single Point of Failure Detection
Find providers with only one workload serving multiple consumers:

```
{
  "spof": [
    {
      "provider": {"app": "shareddb", "env": "prod", "role": "db"},
      "workload_count": 1,
      "consumer_count": 5,
      "consumers": ["payments", "ordering", "frontend", "reports", "mobile-api"],
      "risk": "critical"
    }
  ]
}
```

### 3. Circular Dependency Detection
Find cycles in the dependency graph:

```
{
  "cycles": [
    {
      "path": ["app-a-prod", "app-b-prod", "app-c-prod", "app-a-prod"],
      "services": ["8080/tcp", "5432/tcp", "443/tcp"],
      "risk": "Circular dependency may cause cascading failures"
    }
  ]
}
```

### 4. Environment Boundary Analysis
Find dependencies that cross environment boundaries:

```
{
  "cross_env_dependencies": [
    {
      "consumer": "payments-prod",
      "provider": "testdb-dev",
      "services": ["5432/tcp"],
      "risk": "critical",
      "violation": "Production depends on development database"
    }
  ]
}
```

### 5. Change Impact Analysis
Before a maintenance window or migration:

```
POST /api/impact
{"targets": ["db01.shareddb.prod", "db02.shareddb.prod"], "action": "maintenance"}

Response:
{
  "affected_applications": 5,
  "affected_workloads": 47,
  "affected_services": ["PostgreSQL (5432/tcp)"],
  "recommended_notification": [
    "payments-team (3 workloads depend on these servers)",
    "ordering-team (2 workloads)"
  ],
  "maintenance_window_risk": "high"
}
```

### 6. Infrastructure Hub Analysis
Identify shared services and their consumer base:

```
{
  "infrastructure_hubs": [
    {"app": "dns", "consumers": 45, "type": "infrastructure", "redundancy": "high"},
    {"app": "shareddb", "consumers": 5, "type": "shared-service", "redundancy": "low"},
    {"app": "monitoring", "consumers": 42, "type": "infrastructure", "redundancy": "medium"}
  ]
}
```

## Dashboard Views

### 1. Dependency Overview
- Total applications, total dependencies, cross-env count, infrastructure count
- Dependency graph (D3.js force-directed) — click to drill into any node
- Filter by: environment, application, dependency type

### 2. Blast Radius Calculator
- Input: select an application or workload
- Output: visual blast radius map showing direct and transitive impact
- Color-coded by severity (red=critical path, yellow=moderate, gray=infrastructure)

### 3. Resiliency Report
- Single points of failure table with risk rating
- Circular dependencies list
- Redundancy scores per application
- Recommendations (add redundancy, break cycles)

### 4. Compliance View
- Cross-environment dependency matrix (heatmap)
- CDE boundary violations (prod→dev, CDE→non-CDE)
- Dependencies on unmanaged/unlabeled systems

### 5. Change Impact Planner
- Select workloads/applications being changed
- See affected applications with team contacts
- Generate notification list for maintenance windows
- Export as change request document

### 6. Architecture Report
- Per-application tier diagram (auto-discovered)
- Full organization dependency map (exportable SVG/PNG)
- Trend: dependency count over time (are we getting more or less coupled?)

## Export Formats

- **JSON** — full dependency data for automation
- **CSV** — dependency pairs for spreadsheet analysis
- **SVG/PNG** — visual graphs for presentations
- **PDF** — formatted report for management/auditors
- **CMDB-compatible** — CI relationships for ServiceNow/BMC

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOOKBACK_DAYS` | `30` | Days of traffic to analyze |
| `MAX_FLOWS` | `200000` | Max flows to process |
| `SCAN_INTERVAL` | `3600` | Seconds between analysis runs |
| `HUB_THRESHOLD` | `4` | Min consumers to flag as infrastructure |
| `SPOF_THRESHOLD` | `1` | Max provider workloads before SPOF warning |
| `GROUP_BY` | `app,env` | Label keys for application grouping |
| `STORE_HISTORY` | `true` | Keep historical dependency snapshots |
| `HISTORY_RETENTION_DAYS` | `90` | Days of history to retain |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/dependencies` | Full dependency list |
| GET | `/api/applications` | Application node list with dependency counts |
| GET | `/api/applications/{app-env}` | Single application detail |
| POST | `/api/blast-radius` | Blast radius analysis |
| POST | `/api/impact` | Change impact analysis |
| GET | `/api/spof` | Single points of failure |
| GET | `/api/cycles` | Circular dependencies |
| GET | `/api/cross-env` | Cross-environment violations |
| GET | `/api/infrastructure` | Infrastructure hub analysis |
| GET | `/api/export/{format}` | Export (json, csv, svg) |

## Why This Matters

- **Fills a real gap** — Illumio has the data but doesn't surface it for BCM/compliance/resiliency
- **Unique value** — no other micro-segmentation tool does blast radius or SPOF analysis from traffic
- **Uses existing data** — no new agents, no new infrastructure, just PCE traffic flows
- **Multiple audiences** — BCM team, compliance, architects, change management, management
- **Replaces expensive tools** — Faddom ($20K+), ServiceNow Discovery, manual architecture docs
- **Demo differentiator** — "show me what breaks if this goes down" is instantly compelling
