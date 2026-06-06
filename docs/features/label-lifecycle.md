# Label Lifecycle Manager

**Status:** Proposed
**Priority:** High — labeling is #1 adoption blocker
**Complexity:** Medium
**Dependencies:** PCE labels/workloads API

## Problem

Labeling is the #1 blocker for Illumio adoption according to Illumio's own blog posts and PeerSpot reviews. Customers struggle with: orphaned labels, inconsistent naming, missing labels on workloads, labels out of sync with CMDB, and no governance over label creation.

## Solution

A plugin that provides label hygiene analytics, governance, and bulk operations.

## Features

### 1. Label Hygiene Dashboard
- **Orphaned labels** — labels with zero workloads assigned
- **Duplicate/similar labels** — "Production" vs "production" vs "prod" vs "Prod"
- **Naming convention violations** — labels not matching a configurable regex pattern
- **Empty label keys** — workloads with some labels but missing required keys (RAEL)

### 2. Label Coverage Report
- Per-key coverage: what % of workloads have app, env, role, loc assigned
- Fully labeled workloads vs partially labeled vs unlabeled
- Coverage by environment (is prod better labeled than dev?)
- Coverage trend over time (is it getting better?)

### 3. Auto-Suggestion
For unlabeled workloads, suggest labels based on:
- **Hostname patterns** — `web01-prod` → role:web, env:prod
- **Traffic patterns** — listens on 5432 → role:db
- **Peer labels** — workloads in the same subnet as labeled workloads
- **CMDB/AD data** — if ad-label-sync or remedy-cmdb-sync is running

### 4. Naming Convention Enforcement
```yaml
# label-rules.yaml
conventions:
  app:
    pattern: "^[a-z][a-z0-9-]{1,30}$"
    description: "Lowercase alphanumeric with hyphens, 2-31 chars"
  env:
    allowed_values: ["prod", "staging", "dev", "test", "qa", "uat"]
  role:
    pattern: "^[a-z][a-z0-9-]{1,20}$"
  loc:
    pattern: "^[a-z]{2}-[a-z]+-[0-9]$"
    description: "Region format: us-east-1"
```

### 5. Label Change Audit
- Who changed what label when (from PCE events)
- Approval workflow hooks (integrate with policy-workflow)
- Bulk change tracking

### 6. Bulk Operations
- CSV upload: hostname,app,env,role,loc → apply to PCE
- Regex-based relabeling: "all hostnames matching ^web → role:web"
- Merge labels: consolidate "Production" + "production" + "prod" into "prod"
- Rename labels: "Web Server" → "web"

## Dashboard

### Overview Tab
- 4 stat cards: total labels, orphaned, coverage %, naming violations
- Coverage bar chart (per key)
- Orphan list with delete buttons

### Coverage Tab
- Per-key table: key, total workloads, labeled, unlabeled, % coverage
- Drill-down: click a key to see unlabeled workloads
- Filter by env/app to see coverage per scope

### Hygiene Tab
- Orphaned labels with workload count (0) and delete button
- Duplicate/similar label groups with merge suggestions
- Naming violations with suggested corrections

### Suggestions Tab
- Unlabeled workloads with auto-suggested labels
- Confidence score per suggestion
- Apply button (individual or bulk)

### Bulk Operations Tab
- CSV upload form
- Regex-based operation builder
- Merge/rename wizard
- Dry-run toggle

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL` | `3600` | Seconds between scans |
| `REQUIRED_KEYS` | `app,env,role,loc` | Required label keys for coverage |
| `CONVENTION_FILE` | `/data/label-rules.yaml` | Naming convention rules |
| `ENABLE_BULK_OPS` | `false` | Enable write operations (delete, merge, rename) |
| `SUGGESTION_SOURCES` | `hostname,traffic` | Sources for auto-suggestion |

## Why This Matters

- **#1 adoption blocker** — labeling is where every deployment gets stuck
- **Governance** — prevents label sprawl and inconsistency
- **Automation** — bulk operations save weeks of manual work
- **Visibility** — "how healthy is our labeling?" at a glance
- **Continuous** — not a one-time cleanup, ongoing monitoring
