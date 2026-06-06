# Segmentation Drift Detector

**Status:** Proposed
**Priority:** Medium-High — PCI-DSS requires continuous validation
**Complexity:** Low-Medium
**Dependencies:** PCE workloads/policy API, historical snapshots

## Problem

After initial segmentation deployment, policies drift over time. Emergency exceptions become permanent. New applications deploy without policies. Enforcement modes get relaxed and never re-tightened. PCI-DSS 4.0 specifically requires ongoing segmentation validation.

## Solution

A plugin that takes periodic snapshots of segmentation state and alerts when coverage drops, enforcement regresses, or policy exceptions accumulate.

## What It Tracks

### Enforcement Drift
- Workloads moving from `full` → `visibility_only` → `idle` (regression)
- Enforcement coverage percentage trend over time
- Alert when coverage drops below configurable threshold

### Policy Drift
- New "allow all" rules appearing (ams → ams on global scope)
- Disabled rules accumulating (rules turned off and never re-enabled)
- Empty rulesets (created but never populated)
- Rule count growth rate (is policy getting more permissive?)

### Exception Tracking
- Rules tagged as temporary (via description or label) that exceed their expiry
- "Emergency" rules older than N days
- Broad port ranges that were supposed to be narrowed

### Coverage Drift
- New workloads without policy coverage
- Workloads removed from enforcement boundaries
- Label coverage changes (new unlabeled workloads)

## Snapshots and Baselines

### Snapshot (taken every scan)
```json
{
  "timestamp": "2026-05-29T12:00:00Z",
  "enforcement": {
    "full": 312, "selective": 45,
    "visibility_only": 80, "idle": 14
  },
  "coverage_pct": 87.2,
  "total_rulesets": 25,
  "total_rules": 180,
  "disabled_rules": 3,
  "any_any_rules": 0,
  "label_coverage": {"app": 95.1, "env": 93.2, "role": 78.4, "loc": 65.0}
}
```

### Baseline
First snapshot becomes the baseline. Drift is measured against it.
Baseline can be manually reset via dashboard.

## Alert Conditions

| Condition | Severity | Default Threshold |
|-----------|----------|-------------------|
| Enforcement coverage drops | High | < 80% |
| Workload moved to idle | Medium | Any |
| New any-to-any rule | Critical | Any |
| Temporary rule expired | Medium | > 7 days past expiry |
| Label coverage drops | Medium | < 70% for any key |
| Disabled rules accumulate | Low | > 10 |
| Policy rule count spike | Low | > 20% increase in 24h |

## Dashboard

- **Drift Score** — 0-100, weighted composite of all drift metrics
- **Trend Charts** — enforcement %, label %, rule count over weeks/months
- **Active Alerts** — current drift conditions with severity
- **Baseline Comparison** — side-by-side current vs baseline
- **Exception Tracker** — temporary rules with age and expiry status

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL` | `3600` | Seconds between snapshots |
| `SNAPSHOT_RETENTION` | `90` | Days of snapshot history |
| `ENFORCEMENT_THRESHOLD` | `80` | Alert below this coverage % |
| `LABEL_THRESHOLD` | `70` | Alert below this label coverage % |
| `TEMP_RULE_MAX_DAYS` | `7` | Days before temporary rules are flagged |
| `NOTIFICATION_WEBHOOK` | _(empty)_ | Slack/webhook for alerts |

## Why This Matters

- **PCI-DSS 4.0 Req 11.4.5** — continuous segmentation validation
- **Low complexity** — builds on concepts already in posture-report
- **Time-series value** — snapshots enable trend analysis
- **Proactive** — catches problems before auditors do
- **Complements policy-workflow** — drift detection feeds approval workflows
