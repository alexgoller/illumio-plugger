# PCE Posture Report

Scheduled security posture scoring for Illumio PCE. Runs on a cron schedule
(every 6 hours by default), collects workloads, labels, rulesets, and policy
data, computes a 0-100 posture score, and generates HTML and JSON reports.

## Install

```
plugger install pce-posture-report
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification |
| `PCE_HOST` | — | PCE hostname (set globally by plugger) |
| `PCE_PORT` | `8443` | PCE API port |
| `PCE_API_KEY` | — | PCE API key |
| `PCE_API_SECRET` | — | PCE API secret |
| `PCE_ORG_ID` | `1` | PCE organization ID |
| `DATA_DIR` | `/data` | Directory for report output |

The default cron schedule is `0 */6 * * *` (every 6 hours).

## Features

- Posture score (0-100) based on enforcement coverage, label coverage, active policy, and managed workloads
- Enforcement mode breakdown (full, selective, visibility only, idle)
- Label coverage analysis (role, app, env, loc, fully labeled, unlabeled)
- OS type distribution across workloads
- Policy summary: active/draft rulesets, rules, IP lists, services
- Generates timestamped HTML and JSON reports with `latest` symlinks
- Runs as a cron plugin — no persistent daemon required
- Uses `illumio` Python SDK for PCE connectivity
