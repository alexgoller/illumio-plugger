# Stale Workloads

Discovers workloads that are offline, have not sent a heartbeat, or show
no traffic activity. Groups results by app|env labels and provides
optional cleanup actions (unpair managed workloads, delete unmanaged ones).

## Install

```
plugger install stale-workloads
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL` | `600` | Seconds between staleness checks |
| `STALE_DAYS` | `7` | Days without heartbeat to consider stale |
| `OFFLINE_HOURS` | `24` | Hours offline to flag as stale |
| `CHECK_TRAFFIC` | `true` | Also check for zero-traffic workloads |
| `TRAFFIC_LOOKBACK_HOURS` | `168` | Traffic lookback window (default 7 days) |
| `ENABLE_CLEANUP` | `false` | Enable unpair/delete actions via the dashboard |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification |

## Features

- Detects stale workloads by heartbeat age, offline duration, and traffic absence
- Groups stale workloads by app|env labels
- Breakdown by staleness reason (no heartbeat, offline, no traffic)
- Dashboard with per-workload detail and cleanup buttons
- Cleanup actions: unpair managed workloads, delete unmanaged workloads
- Cleanup is disabled by default; set `ENABLE_CLEANUP=true` to enable
- JSON API for programmatic access
- Uses `illumio` Python SDK for PCE connectivity and traffic analysis
