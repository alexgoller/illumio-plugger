# PCE Health Monitor

Live health dashboard for Illumio PCE. Polls multiple PCE API endpoints
(health, node availability, workload connectivity) and displays overall
status with per-endpoint detail on an auto-refreshing web page.

## Install

```
plugger install pce-health-monitor
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL` | `30` | Seconds between health checks |
| `PCE_TLS_SKIP_VERIFY` | `false` | Skip TLS certificate verification |
| `PCE_HOST` | — | PCE hostname (set globally by plugger) |
| `PCE_PORT` | `8443` | PCE API port |
| `PCE_API_KEY` | — | PCE API key |
| `PCE_API_SECRET` | — | PCE API secret |
| `PCE_ORG_ID` | `1` | PCE organization ID |

## Features

- Polls `/api/v2/health`, `/api/v2/node_available`, and workload endpoints
- Color-coded status: healthy, degraded, unreachable, error
- Per-endpoint HTTP status and response detail
- Auto-refreshing dashboard (every 15 seconds)
- JSON API at `/api/health` for programmatic access
- Runs as a daemon with configurable poll interval
- Lightweight — 128 MB memory, 0.25 CPU
