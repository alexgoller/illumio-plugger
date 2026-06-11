# PCE Health Monitor

Live health dashboard for Illumio PCE. Polls multiple PCE API endpoints
(health, node availability, workload connectivity) and displays overall
status with per-endpoint detail on an auto-refreshing web page.

## Install

```bash
plugger install pce-health-monitor
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `120` | Seconds between health checks |
| `PCE_TLS_SKIP_VERIFY` | `false` | Skip TLS certificate verification |

## Features

- Polls `/api/v2/health`, `/api/v2/node_available`, and workload endpoints
- Color-coded overall status: healthy, degraded, unreachable, error
- Per-endpoint breakdown showing HTTP status codes and response detail
- Auto-refreshing dashboard (every 15 seconds)
- JSON API at `/api/health` for programmatic access and external monitoring integration
- Runs as a daemon with configurable poll interval
- Lightweight -- 128 MB memory, 0.25 CPU

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Health status dashboard |
| GET | `/healthz` | Plugin health check |
| GET | `/api/health` | Full health state as JSON (status, endpoints, last check time, errors) |
