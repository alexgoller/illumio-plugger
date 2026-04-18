# Traffic Reporter

Interactive traffic flow analysis dashboard for Illumio PCE. Queries traffic
flows via the Illumio SDK and visualizes policy decisions, top talkers,
services, and blocked flows using Chart.js with Sankey diagrams.

## Install

```
plugger install traffic-reporter
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL` | `300` | Seconds between traffic polls |
| `LOOKBACK_HOURS` | `24` | Hours of traffic history to query |
| `MAX_RESULTS` | `10000` | Maximum flows per query |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification |
| `PCE_HOST` | — | PCE hostname (set globally by plugger) |
| `PCE_PORT` | `8443` | PCE API port |
| `PCE_API_KEY` | — | PCE API key |
| `PCE_API_SECRET` | — | PCE API secret |
| `PCE_ORG_ID` | `1` | PCE organization ID |

## Features

- Policy decision breakdown (allowed, blocked, potentially blocked, unknown)
- Sankey diagram showing source-to-service-to-destination flow paths
- Top sources, destinations, and services bar charts
- Blocked flow detail table with connection counts
- Label-aware grouping by app|env for Sankey nodes
- Auto-refreshing dashboard (every 30 seconds)
- JSON API at `/api/traffic` for programmatic access
- Uses `illumio` Python SDK for traffic analysis queries
