# Policy Diff

Git-like policy change tracker for Illumio PCE. Compares draft vs active
policy across rulesets, IP lists, services, label groups, virtual services,
and firewall settings, showing field-level diffs with user attribution.

## Install

```bash
plugger install policy-diff
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `3600` | Seconds between policy comparisons |
| `EVENT_LOOKBACK_HOURS` | `72` | Hours of audit events to fetch for user attribution |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification |

Snapshots and event history are persisted to the `/data` volume.

## Features

- Tracks rulesets, IP lists, services, label groups, virtual services, and firewall settings
- Field-level diffs between draft and active policy
- Snapshot history with content hashing for change detection
- User attribution via PCE audit events
- Added/modified/deleted/unchanged summary counts
- Interactive timeline UI with diff detail view
- Persistent snapshot storage across restarts
- Uses `illumio` Python SDK for PCE connectivity

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Interactive policy diff dashboard with timeline |
| GET | `/healthz` | Health check |
| GET | `/api/diff` | Full diff state as JSON (current diffs, snapshot history, audit events) |
