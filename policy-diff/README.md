# Policy Diff

Git-like policy change tracker for Illumio PCE. Compares draft vs active
policy across rulesets, IP lists, services, label groups, virtual services,
and firewall settings, showing field-level diffs with user attribution.

## Install

```
plugger install policy-diff
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL` | `300` | Seconds between policy checks |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification |
| `PCE_HOST` | — | PCE hostname (set globally by plugger) |
| `PCE_PORT` | `8443` | PCE API port |
| `PCE_API_KEY` | — | PCE API key |
| `PCE_API_SECRET` | — | PCE API secret |
| `PCE_ORG_ID` | `1` | PCE organization ID |

## Features

- Tracks rulesets, IP lists, services, label groups, virtual services, and firewall settings
- Field-level diffs between draft and active policy
- Snapshot history with content hashing for change detection
- User attribution via PCE audit events
- Added/modified/deleted/unchanged summary counts
- Interactive timeline UI with diff detail
- Persistent snapshot storage in `/data`
- Uses `illumio` Python SDK for PCE connectivity
