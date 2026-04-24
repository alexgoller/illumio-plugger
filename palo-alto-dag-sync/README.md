# Palo Alto DAG Sync

> **Status: Untested** — This plugin has not been validated against a live Palo Alto Networks firewall or Panorama instance. The API integration follows PAN-OS XML API documentation. Please report issues.

Syncs Illumio PCE workload labels to Palo Alto Networks Dynamic Address
Groups (DAGs). Polls PCE workloads, maps labels to PAN-OS tags using a
configurable format, and registers IP-to-tag mappings via the PAN-OS
XML API so that DAG-based firewall policies stay current automatically.

## Install

```
plugger install palo-alto-dag-sync
```

## Prerequisites

This plugin requires API access to a Palo Alto Networks firewall or
Panorama instance.

1. Generate a PAN-OS API key:
   ```
   curl -k "https://<firewall>/api/?type=keygen&user=admin&password=<password>"
   ```
2. Set `PALO_HOST` to your firewall/Panorama hostname or IP.
3. Set `PALO_API_KEY` to the generated API key.

Without `PALO_HOST` configured, the plugin runs in **dry-run mode** --
it polls the PCE, builds tags, and shows what would be synced on the
dashboard, but does not push anything to PAN-OS. This is useful for
validating tag mappings before enabling the integration.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PALO_HOST` | _(empty)_ | PAN-OS firewall/Panorama host (empty = dry-run) |
| `PALO_API_KEY` | _(empty)_ | PAN-OS API key (secret) |
| `PALO_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for PAN-OS |
| `SYNC_INTERVAL` | `300` | Seconds between sync cycles |
| `TAG_PREFIX` | `illumio` | Prefix for generated PAN-OS tags |
| `TAG_FORMAT` | `{prefix}-{key}-{value}` | Tag naming template |
| `SYNC_LABELS` | `role,app,env,loc` | Comma-separated Illumio label keys to sync |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for PCE |

## Features

- Maps Illumio labels to PAN-OS tags with configurable format and prefix
- Registers IP-to-tag mappings via PAN-OS User-ID XML API
- Batched API calls (500 entries per request) for large environments
- Dry-run mode when `PALO_HOST` is not set -- preview without pushing
- Sync history tracking (last 20 syncs)
- Dashboard showing workloads synced, tags registered, and PAN-OS status
- Uses `illumio` Python SDK for PCE connectivity
