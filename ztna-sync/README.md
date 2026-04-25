# ZTNA Sync

> **Status: Untested** — This plugin has not been validated against live ZTNA platforms. Use analytics mode to preview before enabling sync.

Sync Illumio workloads to ZTNA application definitions. Groups workloads by label, discovers listening ports from traffic data, and creates application segments on your ZTNA platform.

Supports: **Zscaler ZPA**, **Netskope NPA**, **Cloudflare Access**, **Cisco Secure Access**

## Install

```bash
plugger install ztna-sync
```

## How It Works

1. Pulls all workloads from the PCE with their labels and IPs
2. Groups workloads by `app|env` (configurable) into application definitions
3. Discovers listening ports from traffic flow data (last 7 days by default)
4. In **analytics mode**: shows what would be created on the ZTNA platform
5. In **sync mode**: creates/updates application segments via ZTNA API

## Configuration

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTNA_PROVIDER` | _(required)_ | `zscaler`, `netskope`, `cloudflare`, or `cisco` |
| `MODE` | `analytics` | `analytics` = preview only, `sync` = push to ZTNA |
| `SCAN_INTERVAL` | `3600` | Seconds between sync cycles |
| `GROUP_BY` | `app,env` | Label keys to group applications by |
| `NAMING_PATTERN` | `{app}-{env}` | Application naming template |
| `PORT_SOURCE` | `traffic` | Port discovery source (`traffic` or `policy`) |
| `LOOKBACK_HOURS` | `168` | Hours of traffic to analyze (default 7 days) |
| `LABEL_FILTER` | _(empty)_ | JSON filter, e.g. `{"env": ["prod", "staging"]}` |

### Zscaler ZPA

| Variable | Description |
|----------|-------------|
| `ZPA_CLIENT_ID` | Zscaler client ID |
| `ZPA_CLIENT_SECRET` | Zscaler client secret |
| `ZPA_CUSTOMER_ID` | ZPA customer ID |
| `ZPA_VANITY_DOMAIN` | Vanity domain (for OneAPI auth) |
| `ZPA_CLOUD` | Cloud: `PRODUCTION`, `BETA`, `GOV` |
| `ZPA_CONNECTOR_GROUP_ID` | Pre-existing App Connector Group ID |

### Netskope NPA

| Variable | Description |
|----------|-------------|
| `NETSKOPE_TENANT` | Tenant name (from `{tenant}.goskope.com`) |
| `NETSKOPE_API_TOKEN` | REST API v2 token |
| `NETSKOPE_PUBLISHER_ID` | Publisher ID for routing |

### Cloudflare Access

| Variable | Description |
|----------|-------------|
| `CF_API_TOKEN` | API token with Access Apps Write permission |
| `CF_ACCOUNT_ID` | Cloudflare account ID |

### Cisco Secure Access

| Variable | Description |
|----------|-------------|
| `CISCO_API_KEY` | Secure Access API key |
| `CISCO_API_SECRET` | Secure Access API secret |

## Example Mapping

```
PCE Workloads:
  app=HRApp, env=prod, role=web → IPs: [10.0.1.5, 10.0.1.6], Ports: [443/tcp, 8080/tcp]
  app=HRApp, env=prod, role=db  → IPs: [10.0.2.1], Ports: [5432/tcp]

ZTNA Applications Created:
  "illumio-hrapp-prod" → IPs: [10.0.1.5, 10.0.1.6, 10.0.2.1], Ports: [443, 5432, 8080]
```

## Features

- Multi-provider support (Zscaler, Netskope, Cloudflare, Cisco)
- Analytics mode for safe preview before syncing
- Configurable label grouping and naming patterns
- Port discovery from PCE traffic data
- Label-based filtering to sync only specific apps/environments
- Idempotent sync (creates new, updates existing by name match)
- Dashboard with application table, IP/port preview, sync status
- JSON export for manual review

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/state` | Current state and applications |
| POST | `/api/scan` | Trigger immediate scan |
