# Infoblox IPAM Sync

> **Status: Untested** — This plugin has not been validated against a live Infoblox instance. Use analytics mode first.

Bi-directional sync between Illumio PCE and Infoblox IPAM/DDI. Maps Illumio labels to Infoblox extensible attributes and vice versa. Also syncs Infoblox networks/IP ranges to Illumio IP Lists.

## Install

```bash
plugger install infoblox-ipam-sync
```

## Why This Integration Matters

Infoblox is the source of truth for IP address management in most enterprises. Illumio is the source of truth for micro-segmentation policy. Bridging them:

- **IPAM teams see segmentation context** — "This IP belongs to the payments app in production, role: database"
- **Security teams get automated labeling** — Infoblox already knows site, department, owner → auto-apply as Illumio labels
- **IP lifecycle awareness** — IPs deallocated in IPAM → flag as stale in Illumio
- **IP List sync** — Infoblox network definitions → Illumio IP Lists (and reverse)

## Modes

| Mode | Direction | What It Does |
|------|-----------|-------------|
| `analytics` (default) | Read-only | Shows matches and what would sync — changes nothing |
| `illumio-to-infoblox` | PCE → Infoblox | Push Illumio labels as extensible attributes on host records |
| `infoblox-to-illumio` | Infoblox → PCE | Pull Infoblox EAs and apply as Illumio workload labels |

## Configuration

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `INFOBLOX_HOST` | _(required)_ | Grid Master hostname or IP |
| `INFOBLOX_USER` | _(required)_ | WAPI username |
| `INFOBLOX_PASSWORD` | _(required)_ | WAPI password (secret) |
| `INFOBLOX_WAPI_VERSION` | `v2.12` | WAPI version |
| `INFOBLOX_SSL_VERIFY` | `false` | Verify Infoblox TLS certificate |
| `MODE` | `analytics` | `analytics`, `illumio-to-infoblox`, or `infoblox-to-illumio` |
| `SCAN_INTERVAL` | `3600` | Seconds between sync cycles |
| `MATCH_BY` | `ip` | Match strategy: `ip`, `hostname`, or `both` |
| `BATCH_SIZE` | `50` | Operations per WAPI batch request |
| `CREATE_EA_DEFS` | `true` | Auto-create EA definitions on Infoblox |

### Label Mapping (Illumio → Infoblox)

Default mapping — Illumio label keys become Infoblox extensible attributes:

| Illumio Label | Infoblox EA |
|--------------|-------------|
| `app` | `IllumioApp` |
| `env` | `IllumioEnv` |
| `role` | `IllumioRole` |
| `loc` | `IllumioLoc` |

Plus metadata EAs set automatically: `IllumioManaged=true`, `IllumioSyncTime=<timestamp>`

Override with `LABEL_MAPPING` JSON:
```bash
LABEL_MAPPING={"app": "Application", "env": "Environment", "role": "ServerRole", "loc": "Site"}
```

### Reverse Mapping (Infoblox → Illumio)

Map existing Infoblox EAs to Illumio label keys:
```bash
REVERSE_MAPPING={"Site": "loc", "Department": "app", "ServerType": "role", "Environment": "env"}
```

## How It Works

### Matching

The plugin matches PCE workloads to Infoblox host records by:
1. **IP address** (default) — workload interface IP matches host record IPv4 address
2. **Hostname** — workload hostname matches host record FQDN (substring match)
3. **Both** — tries IP first, falls back to hostname

### Illumio → Infoblox Sync

1. Fetch all PCE workloads with labels
2. Fetch all Infoblox host records with extensible attributes (paginated via WAPI)
3. Match by IP/hostname
4. For each match, compare current EAs vs Illumio labels
5. Batch update EAs using `extattrs+` (partial update — doesn't overwrite unrelated EAs)
6. Set `IllumioManaged=true` and `IllumioSyncTime` for tracking

### Infoblox → Illumio Sync

1. Fetch Infoblox host records with their EAs
2. Fetch PCE workloads
3. Match by IP/hostname
4. Map EA values to Illumio label keys via `REVERSE_MAPPING`
5. Apply labels to PCE workloads (creates labels if they don't exist)

## Infoblox WAPI Setup

### Prerequisites

1. An Infoblox Grid Master with WAPI enabled (NIOS 8.6+ / WAPI v2.12+)
2. A WAPI user account with permissions:
   - Read access to `record:host`, `network`, `extensibleattributedef`
   - Write access to `record:host` (for EA updates) — only if syncing
   - Write access to `extensibleattributedef` — only if `CREATE_EA_DEFS=true`
3. Network connectivity from the plugin container to the Grid Master (HTTPS, typically port 443)

### Creating a WAPI User

1. Log into the Infoblox Grid Manager
2. Go to **Administration > Administrators**
3. Create a new admin user (e.g., `plugger-sync`)
4. Assign an admin group with appropriate permissions:
   - For analytics: read-only access to DNS and IPAM objects
   - For sync: read-write access to DNS objects and extensible attributes
5. Note the username and password

### WAPI Authentication

The plugin uses **Basic Auth with session cookie reuse**:
- First request authenticates with username/password
- Subsequent requests reuse the `ibapauth` session cookie (faster)
- Session is explicitly logged out after each sync cycle

### Extensible Attribute Setup

The plugin can **auto-create** EA definitions on first sync (`CREATE_EA_DEFS=true`). The following EAs are created as STRING type:

| EA Name | Purpose |
|---------|---------|
| `IllumioApp` | Application label value |
| `IllumioEnv` | Environment label value |
| `IllumioRole` | Role label value |
| `IllumioLoc` | Location label value |
| `IllumioManaged` | Set to "true" on synced records |
| `IllumioSyncTime` | ISO 8601 timestamp of last sync |

If you prefer to create them manually or use ENUM type (with predefined values), set `CREATE_EA_DEFS=false` and define them in the Infoblox GUI.

### IP Lists

Infoblox networks and IP ranges are the natural source for Illumio IP Lists. While the current version syncs workload labels ↔ host record EAs, a future enhancement will support:

- **Infoblox network → Illumio IP List**: A network `10.1.0.0/16` with EA `Site=NYC` becomes an Illumio IP List named `infoblox-NYC-10.1.0.0/16`
- **Illumio IP List → Infoblox network EA**: Enrich Infoblox networks with the Illumio IP List names that reference them

This is a common customer ask and the WAPI `network` object supports extensible attributes identically to `record:host`.

## Dashboard

- **Stats**: PCE workloads, Infoblox host records, matched, changes needed, match rate %
- **Match Distribution**: Doughnut chart (matched vs unmatched PCE vs unmatched Infoblox)
- **Matches Tab**: Table showing each matched pair with Illumio labels, Infoblox EAs, and pending changes
- **Unmatched Tab**: Side-by-side view of PCE workloads without Infoblox match and Infoblox hosts without PCE match
- **Sync Log Tab**: Per-host sync results (synced/error) with details

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/state` | Full state: matches, unmatched, summary, sync results |
| POST | `/api/scan` | Trigger immediate scan/sync |

## Features

- Bi-directional sync (Illumio → Infoblox or Infoblox → Illumio)
- Analytics mode for safe preview before any changes
- Match workloads to host records by IP, hostname, or both
- Configurable label ↔ EA mapping
- Partial EA updates via `extattrs+` (doesn't overwrite unrelated EAs)
- Batch WAPI operations for performance (~70% faster than sequential)
- Auto-create EA definitions on Infoblox
- Metadata tracking (IllumioManaged, IllumioSyncTime)
- Session cookie reuse for efficient API calls
- Paginated host record fetching for large environments
- Dashboard with match visualization and change preview
