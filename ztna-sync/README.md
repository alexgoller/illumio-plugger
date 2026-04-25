# ZTNA Sync

> **Status: Untested** — This plugin has not been validated against live ZTNA platforms. Always start in analytics mode to preview before enabling sync.

Sync Illumio workloads to ZTNA application definitions. Groups workloads by label, discovers listening ports from traffic data, and creates application segments on your ZTNA platform.

Supports: **Zscaler ZPA** · **Netskope NPA** · **Cloudflare Access** · **Cisco Secure Access**

## Install

```bash
plugger install ztna-sync
```

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   Illumio PCE    │────▶│    ZTNA Sync      │────▶│   ZTNA Platform     │
│                  │     │                  │     │                     │
│ Workloads:       │     │ 1. Group by label │     │ Zscaler ZPA         │
│  - IPs           │     │ 2. Discover ports │     │ Netskope NPA        │
│  - Labels        │     │ 3. Build app defs │     │ Cloudflare Access   │
│  - Traffic flows │     │ 4. Sync (or show) │     │ Cisco Secure Access │
└─────────────────┘     └──────────────────┘     └─────────────────────┘
```

1. **Collects workloads** from the PCE with labels (app, env, role, loc) and interface IPs
2. **Groups by label** — workloads sharing the same `app|env` become one ZTNA application
3. **Discovers ports** — queries PCE traffic flows to find what ports each workload is listening on
4. **Builds application definitions** — name, server IPs, TCP/UDP ports per application
5. **Analytics mode** (default) — shows what would be created, changes nothing
6. **Sync mode** — creates or updates application segments on the configured ZTNA platform

## Quick Start

### 1. Install and start in analytics mode

```bash
plugger install ztna-sync
plugger start ztna-sync
```

Open the dashboard to see all discovered applications with their IPs and ports.

### 2. Review the application definitions

The dashboard shows a table of every application that would be created:

| Application | Labels | IPs | Ports | Workloads |
|------------|--------|-----|-------|-----------|
| hrapp-prod | app:hrapp, env:prod | 10.0.1.5, 10.0.1.6, 10.0.2.1 | 443/tcp, 5432/tcp, 8080/tcp | 3 |
| payments-prod | app:payments, env:prod | 10.0.3.1, 10.0.3.2 | 443/tcp, 8443/tcp | 2 |

### 3. Configure your ZTNA provider and enable sync

See the provider-specific sections below. Once configured, set `MODE=sync` to start pushing.

---

## Core Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTNA_PROVIDER` | _(required)_ | `zscaler`, `netskope`, `cloudflare`, or `cisco` |
| `MODE` | `analytics` | `analytics` = preview only, `sync` = create/update apps on ZTNA platform |
| `SCAN_INTERVAL` | `3600` | Seconds between sync cycles (default: 1 hour) |
| `GROUP_BY` | `app,env` | Comma-separated label keys to group applications by |
| `NAMING_PATTERN` | `{app}-{env}` | Template for ZTNA application names (uses label values) |
| `PORT_SOURCE` | `traffic` | Where to discover ports: `traffic` (from flow data) or `policy` |
| `LOOKBACK_HOURS` | `168` | Hours of traffic history to analyze for port discovery (default: 7 days) |
| `LABEL_FILTER` | _(empty)_ | JSON object to filter which workloads to include |

### Label Filter Examples

Only sync production workloads:
```
LABEL_FILTER={"env": ["prod", "production"]}
```

Only sync specific applications:
```
LABEL_FILTER={"app": ["hrapp", "payments", "ordering"], "env": ["prod"]}
```

### Naming Pattern Examples

Default — group by app and environment:
```
NAMING_PATTERN={app}-{env}
# → hrapp-prod, payments-staging
```

Include role for finer granularity:
```
NAMING_PATTERN={app}-{env}-{role}
GROUP_BY=app,env,role
# → hrapp-prod-web, hrapp-prod-db
```

Include location:
```
NAMING_PATTERN={app}-{env}-{loc}
GROUP_BY=app,env,loc
# → hrapp-prod-us-east, hrapp-prod-eu-west
```

### What Gets Created

For each application group, the plugin creates a ZTNA application with:

- **Name**: `illumio-{naming_pattern}` (e.g., `illumio-hrapp-prod`)
- **Server IPs**: All workload IPs in the group
- **TCP Ports**: All TCP ports observed in allowed traffic to those workloads
- **UDP Ports**: All UDP ports observed in allowed traffic to those workloads

Applications are matched by name — if `illumio-hrapp-prod` already exists on the ZTNA platform, it's updated instead of duplicated.

---

## Zscaler Private Access (ZPA)

### Prerequisites

1. A Zscaler ZPA tenant with API access enabled
2. An **App Connector Group** deployed in your network (connectors must be able to reach the Illumio-managed workloads)
3. API credentials — either OneAPI (recommended) or Legacy

### Getting Your Credentials

**OneAPI (recommended for new tenants):**
1. Log into the Zscaler admin portal
2. Go to **Administration > API Key Management > OneAPI Credentials**
3. Create a new credential with `Private Access` scope
4. Note the **Client ID** and **Client Secret**
5. Your **Vanity Domain** is the subdomain of your login URL (e.g., `myorg` from `myorg.admin.zscaler.com`)
6. Find your **Customer ID** in **Administration > Company Profile**

**Legacy API (older tenants):**
1. Go to **Administration > API Key Management**
2. Create a new API key
3. Note the **Client ID** and **Client Secret**
4. Find your **Customer ID** in the tenant URL or **Company Profile**

### Getting the App Connector Group ID

1. Go to **Infrastructure > App Connectors > App Connector Groups**
2. Click on the group that can reach your Illumio workloads
3. The ID is in the URL or available via `GET /zpa/mgmtconfig/v1/admin/customers/{customerId}/appConnectorGroup`

### Configuration

```bash
ZTNA_PROVIDER=zscaler
ZPA_CLIENT_ID=your-client-id
ZPA_CLIENT_SECRET=your-client-secret
ZPA_CUSTOMER_ID=123456789
ZPA_VANITY_DOMAIN=myorg                 # For OneAPI auth (leave empty for legacy)
ZPA_CLOUD=PRODUCTION                     # PRODUCTION | BETA | GOV | GOVUS | ZPATWO
ZPA_CONNECTOR_GROUP_ID=abc-def-123       # Pre-existing App Connector Group
```

### What Gets Created on ZPA

For each application group:

```
Application Segment: "illumio-hrapp-prod"
├── domainNames: ["10.0.1.5", "10.0.1.6", "10.0.2.1"]
├── tcpPortRanges: ["443", "443", "5432", "5432", "8080", "8080"]
├── udpPortRanges: []
├── segmentGroupId: (linked to connector group)
├── enabled: true
├── bypassType: NEVER
└── healthReporting: ON_ACCESS
```

### ZPA Cloud Endpoints

| Cloud | Auth URL | API URL |
|-------|----------|---------|
| PRODUCTION | `{vanity}.zslogin.net` | `api.zsapi.net` |
| BETA | `{vanity}.zsloginbeta.net` | `api.beta.zsapi.net` |
| GOV | `{vanity}.zslogingov.net` | `api.gov.zsapi.net` |
| GOVUS | `{vanity}.zslogingovus.net` | `api.govus.zsapi.net` |

---

## Netskope Private Access (NPA)

### Prerequisites

1. A Netskope tenant with Private Access licensed
2. At least one **Publisher** deployed in your network (the publisher routes traffic to your Illumio workloads)
3. A REST API v2 token with Private Access permissions

### Getting Your API Token

1. Log into the Netskope admin console
2. Go to **Settings > Tools > REST API v2**
3. Create a new token with permissions:
   - `/api/v2/steering/apps/private` — Read + Write
   - `/api/v2/infrastructure/publishers` — Read (to list publishers)
4. Copy the token

### Getting the Publisher ID

1. Go to **Settings > Security Cloud Platform > App Connectors** (or use the API)
2. Note the publisher name and ID
3. Or query: `GET https://{tenant}.goskope.com/api/v2/infrastructure/publishers`

### Configuration

```bash
ZTNA_PROVIDER=netskope
NETSKOPE_TENANT=myorg                    # From myorg.goskope.com
NETSKOPE_API_TOKEN=your-api-v2-token
NETSKOPE_PUBLISHER_ID=12345              # Publisher that can reach workloads
```

### What Gets Created on Netskope

For each application group:

```
Private App: "illumio-hrapp-prod"
├── host: "10.0.1.5, 10.0.1.6, 10.0.2.1"
├── protocols:
│   ├── {port: "443", type: "tcp"}
│   ├── {port: "5432", type: "tcp"}
│   └── {port: "8080", type: "tcp"}
├── publishers: [{publisher_id: "12345"}]
├── use_publisher_dns: false
└── clientless_access: false
```

---

## Cloudflare Access (Zero Trust)

### Prerequisites

1. A Cloudflare account with Zero Trust / Cloudflare One
2. A **Cloudflare Tunnel** connected to your network (for private IP-based applications)
3. **WARP client** deployed on user devices (for accessing private apps)
4. An API token with Access write permissions

### Getting Your API Token

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com) > **My Profile > API Tokens**
2. Click **Create Token**
3. Use the **Custom Token** template with these permissions:
   - **Account > Access: Apps and Policies > Edit**
4. Set the account scope to your account
5. Copy the token

### Getting Your Account ID

1. Go to any zone in the Cloudflare dashboard
2. Your **Account ID** is in the right sidebar under **API**
3. Or check the URL: `dash.cloudflare.com/{account_id}/...`

### Configuration

```bash
ZTNA_PROVIDER=cloudflare
CF_API_TOKEN=your-cloudflare-api-token
CF_ACCOUNT_ID=abc123def456
```

### What Gets Created on Cloudflare

For each application group, a `self_hosted` application with private destinations:

```
Application: "illumio-hrapp-prod"
├── type: self_hosted
├── domain: hrapp-prod.internal
├── destinations:
│   ├── {type: "private", cidr: "10.0.1.5/32", l4_protocol: "tcp", port_range: "443"}
│   ├── {type: "private", cidr: "10.0.1.5/32", l4_protocol: "tcp", port_range: "8080"}
│   ├── {type: "private", cidr: "10.0.1.6/32", l4_protocol: "tcp", port_range: "443"}
│   ├── {type: "private", cidr: "10.0.2.1/32", l4_protocol: "tcp", port_range: "5432"}
│   └── ...
└── session_duration: 24h
```

### Important Notes

- Private destinations require a **Cloudflare Tunnel** connected to the network where Illumio workloads live
- Users must have the **WARP client** installed to access private applications
- Cloudflare limits destinations per application — large groups may need to be split
- Access Policies (who can access) must be configured separately in the Cloudflare dashboard after apps are created

---

## Cisco Secure Access

### Prerequisites

1. A Cisco Secure Access subscription (formerly Umbrella SIG + Duo)
2. **Resource Connectors** deployed in your network
3. API credentials from the Secure Access dashboard

### Getting Your API Credentials

1. Log into the [Cisco Secure Access dashboard](https://dashboard.sse.cisco.com)
2. Go to **Admin > API Keys**
3. Create a new API key pair
4. Note the **API Key** and **API Secret**
5. The key needs permissions for Private Resources management

### Configuration

```bash
ZTNA_PROVIDER=cisco
CISCO_API_KEY=your-api-key
CISCO_API_SECRET=your-api-secret
```

### What Gets Created on Cisco

For each application group:

```
Private Resource: "illumio-hrapp-prod"
├── accessTypes: ["networkAccess"]
├── resourceAddresses:
│   ├── destinationAddr: ["10.0.1.5/32", "10.0.1.6/32", "10.0.2.1/32"]
│   └── protocolPorts:
│       ├── {protocol: "TCP", ports: "443"}
│       ├── {protocol: "TCP", ports: "5432"}
│       └── {protocol: "TCP", ports: "8080"}
└── description: "Synced from Illumio | hrapp|prod"
```

### Important Notes

- Maximum 1000 Private Resources per organization
- Resource Connector Groups must be configured to route traffic to your workloads
- Access Policies are configured separately after resources are created

---

## Mapping Reference

### How Illumio Concepts Map to ZTNA

| Illumio | Zscaler ZPA | Netskope NPA | Cloudflare Access | Cisco Secure Access |
|---------|------------|-------------|-------------------|-------------------|
| App + Env labels | Application Segment name | Private App name | Application name | Private Resource name |
| Workload IPs | `domainNames` array | `host` field | `destinations[].cidr` | `destinationAddr` array |
| TCP ports (from traffic) | `tcpPortRanges` | `protocols[].port` (type:tcp) | `destinations[].port_range` | `protocolPorts[].ports` (TCP) |
| UDP ports (from traffic) | `udpPortRanges` | `protocols[].port` (type:udp) | `destinations[].port_range` (l4:udp) | `protocolPorts[].ports` (UDP) |
| Ruleset scope | Segment Group | _(flat)_ | _(flat)_ | Resource Group |

### Naming Convention

All created applications are prefixed with `illumio-` to identify them as managed by this plugin:

```
illumio-{app}-{env}          # Default: illumio-hrapp-prod
illumio-{app}-{env}-{role}   # With role: illumio-hrapp-prod-web
```

The prefix ensures the plugin can identify its own applications for updates without touching manually created ones.

---

## Dashboard

The dashboard shows:

- **Stats**: Total applications, IPs, ports, workloads discovered
- **Provider status**: Connected, configured, incomplete config, sync results
- **Application table**: Every application definition with labels, IPs (expandable), ports, workload count
- **Search**: Filter applications by name, label, or IP
- **JSON export**: Copy all application definitions as JSON for manual review or scripting
- **Sync status column**: Shows created/updated/error per application (sync mode only)

---

## Workflow: From Analytics to Production

### Step 1: Analytics (no ZTNA credentials needed)

```bash
ZTNA_PROVIDER=zscaler    # Just sets the target platform
MODE=analytics           # Default — no ZTNA API calls
```

Review the dashboard. Verify:
- Correct number of applications
- Correct IPs per application
- Ports look reasonable (from traffic data)
- No unexpected groupings

### Step 2: Dry Run (with ZTNA credentials)

Add your ZTNA credentials but keep `MODE=analytics`. The dashboard will show "configured" status, confirming credentials work, but nothing is pushed.

### Step 3: Sync

```bash
MODE=sync
```

The plugin will:
1. Authenticate to the ZTNA platform
2. List existing applications (to detect updates vs creates)
3. Create new applications or update existing ones
4. Report results per application in the dashboard

### Step 4: Ongoing

With `SCAN_INTERVAL=3600` (default), the plugin re-syncs every hour:
- New workloads → new IPs added to existing applications
- New applications (new app|env label combinations) → new ZTNA applications created
- Removed workloads → IPs updated on next sync

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/state` | Full state: applications, summary, sync results |
| POST | `/api/scan` | Trigger immediate scan/sync |

## Features

- Multi-provider: Zscaler ZPA, Netskope NPA, Cloudflare Access, Cisco Secure Access
- Analytics mode for safe preview before any sync
- Configurable label grouping (`GROUP_BY`) and naming (`NAMING_PATTERN`)
- Port discovery from PCE traffic data or policy rules
- Label-based filtering to sync only specific apps/environments
- Idempotent sync — creates new, updates existing (matched by `illumio-` prefix name)
- Dashboard with full application table, IP/port visibility, sync status
- JSON export for manual review, scripting, or audit
- 1-hour default sync interval to minimize PCE and ZTNA API load
