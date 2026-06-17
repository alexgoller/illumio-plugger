# network-discovery

[![Plugin](https://img.shields.io/badge/plugger-network--discovery-blue)](https://alexgoller.github.io/illumio-plugger/)
[![Version](https://img.shields.io/badge/version-0.2.0-green)]()
[![Mode](https://img.shields.io/badge/mode-daemon-orange)]()

Scan PCE traffic flows for bare IP addresses that have no workload record, resolve their hostnames via DNS, and optionally create unmanaged workloads in the PCE.

## The Problem

In any Illumio deployment, traffic flows contain endpoints that appear as raw IP addresses rather than managed workloads. These "bare IPs" represent servers, appliances, or devices that the VEN has not been deployed to. Without workload records, these endpoints are invisible in the Illumination map -- you cannot label them, write policy for them, or track their communication patterns.

Manually hunting for these IPs, resolving their hostnames, and creating unmanaged workloads is tedious. This plugin automates the entire pipeline: discover bare IPs from traffic, resolve DNS, infer labels from hostname patterns, and create unmanaged workloads on the PCE.

## Install

```bash
plugger install network-discovery
```

## How It Works

Each scan cycle runs this pipeline:

```
Traffic Flows      Filter & Classify      DNS Resolve       Create Workloads
+-----------+     +-----------------+    +------------+    +----------------+
| PCE       | --> | Bare IPs only   | -> | System DNS | -> | POST to PCE    |
| Explorer  |     | Internal subnets|    | Custom DNS |    | with labels    |
| API       |     | Dedup vs known  |    | Cache+TTL  |    | (if auto-create|
+-----------+     +-----------------+    +------------+    +----------------+
```

1. **Query traffic**: Pull flows from the PCE Explorer API for the configured lookback window.
2. **Extract bare IPs**: Find endpoints with an IP but no workload hostname. Count flow directions and services.
3. **Filter**: Keep only IPs in configured internal subnets. Remove IPs that already have a workload record.
4. **DNS resolution**: Resolve each IP via system DNS, falling back to a custom DNS server if configured. Results are cached with TTL.
5. **Label inference**: Match resolved hostnames against configurable regex rules to infer app/env/role labels.
6. **Create workloads**: In `auto-create` mode, POST unmanaged workloads to the PCE with resolved hostname and inferred labels. In `dry-run` mode, log what would be created without making changes.

## Modes

| Mode | Behavior |
|---|---|
| `dry-run` (default) | Discover and resolve IPs. Show what would be created. No PCE writes. |
| `auto-create` | Discover, resolve, and create unmanaged workloads on the PCE automatically. |

Start in `dry-run` to review the discovery results, then switch to `auto-create` when satisfied:

```bash
plugger env set network-discovery MODE=auto-create
```

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `MODE` | No | `dry-run` | Operating mode: `dry-run` or `auto-create`. |
| `POLL_INTERVAL` | No | `3600` | Seconds between scan cycles (minimum 300). |
| `LOOKBACK_HOURS` | No | `24` | Hours of traffic history to analyze per scan. |
| `MAX_RESULTS` | No | `10000` | Maximum traffic flows per query. |
| `INTERNAL_SUBNETS` | No | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Comma-separated CIDR subnets to consider internal. External IPs are ignored. |
| `DNS_SERVER` | No | _(empty)_ | Custom DNS server IP for reverse lookups. Falls back after system DNS. |
| `DNS_TIMEOUT` | No | `5` | Timeout in seconds for DNS queries. |
| `HOSTNAME_LABEL_RULES` | No | _(empty)_ | JSON array of hostname-to-label mapping rules (see below). |
| `STATE_FILE` | No | `/data/state.json` | Path for persistent state (created IPs, DNS cache, scan history). |
| `PCE_TLS_SKIP_VERIFY` | No | `true` | Skip TLS certificate verification for the PCE. |

PCE connection variables (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`, `PCE_API_SECRET`) are injected automatically by Plugger.

## DNS Resolution

The plugin resolves bare IPs in two stages:

1. **System DNS**: Uses the container's configured DNS resolver (`gethostbyaddr`).
2. **Custom DNS server**: If system DNS fails and `DNS_SERVER` is set, queries the specified server for PTR records using `dnspython`.

Results are cached:
- Successful lookups: cached for 1 hour.
- Failed lookups (negative cache): cached for 10 minutes.

Cache hits do not count toward DNS latency stats.

## Subnet Filtering

Only IPs within the configured `INTERNAL_SUBNETS` are processed. This prevents the plugin from trying to resolve and create workloads for external/internet IPs.

Default subnets cover RFC 1918 private address space:
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

Add your organization's specific ranges if they differ:

```bash
plugger env set network-discovery INTERNAL_SUBNETS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10"
```

## Hostname Label Inference

When a hostname is resolved, you can automatically assign labels based on regex patterns. Set `HOSTNAME_LABEL_RULES` to a JSON array:

```json
[
  {"pattern": "^web-",   "labels": {"role": "web",  "app": "frontend"}},
  {"pattern": "^db-",    "labels": {"role": "db",   "app": "backend"}},
  {"pattern": "-prod-",  "labels": {"env": "production"}},
  {"pattern": "-dev-",   "labels": {"env": "development"}},
  {"pattern": "\\bnagios\\b", "labels": {"role": "monitoring"}}
]
```

Rules are evaluated in order. The first matching rule wins. Patterns are case-insensitive. Labels from the rule are applied to the created workload.

If no rule matches, the workload is created with only its hostname and interfaces -- no labels.

## Dashboard

<!-- TODO: Add screenshot -->

The dashboard has three tabs:

### Overview Tab

- **Stats bar**: Bare IPs found, internal IPs, DNS resolved, workloads created, resolution rate, labels inferred.
- **Discovery Funnel**: Horizontal bar chart showing the pipeline stages (Bare IPs, Internal, Resolved, Created, Labeled).
- **Subnet Breakdown**: Doughnut chart showing how discovered IPs distribute across configured subnets.
- **DNS Performance**: Query count, success/fail/timeout rates, average latency, cache hits.
- **Scan History**: Line chart tracking bare IPs, resolved, and created counts over time.

### Discovered IPs Tab

Interactive table of all discovered IPs with:
- IP address, resolved hostname, subnet, status, inferred labels, traffic direction, services, flow count.
- **Filter by status**: All, Pending, Created, Unresolved, Already Exists.
- **JDS Knob**: A "(not)" checkbox that inverts the filter (e.g., show everything _except_ "exists").
- **Search**: Filter by IP or hostname substring.
- **Selectable workload creation**: Check individual rows or "select all", then click "Create Selected" to batch-create workloads on the PCE.
- **Per-row "Create" button**: Create a single workload from a discovered IP.

### Activity Tab

Chronological feed of all create/pending/failed actions with timestamps, IPs, hostnames, and detail messages.

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/state` | Full plugin state (funnel, DNS stats, discovered IPs, activity, cumulative stats). |
| `GET` | `/api/export/json` | Same as `/api/state` (convenience alias for export). |
| `POST` | `/api/scan` | Trigger a scan immediately. Returns `{"status": "scan_triggered"}`. Returns 409 if a scan is already running. |
| `POST` | `/api/create` | Create a workload for a specific IP. Body: `{"ip": "10.1.2.3"}`. Resolves DNS, infers labels, creates on PCE. |
| `GET` | `/healthz` | Health check. |

## State Persistence

The plugin persists state to `STATE_FILE` between restarts:
- Set of already-created workload IPs (avoids duplicates).
- DNS cache entries.
- Cumulative scan statistics and scan history.

## Reports

When a scan finds resolved IPs or creates workloads, a report is published to the Plugger output bus:

```
Discovery: 12 IPs resolved
Scan #3 completed in 8.2s
- Bare IPs found: 45 (38 internal, 7 external)
- DNS resolved: 12 / 38
- Already known: 15
- Would create: 12 workloads (dry-run)
```

## Resources

- Memory limit: 256 MB
- CPU limit: 0.5 cores
