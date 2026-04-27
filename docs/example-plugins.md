# Example Plugins

Plugger ships with seventeen plugins that demonstrate different capabilities and are useful out of the box. Fifteen are built from this repository and available from the [plugin registry](https://alexgoller.github.io/illumio-plugger/). Two additional plugins (Policy GitOps and Policy Workflow) live in a dedicated repository. All can be installed with `plugger install <name>`.

## PCE Health Monitor

**Type:** Daemon (24/7) | **Language:** Python | **UI:** Yes

Polls the PCE health, node availability, and workloads endpoints. Serves a web dashboard showing:

- Overall status badge (healthy / degraded / unreachable)
- Per-endpoint HTTP status and response data
- PCE node details (CPU, memory, disk, services)
- Auto-refresh every 15 seconds

**Install:**
```bash
cd pce-health-monitor
docker build -t pce-health-monitor:latest .
plugger install plugin.yaml
plugger start pce-health-monitor
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `30` | Seconds between health checks |
| `PCE_TLS_SKIP_VERIFY` | `false` | Skip TLS verification |

---

## Traffic Reporter

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes (Chart.js)

Queries the PCE Explorer traffic API and serves an interactive dashboard with:

- **Policy decision doughnut chart** — allowed vs blocked vs unknown
- **Top sources/destinations/services** — horizontal bar charts
- **Blocked flows table** — source, destination, service, connection count
- **Stat cards** — total flows, allowed, blocked, unknown
- Live updates via `fetch()` every 30 seconds

**Install:**
```bash
cd traffic-reporter
docker build -t traffic-reporter:latest .
plugger install plugin.yaml
plugger start traffic-reporter
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `300` | Seconds between traffic queries |
| `LOOKBACK_HOURS` | `24` | Hours of traffic history |
| `MAX_RESULTS` | `10000` | Maximum flows per query |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification |

---

## Policy Diff

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes (Chart.js)

Compares PCE draft vs active policy and tracks changes over time. Features:

- **Changes tab** — expandable git-like diffs showing field-level changes with `+`/`-` lines
- **Timeline tab** — Chart.js graph of changes over time, commit-log style snapshot history with hashes
- **Audit Log tab** — PCE audit events with user attribution and colored avatars
- **Policy Objects tab** — bar chart comparing active vs draft counts (rulesets, IP lists, services, label groups)
- Persistent snapshots stored to disk

**Install:**
```bash
cd policy-diff
docker build -t policy-diff:latest .
plugger install plugin.yaml
plugger start policy-diff
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `120` | Seconds between comparisons |
| `EVENT_LOOKBACK_HOURS` | `72` | Hours of audit events to fetch |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification |

**Compared policy types:** Rulesets, IP Lists, Services, Label Groups, Virtual Services, Firewall Settings

---

## PCE Events (Pretty Cool Events)

**Type:** Daemon (24/7) | **Language:** Python | **UI:** Yes (Flask)

Wraps [illumio-pretty-cool-events](https://github.com/alexgoller/illumio-pretty-cool-events) as a plugger plugin. Real-time PCE event monitoring with 15+ output plugins:

- **Slack** — post events to Slack channels
- **Microsoft Teams** — webhook notifications
- **PagerDuty** — incident creation
- **Email** — SMTP notifications
- **Webhooks** — forward to any URL (including plugger's event trigger)
- **Jira** — create tickets
- **ServiceNow** — incident management
- **AWS SNS/SMS** — cloud notifications
- **Syslog** — forward to syslog
- **File** — write events to JSON
- Plus: Opsgenie, GitHub Issues, AWS Lambda, Mattermost, stdout

**Install:**
```bash
cd pce-events
docker build -t pce-events:latest .
plugger install plugin.yaml

# Copy and edit config
mkdir -p ~/.plugger/volumes/pce-events/config
cp pce-events/config.yaml.example ~/.plugger/volumes/pce-events/config/config.yaml
vim ~/.plugger/volumes/pce-events/config/config.yaml

plugger start pce-events
```

**Config:** See `pce-events/config.yaml.example` for full configuration including PCE connection, output plugins, and watchers.

The web UI provides:
- Event viewer with live updates
- Watcher management (create, edit, delete)
- Plugin status and verification
- Configuration editor
- Event statistics and diagrams

---

## PCE Posture Report

**Type:** Cron | **Language:** Python (Illumio SDK) | **UI:** No (generates files)

Generates security posture reports on a schedule. Queries all workloads, labels, rulesets, IP lists, and services, then produces a posture score and reports.

**Install:**
```bash
plugger install pce-posture-report
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification |

**Schedule:** `0 */6 * * *` (every 6 hours)

**Posture score** (0-100) based on:
- Enforcement coverage (full + selective)
- Label coverage (role, app, env, loc)
- Active policy rules
- Managed workload ratio

Reports written to `/data` volume as timestamped HTML + JSON files.

---

## AI Assisted Rules

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK + Anthropic/OpenAI) | **UI:** Yes

Policy advisor that analyzes blocked traffic and generates PCE-ready rule suggestions.

**Install:**
```bash
# Without AI (rule generation still works)
plugger install ai-assisted-rules

# With AI analysis
plugger install ai-assisted-rules \
  -e AI_PROVIDER=anthropic \
  -e AI_API_KEY=sk-ant-xxx
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `300` | Seconds between analysis runs |
| `LOOKBACK_HOURS` | `24` | Hours of traffic to analyze |
| `AI_PROVIDER` | | `anthropic`, `openai`, or `ollama` (optional) |
| `AI_API_KEY` | | API key for the LLM provider (optional) |
| `AI_MODEL` | | Model to use (optional, auto-detected) |
| `AI_BASE_URL` | | Base URL for Ollama or custom endpoints |

**Features:**
- **Application Policy** — per-app cards showing intra-scope + extra-scope incoming/outgoing + IP traffic
- **Three security tiers** — Basic Ringfencing, Application Tiered, High Security
- **Infrastructure detection** — consolidates monitoring, syslog, NTP, jump hosts into broad rules
- **Risky service flagging** — FTP, telnet, RDP, SMB auto-flagged into FOR REVIEW rulesets
- **Cross-scope rules** — proper Illumio extra-scope format
- **AI analysis** (optional) — LLM-powered risk assessment and modification suggestions
- **Label gap detection** — finds workloads missing roles, suggests labels
- **One-click provisioning** — creates draft rulesets directly on the PCE

---

## Stale Workloads

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

Discovers workloads that are offline, haven't sent a heartbeat, have no traffic, or are unmanaged.

**Install:**
```bash
plugger install stale-workloads
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `600` | Seconds between checks |
| `STALE_DAYS` | `7` | Days without heartbeat to consider stale |
| `OFFLINE_HOURS` | `24` | Hours offline to flag |
| `CHECK_TRAFFIC` | `true` | Check for workloads with zero traffic |
| `TRAFFIC_LOOKBACK_HOURS` | `168` | Hours of traffic to check (7 days) |
| `ENABLE_CLEANUP` | `false` | Enable unpair/delete actions |

**Detection criteria:**
- **Offline** — workload not online
- **No heartbeat** — managed workload hasn't checked in for N days
- **No traffic** — zero flows in the lookback period
- **Unmanaged** — no VEN agent installed

**Cleanup actions** (disabled by default, set `ENABLE_CLEANUP=true`):
- **Unpair** — removes VEN agent from managed workloads
- **Delete** — removes unmanaged workloads from PCE

Dashboard shows stale workloads grouped by app|env with severity levels, doughnut chart by reason, and searchable table.

---

## Palo Alto DAG Sync

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

Syncs Illumio workload labels to Palo Alto Networks Dynamic Address Groups via the PAN-OS XML User-ID API. Enables label-based firewall policy automation.

**Install:**
```bash
# With Palo Alto configured
plugger install palo-alto-dag-sync \
  -e PALO_HOST=panorama.example.com \
  -e PALO_API_KEY=your-pan-api-key

# Dry-run mode (no Palo — shows what would sync)
plugger install palo-alto-dag-sync
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `PALO_HOST` | | Panorama or firewall hostname |
| `PALO_API_KEY` | | PAN-OS API key |
| `PALO_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for PAN-OS |
| `SYNC_INTERVAL` | `300` | Seconds between syncs |
| `TAG_PREFIX` | `illumio` | Prefix for PAN-OS tags |
| `TAG_FORMAT` | `{prefix}-{key}-{value}` | Tag name format |
| `SYNC_LABELS` | `role,app,env,loc` | Label keys to sync |

**How it works:**
1. Polls PCE for all online workloads with labels
2. Builds PAN-OS tags from labels (e.g., `illumio-role-web`, `illumio-app-ordering`)
3. Registers IP-to-tag mappings via PAN-OS XML User-ID API
4. Palo Alto DAGs dynamically include workloads matching those tags
5. Dashboard shows tag distribution, sync history, and full tag registry

**Tag format examples:**
- `illumio-role-web` (52 IPs)
- `illumio-app-ordering` (32 IPs)
- `illumio-env-prod` (134 IPs)
- `illumio-loc-ca` (64 IPs)

**Dry-run mode:** Without `PALO_HOST`, the plugin runs against the PCE and shows what tags would be created and how many IPs would be registered — useful for validating the mapping before connecting a firewall.

---

## AD Label Sync

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

Discovers Active Directory computers via LDAP and maps OU, group, and location attributes to Illumio labels. Includes an analytics mode for feasibility testing before enabling live sync.

**Install:**
```bash
plugger install ad-label-sync
```

---

## Rule Scheduler

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

Time-based rule and ruleset scheduling for Illumio PCE. Enable or disable rules and rulesets on a schedule — business hours policies, maintenance windows, weekend lockdowns.

**Install:**
```bash
plugger install rule-scheduler
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECK_INTERVAL` | `60` | Seconds between schedule checks |
| `TZ` | `UTC` | Timezone for schedule evaluation |

**Features:**
- YAML-based schedule configuration
- Multiple independent schedulers per instance
- Day-of-week and time-of-day windows
- Immediate reconciliation on startup
- Enable/disable rules and rulesets on the PCE
- Dashboard showing active schedules, next transitions, and history

---

## AI Security Report

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK + Anthropic/OpenAI) | **UI:** Yes (Chart.js)

Comprehensive AI-powered security posture analysis for Illumio PCE. Collects workloads, traffic, policy, and process data, runs 10 security analysis categories, scores each 0-100, and presents an interactive dashboard with charts, heatmaps, compliance mapping, and PDF export.

**Install:**
```bash
plugger install ai-security-report
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL` | `86400` | Seconds between scans (minimum 3600) |
| `LOOKBACK_DAYS` | `7` | Days of traffic history to analyze |
| `MAX_TRAFFIC_RESULTS` | `100000` | Maximum traffic flows to query |
| `PROCESS_SAMPLE_SIZE` | `50` | Workloads to sample for process data |
| `REPORT_RETENTION` | `30` | Historical reports to keep |
| `AI_PROVIDER` | | `anthropic`, `openai`, or `ollama` (optional) |
| `AI_API_KEY` | | API key for the LLM provider (optional) |
| `AI_MODEL` | | Model override (optional, auto-detected) |
| `AI_BASE_URL` | | Custom endpoint for Ollama |

**Security analysis categories:** Enforcement Coverage, OS Lifecycle Risk, Label Hygiene, Environmental Separation, Risky Services, Policy Analysis, Traffic Anomalies, Lateral Movement Surface, Agent Health, Compliance Mapping

**Features:**
- Overall security score (0-100) with letter grade (A-F)
- AI-generated executive summary and per-section narratives (optional)
- AI-prioritized remediation roadmap
- Environment separation heatmap
- Compliance mapping to NIST CSF, CIS Controls, PCI-DSS
- Historical report storage with trend comparison
- PDF export via browser print
- Works without AI — all data analysis and scoring is built-in

---

## Remedy CMDB Sync

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

> **Status: Untested** — This plugin has not been validated against a live BMC Helix/Remedy instance.

Sync BMC Helix/Remedy CMDB configuration items to Illumio labels. Queries CIs via the CMDB REST API, maps CI attributes (business service, environment, location, category) to Illumio labels using configurable rules, and optionally applies labels to PCE workloads.

**Install:**
```bash
plugger install remedy-cmdb-sync
```

**Modes:**
- **analytics** (default) — Read-only. Connects to CMDB, discovers CIs, shows what labels would be derived and which PCE workloads match. No changes are made.
- **sync** — Applies derived labels to matching PCE workloads (matched by hostname/IP). Only use after verifying analytics results.

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `REMEDY_HOST` | _(required)_ | BMC Helix/Remedy server hostname |
| `REMEDY_PORT` | `8443` | Remedy API port |
| `REMEDY_USER` | _(required)_ | Remedy API username |
| `REMEDY_PASSWORD` | _(required)_ | Remedy API password |
| `REMEDY_CI_CLASS` | `BMC_ComputerSystem` | CMDB CI class to query |
| `MODE` | `analytics` | `analytics` or `sync` |
| `SCAN_INTERVAL` | `3600` | Seconds between scans |
| `MAPPING_RULES` | _(built-in)_ | Custom mapping rules as JSON array |

**Features:**
- Queries BMC_ComputerSystem CIs via CMDB REST API with JWT authentication
- Paginated CI fetching for large CMDBs
- Configurable attribute-to-label mapping with regex and priority
- Analytics mode for safe, read-only feasibility analysis
- Sync mode to apply labels to PCE workloads matched by hostname/IP
- Dashboard with CI browser, match detail, coverage charts

---

## Policy Resolver

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

Resolve Illumio label-based policy into concrete IP-level firewall rules. Takes abstract rulesets with label scopes and resolves every consumer/provider to actual workload IPs, producing a flat list of source IP / destination IP / port / protocol entries ready for firewall implementation.

**Install:**
```bash
plugger install policy-resolver
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `600` | Seconds between resolution runs |
| `RESOLVE_DRAFT` | `false` | Resolve draft policy instead of active |

**Features:**
- Resolves label-based policy to IP-level firewall rules
- Handles all actor types: labels, IP lists, "all workloads", specific workloads
- Service reference resolution (named services to port/proto)
- Allow, Deny, Override Deny rules with proper ordering
- JSON export with download button
- TSV copy for spreadsheet paste
- Searchable firewall rule table with expandable rows
- Resolves active or draft policy (configurable)

---

## ZTNA Sync

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

> **Status: Untested** — This plugin has not been validated against live ZTNA platforms.

Sync Illumio workloads to ZTNA application definitions. Groups workloads by label, discovers listening ports from traffic data, and creates application segments on your ZTNA platform.

Supports: **Zscaler ZPA** · **Netskope NPA** · **Cloudflare Access** · **Cisco Secure Access**

**Install:**
```bash
plugger install ztna-sync
```

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTNA_PROVIDER` | _(required)_ | `zscaler`, `netskope`, `cloudflare`, or `cisco` |
| `MODE` | `analytics` | `analytics` = preview only, `sync` = create/update apps on ZTNA platform |
| `SCAN_INTERVAL` | `3600` | Seconds between sync cycles |
| `GROUP_BY` | `app,env` | Comma-separated label keys to group applications by |
| `NAMING_PATTERN` | `{app}-{env}` | Template for ZTNA application names |
| `PORT_SOURCE` | `traffic` | Where to discover ports: `traffic` or `policy` |
| `LOOKBACK_HOURS` | `168` | Hours of traffic history to analyze for port discovery |
| `LABEL_FILTER` | _(empty)_ | JSON object to filter which workloads to include |

**How it works:**
1. Collects workloads from the PCE with labels and interface IPs
2. Groups by label — workloads sharing the same `app|env` become one ZTNA application
3. Discovers ports from PCE traffic flows
4. Builds application definitions — name, server IPs, TCP/UDP ports per application
5. Analytics mode (default) shows what would be created; sync mode pushes to the ZTNA platform

**Features:**
- Multi-provider: Zscaler ZPA, Netskope NPA, Cloudflare Access, Cisco Secure Access
- Analytics mode for safe preview before any sync
- Configurable label grouping and naming patterns
- Port discovery from PCE traffic data or policy rules
- Label-based filtering to sync only specific apps/environments
- Idempotent sync — creates new, updates existing (matched by `illumio-` prefix)
- Dashboard with full application table, IP/port visibility, sync status
- JSON export for manual review, scripting, or audit

---

## Infoblox IPAM Sync

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

> **Status: Untested** — This plugin has not been validated against a live Infoblox instance.

Bi-directional sync between Illumio PCE and Infoblox IPAM/DDI. Maps Illumio labels to Infoblox extensible attributes and vice versa.

**Install:**
```bash
plugger install infoblox-ipam-sync
```

**Modes:**
- **analytics** (default) — Read-only. Shows matches and what would sync — changes nothing.
- **illumio-to-infoblox** — Push Illumio labels as extensible attributes on host records.
- **infoblox-to-illumio** — Pull Infoblox EAs and apply as Illumio workload labels.

**Config:**

| Variable | Default | Description |
|----------|---------|-------------|
| `INFOBLOX_HOST` | _(required)_ | Grid Master hostname or IP |
| `INFOBLOX_USER` | _(required)_ | WAPI username |
| `INFOBLOX_PASSWORD` | _(required)_ | WAPI password (secret) |
| `INFOBLOX_WAPI_VERSION` | `v2.12` | WAPI version |
| `MODE` | `analytics` | `analytics`, `illumio-to-infoblox`, or `infoblox-to-illumio` |
| `SCAN_INTERVAL` | `3600` | Seconds between sync cycles |
| `MATCH_BY` | `ip` | Match strategy: `ip`, `hostname`, or `both` |
| `BATCH_SIZE` | `50` | Operations per WAPI batch request |

**Features:**
- Bi-directional sync (Illumio to Infoblox or Infoblox to Illumio)
- Analytics mode for safe preview before any changes
- Match workloads to host records by IP, hostname, or both
- Configurable label-to-EA mapping
- Partial EA updates via `extattrs+` (doesn't overwrite unrelated EAs)
- Batch WAPI operations for performance
- Auto-create EA definitions on Infoblox
- Metadata tracking (IllumioManaged, IllumioSyncTime)
- Dashboard with match visualization and change preview

---

## Policy GitOps

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

> **Moved to external repository:** [github.com/alexgoller/illumio-policy-gitops](https://github.com/alexgoller/illumio-policy-gitops)

Git-based policy management for Illumio PCE. Connects a Git repository to the PCE and synchronizes policy objects (rulesets, IP lists, services, label groups) as YAML files. Supports push (PCE to Git) and pull (Git to PCE) workflows with drift detection, commit history, and a web dashboard.

---

## Policy Workflow

**Type:** Daemon (24/7) | **Language:** Python (Illumio SDK) | **UI:** Yes

> **Moved to external repository:** [github.com/alexgoller/illumio-policy-gitops](https://github.com/alexgoller/illumio-policy-gitops)

Approval-based policy workflow engine for Illumio PCE. Integrates with Policy GitOps to add review and approval gates before policy changes are applied. Supports multi-stage approval pipelines, Slack/Teams notifications, and audit logging of all approval decisions.
