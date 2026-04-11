# Example Plugins

Plugger ships with four example plugins that demonstrate different capabilities and are useful out of the box.

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
