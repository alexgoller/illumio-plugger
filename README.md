# Plugger — Illumio Plugin Framework

Plugger manages Illumio PCE plugins running as Docker containers (or Kubernetes pods). It handles the full plugin lifecycle: install, start, stop, restart, logging, credential injection, health checks, scheduling, and a web dashboard with reverse proxy.

## Features

- **`plugger run` orchestrator** — starts all plugins, auto-restarts on crash, health checks, cron scheduling, embedded dashboard
- **Three scheduling modes** — daemon (24/7 with auto-restart), cron (periodic), event-driven (PCE events)
- **Web dashboard** — plugin tiles, start/stop/restart controls, live log streaming, config editing
- **Reverse proxy** — all plugin UIs consolidated under one port with URL rewriting
- **Install from anywhere** — local file, remote URL, or container image reference
- **Automatic credential injection** — PCE API keys passed as environment variables
- **In-container metadata discovery** — plugins declare ports, config, volumes via `/.plugger/metadata.yaml`
- **Health checks** — HTTP health monitoring with automatic restart on failure
- **Plugin scaffolding** — `plugger create -t go|shell|python` with Illumio SDK support
- **Runtime abstraction** — Docker today, Kubernetes tomorrow (same interface)

## Quick Start

```bash
# Build
make build

# Initialize config directory
plugger init

# Edit PCE connection details
vim ~/.plugger/config.yaml

# Install a plugin (local file, URL, or image ref)
plugger install ./plugin.yaml
plugger install https://example.com/plugin.yaml
plugger install ghcr.io/org/my-plugin:latest

# Run everything (all plugins + dashboard)
plugger run

# Or manage plugins individually
plugger start my-plugin
plugger stop my-plugin
plugger logs my-plugin -f
plugger status my-plugin
plugger list
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `plugger init` | Create `~/.plugger/` and default `config.yaml` |
| `plugger run [--addr host:port]` | Start all plugins with scheduling, health checks, and dashboard |
| `plugger create <name> [-t go\|shell\|python]` | Scaffold a new plugin project from a template |
| `plugger install <file\|URL\|image>` | Install a plugin from a manifest file, URL, or container image |
| `plugger uninstall <name>` | Remove a plugin and its container |
| `plugger start <name>` | Start a single plugin container |
| `plugger stop <name>` | Stop a running plugin container |
| `plugger restart <name>` | Restart a plugin container |
| `plugger list` | List all installed plugins and their state |
| `plugger status <name>` | Show detailed plugin status |
| `plugger logs <name> [-f] [-n 100]` | View plugin container logs |
| `plugger dashboard [--addr host:port]` | Start only the web dashboard (without orchestrator) |
| `plugger version` | Print the plugger version |

### `plugger run` Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `localhost:8800` | Dashboard listen address |
| `--no-dashboard` | `false` | Run without the web dashboard |

### Install Sources

```bash
# Local manifest file
plugger install ./traffic-reporter/plugin.yaml

# Remote URL
plugger install https://raw.githubusercontent.com/org/repo/main/plugin.yaml

# Container image (extracts manifest from /.plugger/manifest.yaml inside the image)
plugger install ghcr.io/illumio/plugger-traffic-reporter:v1.0
```

## `plugger run` — The Orchestrator

`plugger run` is the production way to run plugger. It:

1. **Reconciles state** — compares stored plugin state vs actual Docker containers, fixes mismatches
2. **Starts all enabled plugins** by schedule mode:
   - **Daemon plugins** — started immediately, auto-restarted on crash with exponential backoff (1s → 2s → 4s → ... → 5m cap, gives up after 5 consecutive failures)
   - **Cron plugins** — scheduled via cron expressions, container created per run, cleaned up after exit
3. **Runs health checks** — HTTP GET to each plugin's health endpoint at configured intervals; triggers restart after consecutive failures
4. **Embeds the dashboard** — serves the web UI on `--addr` (default `localhost:8800`)
5. **Handles signals** — graceful shutdown on SIGTERM/SIGINT, stops all plugins with 30s timeout

```bash
# Run as a foreground service (suitable for systemd/launchd)
plugger run

# With custom dashboard address
plugger run --addr 0.0.0.0:8800

# Headless (no dashboard)
plugger run --no-dashboard
```

## Web Dashboard

The dashboard at `http://localhost:8800` provides:

- **Plugin tiles** — name, description, status badge, mode, start/stop/restart buttons, "Open UI" link
- **Plugin detail page** — metadata, ports, volumes, environment config, live container status
- **Log streaming** — real-time container logs via Server-Sent Events
- **Config editing** — edit plugin environment variables from the web UI
- **Reverse proxy** — all plugin UIs accessible at `/plugins/{name}/ui/` through the single dashboard port
  - HTML URL rewriting for absolute paths
  - Location header rewriting for redirects
  - JS monkey-patching for fetch/XHR/WebSocket/form submissions

## Configuration

### Global Config (`~/.plugger/config.yaml`)

```yaml
pce:
  host: pce.example.com
  port: 8443
  orgId: 1
  apiKey: api_xxx
  apiSecret: secret_xxx
  tlsSkipVerify: false

plugger:
  dataDir: ~/.plugger
  network: plugger-net
  eventPollInterval: 30

logging:
  level: info
  format: text
```

Environment variables with `PLUGGER_` prefix override config values.

## Plugin Manifests

### Daemon Plugin (runs 24/7)

```yaml
apiVersion: plugger/v1
name: traffic-monitor
version: 2.0.0
image: ghcr.io/illumio/plugger-traffic-monitor:2.0.0

schedule:
  mode: daemon

health:
  endpoint: /healthz
  port: 8080
  interval: 30s
  timeout: 5s
  retries: 3

resources:
  memoryLimit: 256m
  cpuLimit: "0.5"
```

### Cron Plugin (runs on schedule)

```yaml
apiVersion: plugger/v1
name: vuln-sync
version: 1.2.0
image: ghcr.io/illumio/plugger-vuln-sync:1.2.0

schedule:
  mode: cron
  cron: "0 */6 * * *"    # every 6 hours

resources:
  memoryLimit: 512m
```

### Event-Driven Plugin (triggered by webhooks)

```yaml
apiVersion: plugger/v1
name: workload-tagger
version: 0.5.0
image: ghcr.io/illumio/plugger-workload-tagger:0.5.0

schedule:
  mode: event

events:
  types:
    - workload.create
    - workload.update

resources:
  memoryLimit: 128m
```

Event-driven plugins are ephemeral — a new container is spawned for each matching event, runs, and is cleaned up. The event payload is injected as `PLUGGER_EVENT_PAYLOAD`.

## Event-Driven Architecture

Plugger receives events via a webhook endpoint and spawns containers for matching plugins. This decouples event sourcing from event handling — any system that can POST JSON can trigger plugins.

### How It Works

```
PCE Events API ──→ pce-events (polling + matching) ──webhook──→ plugger /api/events/trigger ──→ spawn container
PCE Traffic API ──→ pce-events (traffic watchers) ──webhook──→ plugger /api/events/trigger ──→ spawn container
Any source ──────→ curl POST ──────────────────────────────────→ plugger /api/events/trigger ──→ spawn container
```

1. An event source (e.g. pce-events) sends a POST to `http://plugger:8800/api/events/trigger`
2. Plugger matches `event_type` against installed event-mode plugins' `events.types`
3. For each match: creates an ephemeral container with `PLUGGER_EVENT_PAYLOAD` set to the full event JSON
4. Container runs, processes the event, exits
5. Plugger cleans up the container

### Webhook API

```bash
# Trigger an event (requires Bearer token)
curl -X POST http://localhost:8800/api/events/trigger \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event_type": "workload.create", "resource": {"href": "/orgs/1/workloads/abc"}}'

# Check event stats
curl http://localhost:8800/api/events/stats
```

**Response:**
```json
{
  "event_type": "workload.create",
  "triggered": ["workload-tagger"],
  "skipped": ["traffic-monitor"],
  "errors": {}
}
```

### Authentication

The webhook endpoint requires a Bearer token for security. Set it in config or let plugger auto-generate one:

```yaml
# ~/.plugger/config.yaml
plugger:
  webhookToken: "your-secret-token"
```

If `webhookToken` is not set, `plugger run` generates a random token and prints it at startup.

### Connecting pce-events

Configure pce-events to forward matching events to plugger's webhook:

```yaml
# pce-events config.yaml
watchers:
  "workload\\.create|workload\\.update":
    - plugin: PCEWebhook
      extra_data:
        url: http://plugger:8800/api/events/trigger
        bearer_token: YOUR_TOKEN

  "blocked_traffic":
    - plugin: PCEWebhook
      extra_data:
        url: http://plugger:8800/api/events/trigger
        bearer_token: YOUR_TOKEN
```

### Concurrency

Each event-mode plugin allows up to 5 concurrent containers by default. If the limit is reached, events are dropped with an error logged. This prevents runaway container creation from high-frequency events.

### Example: Auto-Tagger Plugin

```python
# main.py — runs once per event, then exits
import json, os
from illumio import PolicyComputeEngine

event = json.loads(os.environ["PLUGGER_EVENT_PAYLOAD"])
pce = PolicyComputeEngine(url=os.environ["PCE_HOST"], port=os.environ["PCE_PORT"])
pce.set_credentials(username=os.environ["PCE_API_KEY"], password=os.environ["PCE_API_SECRET"])

if event["event_type"] == "workload.create":
    href = event["resource"]["href"]
    # Auto-label the new workload
    pce.put(href, json.dumps({"description": "auto-tagged by plugger"}))
```

## In-Container Metadata (`/.plugger/metadata.yaml`)

Plugins include this file in their Docker image. Plugger discovers it at install time to auto-configure ports, volumes, and config.

```yaml
plugger: v1

ports:
  - port: 8080
    protocol: tcp
    name: web-ui
    type: ui             # ui | api | service | metrics
    path: /

config:
  - name: MY_SETTING
    description: What this does
    required: true
    type: string         # string | int | bool | secret

volumes:
  - path: /data
    description: Persistent storage
    required: true

info:
  title: My Plugin
  description: What it does
  author: Your Name
```

## Plugin Scaffolding

```bash
# Go (compiled, HTTP server, health endpoint)
plugger create my-plugin -t go

# Shell (lightweight, curl + jq)
plugger create my-plugin -t shell

# Python (with Illumio SDK pre-installed)
plugger create my-plugin -t python
```

The Python template includes the [illumio](https://pypi.org/project/illumio/) SDK with a pre-configured `PolicyComputeEngine` client.

**Claude Code users**: Run `/project:build-plugin` to have Claude build a complete plugin from a description.

## Example Plugins

| Plugin | Description | UI |
|--------|-------------|-----|
| `pce-health-monitor` | PCE health status dashboard with endpoint checks | Yes |
| `traffic-reporter` | Traffic flow analysis with Chart.js graphs — top talkers, blocked flows, policy decisions | Yes |
| `policy-diff` | Git-like policy change tracker — field-level diffs, history snapshots, user attribution, audit trail | Yes |
| `pce-events` | Real-time PCE event monitoring (wraps [illumio-pretty-cool-events](https://github.com/alexgoller/illumio-pretty-cool-events)) — Slack, Teams, PagerDuty, 10+ output plugins | Yes |

## Architecture

### Project Structure

```
cmd/plugger/main.go              — Entry point
internal/
├── cli/                         — Cobra CLI commands (init, run, create, install, start, stop, ...)
├── config/                      — Global config, plugin manifest, container metadata types
├── container/
│   ├── runtime.go               — Runtime interface (Docker/K8s abstraction)
│   └── docker.go                — Docker implementation
├── dashboard/                   — Web UI handlers, templates, reverse proxy
├── health/
│   └── checker.go               — HTTP health check runner with failure callbacks
├── lifecycle/
│   └── lifecycle.go             — Shared start/stop/restart logic (used by CLI + dashboard)
├── plugin/                      — Plugin type, state machine, JSON store
├── scheduler/
│   ├── scheduler.go             — Scheduler interface
│   ├── daemon.go                — Daemon scheduler with auto-restart + exponential backoff
│   ├── cron.go                  — Cron scheduler using robfig/cron
│   └── event.go                 — Event scheduler: ephemeral containers triggered by webhooks
└── logging/                     — Structured logging setup (slog)
plugin-templates/                — Plugin starter templates (go, shell, python)
pce-health-monitor/              — Example: PCE health check plugin
traffic-reporter/                — Example: traffic flow analysis plugin
policy-diff/                     — Example: policy change tracker plugin
pce-events/                      — Example: PCE event monitoring plugin
```

## Roadmap

### Done
- [x] CLI with full lifecycle (init, install, start, stop, restart, list, status, logs, create)
- [x] `plugger run` orchestrator with auto-restart, reconciliation, graceful shutdown
- [x] Daemon scheduler with exponential backoff
- [x] Cron scheduler with robfig/cron
- [x] HTTP health checks with restart-on-failure
- [x] Web dashboard with tiles, detail pages, log streaming, config editing
- [x] Reverse proxy for plugin UIs with URL + Location + JS rewriting
- [x] Install from local file, URL, or container image reference
- [x] In-container metadata discovery (ports, config, volumes)
- [x] Plugin scaffolding (Go, shell, Python with Illumio SDK)
- [x] Runtime abstraction (Docker implemented)
- [x] Event-driven scheduling — webhook endpoint triggers ephemeral containers for matching plugins
- [x] Webhook authentication with Bearer token
- [x] 4 example plugins (health monitor, traffic reporter, policy diff, pce-events)

### Planned
- [ ] API key auto-creation and rotation
- [ ] Kubernetes runtime (`KubernetesRuntime` implementing the `Runtime` interface)
- [ ] Plugin registry — `plugger install vuln-sync` from OCI/HTTPS registry
- [ ] Plugin upgrade — `plugger upgrade <name>` pulls latest image and restarts
- [ ] Multi-PCE support — manage plugins across multiple PCE instances
- [ ] Plugin dependencies — declare that one plugin requires another
- [ ] Plugin sandboxing — restrict container capabilities
- [ ] Audit logging

## Building

```bash
make build    # Build binary
make test     # Run tests
make lint     # Lint
make clean    # Clean
```

Requires Go 1.21+ and Docker.

## License

Proprietary — Illumio, Inc.
