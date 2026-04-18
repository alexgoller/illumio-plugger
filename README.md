# Plugger — Illumio Plugin Framework

Plugger manages Illumio PCE plugins running as Docker containers. It handles the full plugin lifecycle — install, scheduling, health checks, auto-restart, credential injection, web dashboard, plugin registry, and event-driven automation.

## Key Features

- **`plugger run`** — production orchestrator: starts all plugins, auto-restarts on crash, cron scheduling, health checks, embedded dashboard
- **Three scheduling modes** — daemon (24/7), cron (periodic), event-driven (webhook-triggered ephemeral containers)
- **Web dashboard** — plugin tiles, start/stop/restart, live logs, config editing, dark/light/auto theme
- **Reverse proxy** — all plugin UIs consolidated under one port with URL/JS rewriting
- **Plugin registry** — search, install by name, check for updates, custom repos
- **Install from anywhere** — local file, URL, container image, or registry name
- **AI-assisted policy** — blocked traffic analysis, tiered rule generation, LLM-powered recommendations, one-click provisioning
- **Event-driven automation** — webhook endpoint triggers plugins on PCE events, traffic alerts, or any external source
- **Plugin scaffolding** — `plugger create -t go|shell|python` with Illumio SDK support
- **Runtime abstraction** — Docker today, Kubernetes ready (same interface)

## Quick Start

```bash
make build                                    # Build
plugger init                                  # Initialize config
vim ~/.plugger/config.yaml                    # Set PCE connection
plugger search                                # Browse available plugins
plugger install pce-health-monitor            # Install from registry
plugger run                                   # Start everything
```

Dashboard: `http://localhost:8800` | Registry: `http://localhost:8800/registry`

Plugin Portal: [alexgoller.github.io/illumio-plugger](https://alexgoller.github.io/illumio-plugger/)

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | First-time setup walkthrough |
| [Installation & Configuration](docs/installation.md) | Prerequisites, config options, Docker socket, networking |
| [CLI Reference](docs/cli-reference.md) | All commands and flags |
| [Plugin Development](docs/plugin-development.md) | Building plugins: manifests, metadata, templates, health checks |
| [Operations Guide](docs/operations.md) | Production deployment, monitoring, troubleshooting |
| [Event-Driven Architecture](docs/events.md) | Webhook triggers, pce-events integration, authentication |
| [Example Plugins](docs/example-plugins.md) | Six ready-to-use plugins |

## Plugins

| Plugin | Description | Type |
|--------|-------------|------|
| [pce-health-monitor](pce-health-monitor/) | PCE health dashboard with endpoint checks | Daemon + UI |
| [traffic-reporter](traffic-reporter/) | Interactive traffic flow analysis with Chart.js — top talkers, blocked flows, Sankey diagram | Daemon + UI |
| [policy-diff](policy-diff/) | Git-like policy change tracker — field-level diffs, history snapshots, user attribution | Daemon + UI |
| [pce-posture-report](pce-posture-report/) | Security posture scoring — enforcement, labels, policy coverage, HTML+JSON reports | Cron |
| [pce-events](pce-events/) | Real-time PCE event monitoring — Slack, Teams, PagerDuty, 15+ output plugins | Daemon + UI |
| [ai-assisted-rules](ai-assisted-rules/) | Policy advisor — tiered rule generation, AI analysis, infrastructure detection, label gaps, auto-provisioning | Daemon + UI |
| [stale-workloads](stale-workloads/) | Discover offline, unresponsive, and trafficless workloads with optional cleanup | Daemon + UI |
| [palo-alto-dag-sync](palo-alto-dag-sync/) | Sync Illumio labels to Palo Alto Dynamic Address Groups via PAN-OS XML API | Daemon + UI |

Install any plugin from the registry:
```bash
plugger install pce-health-monitor
plugger install traffic-reporter
plugger install ai-assisted-rules
```

## Plugin Registry

Browse and install plugins from the CLI or the web dashboard.

```bash
plugger search                          # List all available plugins
plugger search monitoring               # Search by keyword
plugger install pce-health-monitor      # Install by name from registry
plugger outdated                        # Check for updates
plugger upgrade traffic-reporter        # Pull latest, restart
plugger repo list                       # Show configured registries
plugger repo add myco https://internal.example.com/registry.json
```

**Dashboard**: `http://localhost:8800/registry` — browse plugins, filter by mode/tags, one-click install.

**Custom registries**: host a `registry.json` at any URL with the same format as the [official registry](https://alexgoller.github.io/illumio-plugger/registry.json).

## AI-Assisted Rules

The `ai-assisted-rules` plugin analyzes blocked traffic and generates PCE-ready policy suggestions:

- **Application Policy view** — per-app cards showing intra-scope, extra-scope incoming/outgoing, and IP traffic
- **Three security tiers** — Basic Ringfencing (all↔all), Application Tiered (role→role), High Security (role→role + specific services)
- **Infrastructure detection** — consolidates monitoring, syslog, NTP, jump hosts into broad rules
- **Risky service flagging** — FTP, telnet, RDP, SMB auto-flagged into FOR REVIEW rulesets
- **Extra-scope rules** — proper Illumio extra-scope format with unscoped consumers
- **AI analysis** (optional) — Anthropic/OpenAI/Ollama powered recommendations with risk assessment
- **Label gap detection** — finds workloads missing roles, suggests labels from traffic patterns + AI
- **One-click provisioning** — creates draft rulesets on the PCE

## Architecture

```
cmd/plugger/                     — CLI entry point
internal/
├── cli/                         — Cobra commands (init, run, create, install, search, upgrade, ...)
├── config/                      — Global config, manifest, metadata types
├── container/                   — Runtime interface + Docker implementation
├── dashboard/                   — Web UI, reverse proxy, registry browser, event webhook
├── health/                      — HTTP health checker with restart callbacks
├── lifecycle/                   — Shared start/stop/restart logic
├── registry/                    — Plugin registry: fetch, search, update checks, repo management
├── scheduler/
│   ├── daemon.go                — Auto-restart with exponential backoff
│   ├── cron.go                  — Cron scheduling (robfig/cron)
│   └── event.go                 — Webhook-triggered ephemeral containers
├── plugin/                      — Plugin type, state machine, JSON store
└── logging/                     — Structured logging (slog)
plugin-templates/                — Scaffolding templates (Go, Shell, Python)
docs/                            — Documentation
docs/portal/                     — GitHub Pages: plugin portal + registry.json
```

## Project Status

### Complete
- Full CLI: init, create, install, uninstall, start, stop, restart, list, status, logs, run, dashboard, version
- Plugin registry: search, install by name, outdated, upgrade, repo add/remove, web browser
- `plugger run` orchestrator with auto-restart, reconciliation, graceful shutdown
- Daemon scheduling with exponential backoff (1s → 5m, max 5 retries)
- Cron scheduling with robfig/cron
- Event-driven scheduling via webhook with Bearer token auth
- HTTP health checks with restart-on-failure
- Web dashboard with tiles, detail pages, log streaming (SSE), config editing
- Dark/light/auto theme toggle (follows system preference)
- Reverse proxy with URL/redirect/JS rewriting for plugin UIs
- Plugin registry with GitHub Pages hosting and custom repo support
- Install from local file, URL, container image, or registry name
- In-container metadata discovery (ports, config, volumes)
- Plugin scaffolding (Go, Shell, Python with Illumio SDK)
- Docker runtime with port mapping, volume mounts, network isolation
- Docker socket configurable in config
- CI pipelines: Go build/test, multi-arch plugin images (GHCR), GitHub Pages deployment
- 8 example plugins verified against live PCE
- AI-assisted policy with tiered generation, infrastructure detection, label gaps

### Planned
- Kubernetes runtime
- API key auto-creation and rotation
- Multi-PCE support

## License

Proprietary — Illumio, Inc.
