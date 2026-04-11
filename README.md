# Plugger — Illumio Plugin Framework

Plugger manages Illumio PCE plugins running as Docker containers. It handles the full plugin lifecycle — install, scheduling, health checks, auto-restart, credential injection, web dashboard, and event-driven automation.

## Key Features

- **`plugger run`** — production orchestrator: starts all plugins, auto-restarts on crash, cron scheduling, health checks, embedded dashboard
- **Three scheduling modes** — daemon (24/7), cron (periodic), event-driven (webhook-triggered ephemeral containers)
- **Web dashboard** — plugin tiles, start/stop/restart, live logs, config editing, reverse proxy for all plugin UIs under one port
- **Install from anywhere** — local file, URL, or container image reference
- **Event-driven automation** — webhook endpoint triggers plugins on PCE events, traffic alerts, or any external source
- **Plugin scaffolding** — `plugger create -t go|shell|python` with Illumio SDK support
- **Runtime abstraction** — Docker today, Kubernetes ready (same interface)

## Quick Start

```bash
make build                                    # Build
plugger init                                  # Initialize config
vim ~/.plugger/config.yaml                    # Set PCE connection
plugger install ./my-plugin/plugin.yaml       # Install a plugin
plugger run                                   # Start everything
```

Dashboard: `http://localhost:8800`

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | First-time setup walkthrough |
| [Installation & Configuration](docs/installation.md) | Prerequisites, config options, Docker socket, networking |
| [CLI Reference](docs/cli-reference.md) | All commands and flags |
| [Plugin Development](docs/plugin-development.md) | Building plugins: manifests, metadata, templates, health checks |
| [Operations Guide](docs/operations.md) | Production deployment, monitoring, troubleshooting |
| [Event-Driven Architecture](docs/events.md) | Webhook triggers, pce-events integration, authentication |
| [Example Plugins](docs/example-plugins.md) | Four ready-to-use plugins |

## Example Plugins

| Plugin | Description | Type |
|--------|-------------|------|
| [pce-health-monitor](pce-health-monitor/) | PCE health dashboard with endpoint checks | Daemon + UI |
| [traffic-reporter](traffic-reporter/) | Interactive traffic flow analysis with Chart.js | Daemon + UI |
| [policy-diff](policy-diff/) | Git-like policy change tracker with history and audit trail | Daemon + UI |
| [pce-events](pce-events/) | Real-time PCE event monitoring — Slack, Teams, PagerDuty, 15+ outputs | Daemon + UI |

## Architecture

```
cmd/plugger/                     — CLI entry point
internal/
├── cli/                         — Cobra commands (init, run, create, install, start, stop, ...)
├── config/                      — Global config, manifest, metadata types
├── container/                   — Runtime interface + Docker implementation
├── dashboard/                   — Web UI, reverse proxy, event webhook handler
├── health/                      — HTTP health checker with restart callbacks
├── lifecycle/                   — Shared start/stop/restart logic
├── scheduler/                   — Daemon (auto-restart), Cron (robfig/cron), Event (webhook-triggered)
├── plugin/                      — Plugin type, state machine, JSON store
└── logging/                     — Structured logging (slog)
plugin-templates/                — Scaffolding templates (Go, Shell, Python)
docs/                            — Documentation
```

## Project Status

### Complete
- Full CLI with lifecycle management
- `plugger run` orchestrator with auto-restart, reconciliation, graceful shutdown
- Daemon scheduling with exponential backoff (1s → 5m, max 5 retries)
- Cron scheduling with robfig/cron
- Event-driven scheduling via webhook with Bearer token auth
- HTTP health checks with restart-on-failure
- Web dashboard with tiles, detail pages, log streaming (SSE), config editing
- Reverse proxy with URL/redirect/JS rewriting for plugin UIs
- Install from local file, URL, or container image reference
- In-container metadata discovery (ports, config, volumes)
- Plugin scaffolding (Go, Shell, Python with Illumio SDK)
- Docker runtime with port mapping, volume mounts, network isolation
- Docker socket configurable via `plugger.dockerSocket` in config
- 4 example plugins verified against live PCE

### Planned
- Kubernetes runtime
- Plugin registry (`plugger install vuln-sync` from OCI)
- Plugin upgrade (`plugger upgrade <name>`)
- API key auto-creation and rotation
- Multi-PCE support

## License

Proprietary — Illumio, Inc.
