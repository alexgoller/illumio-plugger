# Plugger — Illumio Plugin Framework

Plugger manages Illumio PCE plugins running as Docker containers (or Kubernetes pods). It handles the full plugin lifecycle: install, start, stop, restart, logging, credential injection, health checks, and scheduling.

## Features

- **Container-based plugins** — each plugin runs as an isolated Docker container
- **Three scheduling modes** — daemon (24/7), cron (periodic), event-driven (PCE events)
- **Automatic credential injection** — PCE API keys and config passed as environment variables
- **Runtime abstraction** — Docker today, Kubernetes tomorrow (same interface)
- **Plugin state tracking** — JSON-backed store with crash recovery
- **Resource limits** — memory and CPU constraints per plugin
- **Structured logging** — slog-based with JSON or text output
- **Plugin scaffolding** — `plugger create` generates Go, shell, or Python plugin projects
- **In-container metadata** — plugins declare ports, config, volumes via `/.plugger/metadata.yaml`

## Quick Start

```bash
# Build
make build

# Initialize config directory
./bin/plugger init

# Edit PCE connection details
vim ~/.plugger/config.yaml

# Install a plugin from a manifest
./bin/plugger install ./examples/hello-world.plugin.yaml

# Start it
./bin/plugger start hello-world

# View logs
./bin/plugger logs hello-world -f

# Check status
./bin/plugger status hello-world

# Stop it
./bin/plugger stop hello-world

# List all plugins
./bin/plugger list

# Uninstall
./bin/plugger uninstall hello-world
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `plugger init` | Create `~/.plugger/` and default `config.yaml` |
| `plugger create <name> [-t go\|shell\|python]` | Scaffold a new plugin project from a template |
| `plugger install <manifest.yaml>` | Install a plugin from a manifest file |
| `plugger uninstall <name>` | Remove a plugin and its container |
| `plugger start <name>` | Start a plugin container |
| `plugger stop <name>` | Stop a running plugin container |
| `plugger restart <name>` | Restart a plugin container |
| `plugger list` | List all installed plugins and their state |
| `plugger status <name>` | Show detailed plugin status |
| `plugger logs <name> [-f] [-n 100]` | View plugin container logs |
| `plugger version` | Print the plugger version |

### Global Flags

| Flag | Description |
|------|-------------|
| `--config <path>` | Path to config file (default: `~/.plugger/config.yaml`) |

### Install Flags

| Flag | Description |
|------|-------------|
| `-e, --env KEY=VALUE` | Set environment variable overrides (repeatable) |

### Logs Flags

| Flag | Description |
|------|-------------|
| `-f, --follow` | Follow log output |
| `-n, --tail <lines>` | Number of lines to show (default: 100) |
| `--since <duration>` | Show logs since timestamp or relative duration (e.g. `1h`) |

## Configuration

### Global Config (`~/.plugger/config.yaml`)

Created by `plugger init`. Edit this to set your PCE connection details.

```yaml
pce:
  host: pce.example.com        # PCE hostname
  port: 8443                    # PCE port
  orgId: 1                      # PCE organization ID
  apiKey: api_xxx               # PCE API key
  apiSecret: secret_xxx         # PCE API secret
  tlsSkipVerify: false          # Skip TLS certificate verification

plugger:
  dataDir: ~/.plugger           # Data directory for plugin state
  network: plugger-net          # Docker network name
  eventPollInterval: 30         # PCE event poll interval (seconds)

logging:
  level: info                   # Log level: debug, info, warn, error
  format: text                  # Log format: text, json
  # file: ~/.plugger/plugger.log  # Optional log file
```

Environment variables with the `PLUGGER_` prefix override config values (e.g. `PLUGGER_PCE_HOST`).

## Plugin Manifests

Plugins are defined by YAML manifest files. Three scheduling modes are supported.

### Daemon Plugin (runs 24/7)

```yaml
apiVersion: plugger/v1
name: traffic-monitor
version: 2.0.0
image: ghcr.io/illumio/plugger-traffic-monitor:2.0.0

schedule:
  mode: daemon

env:
  - name: MONITOR_INTERVAL
    required: false
    default: "60"

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

### Cron Plugin (runs on a schedule)

```yaml
apiVersion: plugger/v1
name: vuln-sync
version: 1.2.0
image: ghcr.io/illumio/plugger-vuln-sync:1.2.0

schedule:
  mode: cron
  cron: "0 */6 * * *"    # every 6 hours

env:
  - name: VULN_SOURCE_URL
    required: true
  - name: VULN_BATCH_SIZE
    required: false
    default: "100"

resources:
  memoryLimit: 512m
  cpuLimit: "1.0"
```

### Event-Driven Plugin (triggered by PCE events)

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

env:
  - name: TAG_PREFIX
    required: false
    default: "auto"
```

### Manifest Reference

| Field | Required | Description |
|-------|----------|-------------|
| `apiVersion` | no | Manifest version (currently `plugger/v1`) |
| `name` | **yes** | Unique plugin name |
| `version` | **yes** | Plugin version (semver) |
| `image` | **yes** | Docker image reference |
| `schedule.mode` | **yes** | `daemon`, `cron`, or `event` |
| `schedule.cron` | cron only | Cron expression |
| `env[]` | no | Environment variables |
| `env[].name` | **yes** | Variable name |
| `env[].required` | no | Whether the variable must be set |
| `env[].default` | no | Default value |
| `env[].secret` | no | Mask value in status output |
| `events.types` | event only | PCE event types to subscribe to |
| `events.filter` | no | Optional filter expression |
| `health.endpoint` | no | HTTP health check path |
| `health.port` | no | Health check port |
| `health.interval` | no | Check interval |
| `health.timeout` | no | Check timeout |
| `health.retries` | no | Failures before unhealthy |
| `resources.memoryLimit` | no | Memory limit (e.g. `256m`, `1g`) |
| `resources.cpuLimit` | no | CPU limit (e.g. `0.5`, `2.0`) |

## Environment Variables Injected into Plugins

Every plugin container receives these environment variables from the global config:

| Variable | Description |
|----------|-------------|
| `PCE_HOST` | PCE hostname |
| `PCE_PORT` | PCE port |
| `PCE_ORG_ID` | PCE organization ID |
| `PCE_API_KEY` | PCE API key |
| `PCE_API_SECRET` | PCE API secret |

Plus any variables defined in the plugin manifest `env` section, with user overrides taking priority over manifest defaults.

For event-driven plugins, `PLUGGER_EVENT_PAYLOAD` contains the JSON of the triggering PCE event.

## In-Container Metadata Discovery

Plugins can include a `/.plugger/metadata.yaml` file inside their Docker image. Plugger discovers this file at `plugger install` time and uses it to auto-configure ports, volumes, and validate config requirements.

### How It Works

1. `plugger install` pulls the image
2. Plugger creates a temp container, extracts `/.plugger/metadata.yaml`, and removes the container
3. Discovered ports are auto-exposed when the plugin starts
4. Discovered volumes get host directories created under `~/.plugger/volumes/<plugin>/`
5. Discovered config requirements are validated against provided `--env` overrides
6. Plugin info is displayed in `plugger status`

### Metadata Schema (`/.plugger/metadata.yaml`)

```yaml
plugger: v1

ports:
  - port: 8080
    protocol: tcp          # tcp or udp
    name: web-ui
    description: Plugin dashboard
    type: ui               # ui | api | service | metrics
    path: /                # base URL path

config:
  - name: MY_SETTING
    description: What this setting does
    required: true
    type: string           # string | int | bool | secret
    default: "value"
    validation: "^[a-z]+$" # optional regex

volumes:
  - path: /data
    description: Persistent plugin state
    required: true

info:
  title: My Plugin
  description: What the plugin does
  author: Your Name
  license: Apache-2.0
  homepage: https://github.com/your-org/your-plugin

healthcheck:
  endpoint: /healthz
  port: 8080
  interval: 30s
```

### Plugin Scaffolding

Use `plugger create` to scaffold a new plugin project:

```bash
# Go plugin (compiled, with HTTP server and health endpoint)
plugger create my-plugin -t go

# Shell plugin (lightweight, curl + jq based)
plugger create my-plugin -t shell

# Python plugin (with Illumio SDK pre-installed)
plugger create my-plugin -t python
```

The Python template includes the [illumio](https://pypi.org/project/illumio/) SDK with a pre-configured `PolicyComputeEngine` client, so you can call `pce.workloads.get()`, `pce.labels.get()`, etc. immediately.

Templates are also available in `plugin-templates/go/`, `plugin-templates/shell/`, and `plugin-templates/python/`.

**Claude Code users**: Run `/project:build-plugin` to have Claude build a complete plugin from a description.

## Architecture

### Runtime Abstraction

Plugger uses a `Runtime` interface to abstract container orchestration:

```
Runtime interface
├── DockerRuntime       (implemented — uses Docker Engine API)
└── KubernetesRuntime   (planned — will use client-go to manage Pods)
```

All CLI commands, schedulers, and state management work against this interface. Switching from Docker to Kubernetes requires zero changes outside the runtime implementation.

### Container Management

- Containers are named `plugger-<plugin-name>` for deterministic identification
- Labels (`io.plugger.managed`, `io.plugger.plugin`, etc.) enable discovery and crash recovery
- A dedicated Docker bridge network (`plugger-net`) provides network isolation
- Plugin state is persisted in `~/.plugger/plugins.json` with atomic writes

### Project Structure

```
cmd/plugger/main.go              — Entry point
internal/
├── cli/                         — Cobra CLI commands
├── config/
│   ├── config.go                — Global config (viper + YAML)
│   ├── manifest.go              — Plugin manifest parsing
│   └── metadata.go              — In-container metadata types + parsing
├── container/
│   ├── runtime.go               — Runtime interface (Docker/K8s abstraction)
│   ├── docker.go                — Docker implementation + CopyFromImage
│   └── network.go               — Network setup
├── plugin/
│   ├── plugin.go                — Plugin type, state machine, env building
│   └── store.go                 — JSON file-backed plugin store
└── logging/
    └── logging.go               — Structured logging setup (slog)
plugin-templates/
├── go/                          — Go plugin template (compiled, HTTP server)
│   ├── main.go, Dockerfile, plugin.yaml, .plugger/metadata.yaml
│   └── README.md
├── shell/                       — Shell plugin template (curl + jq)
│   ├── entrypoint.sh, Dockerfile, plugin.yaml, .plugger/metadata.yaml
│   └── README.md
└── python/                      — Python plugin template (illumio SDK)
    ├── main.py, Dockerfile, requirements.txt, plugin.yaml, .plugger/metadata.yaml
    └── README.md
.claude/commands/
└── build-plugin.md              — Claude Code slash command for building plugins
```

## Roadmap

### Phase 2: Orchestrator + Scheduling
- [ ] `plugger run` command — start all enabled plugins, handle signals, reconcile state on startup
- [ ] Daemon scheduler — auto-restart on failure with exponential backoff (1s to 5m cap, max 5 consecutive failures)
- [ ] Cron scheduler — run plugins on a cron schedule using `robfig/cron`
- [ ] Health checks — HTTP health check runner for daemon plugins
- [ ] Container log forwarding — capture stdout/stderr into structured logging
- [ ] Graceful shutdown — stop daemons (30s timeout), wait for in-progress cron/event containers (60s deadline)

### Phase 3: Event-Driven + PCE Integration
- [ ] PCE REST API client — minimal client with basic auth via API key/secret
- [ ] PCE event poller — poll `/api/v2/orgs/:orgId/events` with cursor persistence
- [ ] Event scheduler — match events to plugin subscriptions, trigger containers with event payload
- [ ] `plugger events` command — list event subscriptions and recent matched events
- [ ] Bounded concurrency — semaphore to limit concurrent event-triggered containers per plugin

### Phase 4: Dashboard + Web UI
- [ ] Embedded HTTP server in `plugger run` or standalone `plugger dashboard` command
- [ ] Web UI showing plugin status, logs, health, and controls (start/stop/restart)
- [ ] Real-time log streaming via WebSocket
- [ ] Plugin metrics and history visualization

### Phase 5: API Key Management
- [ ] Automatic PCE API key creation — `plugger init` or `plugger pce setup` creates a dedicated API key via PCE REST API
- [ ] API key rotation — background goroutine in `plugger run` that creates new key, updates running containers, deletes old key
- [ ] Configurable rotation schedule
- [ ] Per-plugin API keys with scoped permissions

### Phase 6: Kubernetes Runtime
- [ ] `KubernetesRuntime` implementing the `Runtime` interface using client-go
- [ ] Map plugins to Kubernetes Pods/Jobs/CronJobs
- [ ] `runtime: docker|kubernetes` config field to select runtime
- [ ] Namespace isolation per plugin
- [ ] ConfigMap/Secret injection for credentials

### Phase 7: Plugin Registry + Distribution
- [ ] Plugin registry support — resolve `plugger install vuln-sync` from OCI or HTTPS registry
- [ ] `plugger search` — search available plugins
- [ ] Plugin versioning and upgrade — `plugger upgrade <name>`
- [ ] Plugin signing and verification

### Future Ideas
- [ ] `plugger config set <plugin> KEY=VALUE` — manage env overrides without reinstalling
- [ ] PCE connectivity check — `plugger check` pings the PCE and validates credentials
- [ ] Plugin dependencies — declare that one plugin requires another
- [ ] Traffic event subscription — poll PCE traffic flow summaries and trigger plugins
- [ ] Multi-PCE support — manage plugins across multiple PCE instances
- [ ] Alerting/notification hooks — Slack, email, webhook on plugin failure
- [ ] Plugin sandboxing — restrict container capabilities and filesystem access
- [ ] Audit logging — track all plugin actions and PCE API calls

## Building

```bash
# Build binary
make build

# Run tests
make test

# Lint
make lint

# Clean build artifacts
make clean
```

Requires Go 1.21+ and Docker.

## License

Proprietary — Illumio, Inc.
