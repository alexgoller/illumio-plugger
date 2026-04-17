# Getting Started with Plugger

This guide walks you through installing plugger, connecting to your PCE, and running your first plugin.

## Prerequisites

- **Go 1.21+** — to build plugger from source
- **Docker** — Docker Desktop, Colima, Rancher Desktop, or Docker Engine
- **Illumio PCE** — a running PCE instance with API key access

## Install Plugger

```bash
git clone https://github.com/illumio/plugger.git
cd plugger
make build
```

The binary is built to `./bin/plugger`. Optionally add it to your PATH:

```bash
export PATH=$PATH:$(pwd)/bin
```

## Initialize

```bash
plugger init
```

This runs the interactive setup wizard that:

1. **Creates `~/.plugger/`** with directories for plugins, cache, and volumes
2. **Auto-detects your Docker socket** — checks all common paths:
   - `/var/run/docker.sock` (Linux default)
   - `~/.docker/run/docker.sock` (Docker Desktop on macOS)
   - Colima, Rancher Desktop, Podman sockets
   - `DOCKER_HOST` environment variable
   - Verifies the socket actually responds
3. **Reads PCE credentials** from multiple sources (in priority order):
   - Environment variables (`PCE_HOST`, `PCE_API_KEY`, `PCE_API_SECRET`)
   - `.env` file in the current directory or `~/.plugger/.env`
   - Interactive prompts for anything missing
4. **Tests PCE connectivity** — verifies the PCE is reachable
5. **Writes `~/.plugger/config.yaml`** with all detected settings

### Example Output

```
Plugger Setup
=============

✓ Data directory: /home/user/.plugger
✓ Docker socket: unix:///var/run/docker.sock
✓ Found .env
  PCE host: pce.example.com

Testing PCE connection to pce.example.com:8443...
✓ PCE is reachable

✓ Config written: /home/user/.plugger/config.yaml

Next steps:
  plugger search                    # Browse available plugins
  plugger install pce-health-monitor # Install your first plugin
  plugger run                        # Start everything + dashboard

Dashboard: http://localhost:8800
Registry:  http://localhost:8800/registry
```

### Using a .env File

Create a `.env` file in your working directory with your PCE credentials:

```bash
PCE_HOST=pce.example.com
PCE_PORT=8443
PCE_ORG_ID=1
API_KEY=api_xxxxxxxxxxxx
API_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

`plugger init` will automatically read these values. Both `API_KEY` and `PCE_API_KEY` formats are accepted.

### Non-Interactive Mode

For automation and CI/CD, skip the interactive prompts:

```bash
export PCE_HOST=pce.example.com
export PCE_API_KEY=api_xxx
export PCE_API_SECRET=secret_xxx
plugger init --non-interactive
```

### Getting a PCE API Key

1. Log into the PCE web console
2. Go to **Settings → API Keys** (or your user menu → API Keys)
3. Create a new API key pair
4. Copy the API key and secret into your `.env` file or environment

## Docker Socket Configuration

`plugger init` auto-detects your Docker socket, but you can also set it manually:

### In Config File

```yaml
# ~/.plugger/config.yaml
plugger:
  dockerSocket: unix:///var/run/docker.sock
```

### Via Environment Variable

```bash
export DOCKER_HOST=unix:///path/to/docker.sock
```

### Common Socket Paths

| Platform | Path |
|----------|------|
| Linux (default) | `/var/run/docker.sock` |
| Docker Desktop (macOS) | `~/.docker/run/docker.sock` |
| Colima | `~/.colima/default/docker.sock` |
| Rancher Desktop | `~/.rd/docker.sock` |
| Podman | `/run/user/{uid}/podman/podman.sock` |

## Install Your First Plugin

Browse and install from the plugin registry:

```bash
# Search available plugins
plugger search

# Install from registry (pulls image automatically)
plugger install pce-health-monitor

# Start it
plugger start pce-health-monitor

# Check status
plugger status pce-health-monitor
```

Or browse the registry in the dashboard: `http://localhost:8800/registry`

## View the Dashboard

```bash
plugger dashboard
```

Open `http://localhost:8800` in your browser. Features:
- Plugin tiles with status badges and "Open UI" links
- Dark / light / auto theme (follows system preference)
- Plugin registry browser at `/registry`

## Run Everything

For production use, `plugger run` starts all plugins with auto-restart, health checks, and the dashboard:

```bash
plugger run
```

This is the recommended way to run plugger. It:
- Starts all enabled plugins
- Auto-restarts daemons on crash (exponential backoff)
- Runs health checks
- Schedules cron plugins
- Listens for event webhooks
- Serves the dashboard

## Quick Reference

```bash
plugger init                        # Setup wizard
plugger search                      # Browse plugins
plugger install <name>              # Install from registry
plugger install ./plugin.yaml       # Install from file
plugger run                         # Start everything
plugger list                        # Show all plugins
plugger status                      # Overview
plugger status <name>               # Plugin detail
plugger logs <name> -f              # Follow logs
plugger outdated                    # Check for updates
plugger upgrade <name>              # Upgrade a plugin
```

## Create Your Own Plugin

```bash
# Go plugin (compiled, HTTP server)
plugger create my-plugin -t go

# Shell plugin (curl + jq)
plugger create my-plugin -t shell

# Python plugin (with Illumio SDK)
plugger create my-plugin -t python
```

Then edit the generated files, build a Docker image, and install.

See the [Plugin Development Guide](plugin-development.md) for details.

## Next Steps

- [Installation & Configuration](installation.md) — detailed config reference
- [CLI Reference](cli-reference.md) — all commands and flags
- [Plugin Development](plugin-development.md) — building your own plugins
- [Operations Guide](operations.md) — production deployment, troubleshooting
- [Example Plugins](example-plugins.md) — six ready-to-use plugins
- [Event-Driven Architecture](events.md) — webhook-triggered plugins
- [Plugin Portal](https://alexgoller.github.io/illumio-plugger/) — browse and install plugins online
