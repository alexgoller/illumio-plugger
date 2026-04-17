# Getting Started with Plugger

This guide walks you through installing plugger, connecting to your PCE, and running your first plugin.

## Prerequisites

- **Go 1.21+** — to build plugger from source
- **Docker** — Docker Desktop or Docker Engine with the daemon running
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

This creates `~/.plugger/` with a default `config.yaml`.

## Configure PCE Connection

Edit `~/.plugger/config.yaml` with your PCE details:

```yaml
pce:
  host: pce.example.com
  port: 8443
  orgId: 1
  apiKey: api_xxxxxxxxxxxx
  apiSecret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  tlsSkipVerify: false

plugger:
  dataDir: ~/.plugger
  network: plugger-net

logging:
  level: info
  format: text
```

### Getting a PCE API Key

1. Log into the PCE web console
2. Go to **Settings → API Keys** (or your user menu → API Keys)
3. Create a new API key pair
4. Copy the API key and secret into the config

## Install Your First Plugin

The easiest way is to install from the plugin registry:

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

## View the Dashboard

```bash
plugger dashboard
```

Open `http://localhost:8800` in your browser. You'll see your plugin with a status tile and an "Open UI" link.

## Run Everything

For production use, `plugger run` starts all plugins with auto-restart, health checks, and the dashboard:

```bash
plugger run
```

This is the recommended way to run plugger. It:
- Starts all enabled plugins
- Auto-restarts daemons on crash
- Runs health checks
- Schedules cron plugins
- Serves the dashboard

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

- [Installation & Configuration](installation.md) — detailed setup options
- [CLI Reference](cli-reference.md) — all commands and flags
- [Plugin Development](plugin-development.md) — building your own plugins
- [Operations Guide](operations.md) — production deployment, monitoring, troubleshooting
- [Example Plugins](example-plugins.md) — six ready-to-use plugins
- [Event-Driven Architecture](events.md) — webhook-triggered plugins
- [Plugin Portal](https://alexgoller.github.io/illumio-plugger/) — browse and install plugins online
