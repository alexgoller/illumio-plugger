# Installation & Configuration

## Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Go | 1.21+ | Only needed to build from source |
| Docker | 20.10+ | Any OCI runtime — see below |
| Illumio PCE | 21.2+ | With API key access |

### Installing Docker

Plugger runs every plugin as a container, so you need a Docker-compatible
runtime. If `docker version` doesn't work yet, pick one:

| Runtime | Platform | Get it |
|---------|----------|--------|
| **Docker Desktop** | macOS / Windows / Linux | https://www.docker.com/products/docker-desktop/ |
| **Docker Engine** | Linux (headless/servers) | https://docs.docker.com/engine/install/ |
| **Colima** | macOS / Linux (lightweight, CLI) | https://github.com/abiosoft/colima |
| **Rancher Desktop** | macOS / Windows / Linux | https://rancherdesktop.io/ |
| **Podman** | macOS / Windows / Linux | https://podman.io/getting-started/installation |

General Docker install index: https://docs.docker.com/get-docker/

After installing, verify the daemon is running and reachable:

```bash
docker version   # both Client and Server sections should print
```

`plugger init` auto-detects the socket for all of the runtimes above (see
[Docker Socket](#docker-socket)).

## Building from Source

```bash
git clone https://github.com/illumio/plugger.git
cd plugger
make build
```

Build targets:

```bash
make build    # Build binary to bin/plugger
make test     # Run tests
make lint     # Run linter
make clean    # Remove build artifacts
make install  # Install to $GOPATH/bin
```

## Configuration

### Initialize

```bash
plugger init
```

Creates `~/.plugger/` with:
- `config.yaml` — global configuration
- `plugins.json` — plugin state store (auto-managed)

### Global Config (`~/.plugger/config.yaml`)

```yaml
pce:
  host: pce.example.com        # PCE hostname (required)
  port: 443                     # PCE port (default: 443)
  orgId: 1                      # Organization ID (default: 1)
  apiKey: api_xxx               # PCE API key (required)
  apiSecret: secret_xxx         # PCE API secret (required)
  tlsSkipVerify: false          # Skip TLS verification (default: false)

plugger:
  dataDir: ~/.plugger           # Data directory (default: ~/.plugger)
  network: plugger-net          # Docker network name (default: plugger-net)
  eventPollInterval: 30         # PCE event poll interval in seconds
  webhookToken: ""              # Webhook auth token (auto-generated if empty)

logging:
  level: info                   # debug | info | warn | error
  format: text                  # text | json
  file: ""                      # Optional log file path
```

### Environment Variable Overrides

All config values can be overridden via environment variables with the `PLUGGER_` prefix:

```bash
export PLUGGER_PCE_HOST=pce.example.com
export PLUGGER_PCE_APIKEY=api_xxx
export PLUGGER_LOGGING_LEVEL=debug
```

### Custom Config Path

```bash
plugger --config /path/to/config.yaml run
```

### Docker Socket

`plugger init` auto-detects your Docker socket. You can also set it manually:

```yaml
# In config.yaml
plugger:
  dockerSocket: unix:///var/run/docker.sock
```

Or via environment variable:

```bash
export DOCKER_HOST=unix:///path/to/docker.sock
```

**Auto-detected paths** (checked in order):
| Platform | Path |
|----------|------|
| `DOCKER_HOST` env | Whatever is set |
| Linux default | `/var/run/docker.sock` |
| Docker Desktop (macOS) | `~/.docker/run/docker.sock` |
| Colima | `~/.colima/default/docker.sock` |
| Rancher Desktop | `~/.rd/docker.sock` |
| Podman | `/run/user/{uid}/podman/podman.sock` |

### .env File Support

`plugger init` reads `.env` files from the current directory or `~/.plugger/.env`:

```bash
# .env
PCE_HOST=pce.example.com
PCE_PORT=8443
PCE_ORG_ID=1
API_KEY=api_xxxxxxxxxxxx
API_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Both `API_KEY` and `PCE_API_KEY` formats are accepted.

## Installing Plugins

Plugger supports four install sources:

### Registry Name (recommended)

```bash
plugger install pce-health-monitor
```

Looks up the plugin in configured registries, pulls the image from GHCR.

### Local Manifest File

```bash
plugger install ./my-plugin/plugin.yaml
```

### Remote URL

```bash
plugger install https://raw.githubusercontent.com/org/repo/main/plugin.yaml
```

### Container Image Reference

```bash
plugger install ghcr.io/org/my-plugin:v1.0
```

This pulls the image, extracts the manifest from `/.plugger/manifest.yaml` inside the container, and discovers metadata from `/.plugger/metadata.yaml`.

### Install with Environment Overrides

```bash
plugger install ./plugin.yaml \
  -e MY_SETTING=custom-value \
  -e MY_SECRET=s3cr3t
```

## Networking

Plugger creates a dedicated Docker bridge network (`plugger-net` by default) for all plugin containers. Plugins can reach:

- The PCE (outbound internet/intranet)
- Each other by container name (e.g. `plugger-pce-events`)
- The host machine (for the dashboard reverse proxy)

## Data Directory Layout

```
~/.plugger/
├── config.yaml           # Global configuration
├── plugins.json          # Plugin state store
└── volumes/              # Plugin persistent volumes
    ├── plugin-a/
    │   └── data/         # Mounted to /data in the container
    └── plugin-b/
        └── data/
```
