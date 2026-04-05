# Shell Plugin Template

A lightweight shell-based plugin for the Plugger framework. Uses `curl` and `jq` for PCE API calls — no compiled language needed.

## Files

| File | Purpose |
|------|---------|
| `entrypoint.sh` | Plugin logic with daemon/cron/event mode support |
| `Dockerfile` | Alpine-based image with curl + jq |
| `plugin.yaml` | Install manifest |
| `.plugger/metadata.yaml` | Container metadata for plugger discovery |

## Usage

```bash
# Build
docker build -t my-shell-plugin:latest .

# Install and run
plugger install plugin.yaml
plugger start my-shell-plugin
plugger logs my-shell-plugin -f
```

## Modes

The entrypoint supports all three modes via the `PLUGIN_MODE` env var (defaults to `daemon`):

- **daemon** — runs a loop with configurable `POLL_INTERVAL`
- **cron** — runs once and exits
- **event** — reads `PLUGGER_EVENT_PAYLOAD` and exits

## Making PCE API Calls

The `pce_api` helper function handles authentication:

```bash
# List workloads
pce_api GET /workloads

# Get a specific workload
pce_api GET /workloads/abc123

# Update a workload
pce_api PUT /workloads/abc123 -d '{"description": "updated"}'

# Create a label
pce_api POST /labels -d '{"key": "env", "value": "prod"}'
```
