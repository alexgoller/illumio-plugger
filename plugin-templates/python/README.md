# Python Plugin Template

A Python-based plugin for the Plugger framework with the [Illumio Python SDK](https://github.com/illumio/illumio-py) pre-installed.

## Files

| File | Purpose |
|------|---------|
| `main.py` | Plugin entrypoint with PCE client, daemon/cron/event modes |
| `requirements.txt` | Python dependencies (illumio SDK) |
| `Dockerfile` | Python 3.12 slim image with illumio SDK |
| `plugin.yaml` | Install manifest |
| `.plugger/metadata.yaml` | Container metadata for plugger discovery |

## Usage

```bash
# Build
docker build -t my-plugin:latest .

# Install and run
plugger install plugin.yaml
plugger start my-plugin
plugger logs my-plugin -f
```

## Illumio SDK Quick Reference

The template sets up an authenticated `PolicyComputeEngine` client from the environment variables that plugger injects.

```python
from illumio import PolicyComputeEngine

pce = get_pce()  # helper from template — reads PCE_HOST, PCE_API_KEY, etc.

# List workloads
workloads = pce.workloads.get()

# Filter workloads
managed = pce.workloads.get(params={"managed": True})

# List labels
labels = pce.labels.get()
env_labels = pce.labels.get(params={"key": "env"})

# List rulesets
rulesets = pce.rulesets.get()

# List label groups
label_groups = pce.label_groups.get()

# List IP lists
ip_lists = pce.ip_lists.get()

# List services
services = pce.services.get()
```

## Adding Dependencies

Add packages to `requirements.txt`:

```
illumio
requests
pandas
```

They'll be installed during `docker build`.

## Modes

The entrypoint supports all three modes via the `PLUGIN_MODE` env var (defaults to `daemon`):

- **daemon** — runs `do_work()` in a loop with configurable `POLL_INTERVAL`
- **cron** — runs `do_work()` once and exits
- **event** — reads `PLUGGER_EVENT_PAYLOAD` and calls `handle_event()`
