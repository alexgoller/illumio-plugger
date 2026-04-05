# Plugger Plugin Template

This is a template for building plugins that run in the [Plugger](https://github.com/illumio/plugger) framework.

## Files

| File | Purpose |
|------|---------|
| `main.go` | Plugin entrypoint with signal handling, HTTP server, and PCE config loading |
| `Dockerfile` | Multi-stage build producing a minimal container image |
| `plugin.yaml` | Install manifest — tells plugger how to schedule and configure the plugin |
| `.plugger/metadata.yaml` | In-container metadata — tells plugger what ports, config, and volumes the plugin needs |
| `go.mod` | Go module definition |

## How It Works

### The Two Manifests

Plugins use two YAML files with different purposes:

**`plugin.yaml`** (install manifest) — lives in your repo, used by `plugger install`:
- Plugin name, version, image reference
- Scheduling mode (daemon/cron/event)
- Environment variables and their defaults
- Resource limits

**`.plugger/metadata.yaml`** (container metadata) — baked into the Docker image, discovered by plugger at install time:
- Ports the plugin exposes (plugger auto-maps them to the host)
- Extra config requirements (plugger validates at install)
- Volume mounts (plugger creates host directories)
- Plugin info for display in `plugger status` and the dashboard

### Environment Variables

Plugger injects these into every plugin container:

| Variable | Description |
|----------|-------------|
| `PCE_HOST` | PCE hostname |
| `PCE_PORT` | PCE port |
| `PCE_ORG_ID` | PCE organization ID |
| `PCE_API_KEY` | PCE API key |
| `PCE_API_SECRET` | PCE API secret |

Plus any variables from `plugin.yaml` env section and `metadata.yaml` config section.

For event-driven plugins, `PLUGGER_EVENT_PAYLOAD` contains the triggering PCE event as JSON.

## Getting Started

1. **Copy this template**:
   ```bash
   cp -r plugin-template my-plugin
   cd my-plugin
   ```

2. **Edit the files**:
   - `main.go` — add your plugin logic
   - `plugin.yaml` — set your plugin name, image, schedule
   - `.plugger/metadata.yaml` — declare your ports, config, volumes
   - `go.mod` — set your module path

3. **Build the image**:
   ```bash
   docker build -t my-plugin:latest .
   ```

4. **Install and run**:
   ```bash
   plugger install plugin.yaml
   plugger start my-plugin
   plugger logs my-plugin -f
   plugger status my-plugin
   ```

## Plugin Types

### Daemon Plugin
Runs 24/7. Use for continuous monitoring, long-polling, or serving a UI.

```yaml
# plugin.yaml
schedule:
  mode: daemon
```

### Cron Plugin
Runs on a schedule, does work, exits. Use for periodic syncs or reports.

```yaml
# plugin.yaml
schedule:
  mode: cron
  cron: "0 */6 * * *"  # every 6 hours
```

For cron plugins, your `main.go` should do the work and `os.Exit(0)` when done (no signal loop needed).

### Event-Driven Plugin
Triggered by PCE events. Read the event from `PLUGGER_EVENT_PAYLOAD`.

```yaml
# plugin.yaml
schedule:
  mode: event
events:
  types:
    - workload.create
    - workload.update
```

```go
// In main.go
payload := os.Getenv("PLUGGER_EVENT_PAYLOAD")
var event map[string]interface{}
json.Unmarshal([]byte(payload), &event)
// Process event...
```

## Health Checks

For daemon plugins, expose a `/healthz` endpoint that returns HTTP 200. Plugger will poll it to detect unhealthy plugins and auto-restart them.

```go
mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
})
```

Configure the health check in `plugin.yaml`:

```yaml
health:
  endpoint: /healthz
  port: 8080
  interval: 30s
  timeout: 5s
  retries: 3
```
