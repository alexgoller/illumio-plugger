# Plugin Development Guide

Plugins are Docker containers that interact with the Illumio PCE. Plugger handles the container lifecycle, credential injection, scheduling, health checks, and web UI proxying.

## Quick Start

```bash
# Scaffold a new plugin
plugger create my-plugin -t python

# Edit the plugin logic
cd my-plugin
vim main.py

# Build and install
docker build -t my-plugin:latest .
plugger install plugin.yaml
plugger start my-plugin
```

## Plugin Structure

Every plugin has two configuration files:

### 1. `plugin.yaml` — Install Manifest

Lives in your repo. Used by `plugger install`. Defines scheduling, env vars, and resource limits.

```yaml
apiVersion: plugger/v1
name: my-plugin
version: 1.0.0
image: my-plugin:latest

schedule:
  mode: daemon                # daemon | cron | event

env:
  - name: MY_SETTING
    required: false
    default: "value"
    secret: false             # mask in status output

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

### 2. `/.plugger/metadata.yaml` — Container Metadata

Baked into the Docker image. Plugger discovers it at install time to auto-configure ports, volumes, and config validation.

```yaml
plugger: v1

ports:
  - port: 8080
    protocol: tcp
    name: dashboard
    description: Plugin web UI
    type: ui                  # ui | api | service | metrics
    path: /

config:
  - name: MY_SETTING
    description: What this setting does
    required: false
    type: string              # string | int | bool | secret
    default: "value"
    example: "custom"
    validation: "^[a-z]+$"   # optional regex

volumes:
  - path: /data
    description: Persistent storage
    required: true

info:
  title: My Plugin
  description: What the plugin does
  author: Your Name
  license: Apache-2.0
  homepage: https://github.com/your-org/my-plugin

healthcheck:
  endpoint: /healthz
  port: 8080
  interval: 30s
```

## Plugin Types

### Daemon Plugin (24/7)

Runs continuously. Auto-restarted by plugger on crash with exponential backoff.

**Use for:** monitoring, web UIs, continuous polling, long-running services

```yaml
schedule:
  mode: daemon
```

**Your code:** run a main loop or HTTP server, handle SIGTERM for graceful shutdown.

### Cron Plugin (Periodic)

Runs on a schedule, does work, exits. Plugger creates a fresh container each time.

**Use for:** periodic reports, data syncs, cleanup tasks

```yaml
schedule:
  mode: cron
  cron: "0 */6 * * *"    # standard 5-field cron expression
```

**Your code:** do the work and exit. Exit code 0 = success, non-zero = error logged.

### Event Plugin (Webhook-Triggered)

Spawned when a matching event arrives via webhook. Container is ephemeral — runs once per event.

**Use for:** reacting to PCE events (workload creation, policy changes), traffic alerts

```yaml
schedule:
  mode: event
events:
  types:
    - workload.create
    - workload.update
```

**Your code:** read `PLUGGER_EVENT_PAYLOAD` env var (JSON), process the event, exit.

## Environment Variables

Every plugin container receives these from the global config:

| Variable | Description |
|----------|-------------|
| `PCE_HOST` | PCE hostname |
| `PCE_PORT` | PCE port |
| `PCE_ORG_ID` | Organization ID |
| `PCE_API_KEY` | PCE API key |
| `PCE_API_SECRET` | PCE API secret |

Plus any variables from `plugin.yaml` env section and `metadata.yaml` config section. User overrides (set via `--env` or dashboard config UI) take highest priority.

For event plugins: `PLUGGER_EVENT_PAYLOAD` contains the triggering event as JSON.

## Templates

### Go Template

Best for compiled plugins with web UIs, high performance, and health endpoints.

```bash
plugger create my-plugin -t go
```

Includes: HTTP server with `/healthz`, signal handling, PCE env loading, periodic work loop.

### Shell Template

Best for simple scripts that call the PCE API with curl.

```bash
plugger create my-plugin -t shell
```

Includes: `pce_api` helper function for authenticated PCE calls, daemon/cron/event modes.

### Python Template

Best for rapid development with the Illumio SDK.

```bash
plugger create my-plugin -t python
```

Includes: `PolicyComputeEngine` client pre-configured from env vars, Illumio SDK examples.

**Illumio SDK quick reference:**
```python
from illumio import PolicyComputeEngine

pce = PolicyComputeEngine(url=os.environ["PCE_HOST"], port=os.environ["PCE_PORT"])
pce.set_credentials(username=os.environ["PCE_API_KEY"], password=os.environ["PCE_API_SECRET"])
pce.set_tls_settings(verify=False)

workloads = pce.workloads.get()
labels = pce.labels.get()
rulesets = pce.get("/sec_policy/active/rule_sets").json()
```

### JavaScript Template

Best for plugins where you want zero external dependencies — uses only Node.js built-in modules.

```bash
plugger create my-plugin -t javascript
```

Also accepts `-t js` as shorthand.

Includes: Built-in PCE API client using `node:https`, HTTP server with `/healthz`, Tailwind CSS dashboard, daemon/cron/event modes. No npm packages — everything uses Node.js built-ins (`http`, `https`, `Buffer`, `URL`).

**PCE API quick reference:**
```javascript
// GET workloads
const { status, data } = await pce.get("/workloads", { max_results: 100 });

// POST (create label)
await pce.post("/labels", { key: "role", value: "web" });

// PUT (update workload)
await pce.put("/workloads/abc", { labels: [...] });
```

## Dockerfile

A typical plugin Dockerfile:

```dockerfile
FROM python:3.12-slim
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN useradd -m -u 1000 plugin
COPY main.py /app/main.py
COPY .plugger/metadata.yaml /.plugger/metadata.yaml
USER plugin
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["python3", "main.py"]
```

Key points:
- Copy `/.plugger/metadata.yaml` so plugger can discover it
- Run as non-root user
- `EXPOSE` the ports declared in metadata
- No `CMD` — use `ENTRYPOINT`

## Health Checks

For daemon plugins, expose an HTTP endpoint that returns 200 when healthy:

```python
# Python
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"healthy"}')
```

```go
// Go
http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
})
```

Plugger polls this endpoint and auto-restarts the plugin after consecutive failures.

## Web UI via Reverse Proxy

If your plugin serves a web UI, declare the port in metadata:

```yaml
ports:
  - port: 8080
    type: ui
    name: dashboard
    path: /
```

The UI is then accessible at `http://plugger:8800/plugins/{name}/ui/` through the dashboard's reverse proxy. Plugger handles URL rewriting so absolute links work correctly.

## Claude Code Integration

If you use Claude Code, run `/project:build-plugin` in the plugger repo to have Claude build a complete plugin from a natural language description.
