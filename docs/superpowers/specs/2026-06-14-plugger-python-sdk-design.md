# Plugger Python SDK Design

**Date:** 2026-06-14
**Status:** Approved
**Scope:** Python SDK for plugin development, single vendored file

## Problem

Every Python plugin (20 of 22) repeats ~100-230 lines of identical boilerplate: PCE connection, label caching, HTTP server with health check, thread-safe state management, signal handling, poller loop, and report publishing. This code is copy-pasted across all plugins with minor variations, making it hard to maintain and error-prone for new plugin authors.

## Solution

A single-file Python SDK (`plugger_sdk.py`) that plugin authors copy into their plugin directory. Uses a decorator-based API (Flask-style) to eliminate boilerplate while keeping plugin authors in full control of their logic and dashboard HTML.

## API Design

### Plugin Class

```python
from plugger_sdk import Plugin

app = Plugin("my-plugin")
```

**Constructor behavior:**
- Configures logging (`logging.getLogger(name)`, timestamp format)
- Reads all env vars, provides `app.env(name, default)` accessor
- Defers PCE connection to first `app.pce` access (lazy)
- Defers label cache to first `app.labels` access (lazy, refreshed each poll)
- Initializes thread-safe state via `app.state` (dict with internal lock)

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `app.pce` | `PolicyComputeEngine` | Authenticated PCE client (lazy, created once) |
| `app.state` | `dict` | Thread-safe state dict (auto-locked) |
| `app.labels` | `dict` | Label cache `{href: {key, value}}` (lazy) |
| `app.log` | `Logger` | Configured logger |

**Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `app.env(name, default="")` | `str` | Read env var |
| `app.resolve_label(href)` | `(key, value)` | Look up label href in cache |
| `app.resolve_workload_labels(wl)` | `{key: value}` | Resolve all labels on a workload dict |
| `app.pce_link(href)` | `str` | Convert API HREF to console URL |
| `app.report(title, body, severity, tags, data)` | `None` | Publish report to output bus (fire-and-forget) |
| `app.trigger_poll()` | `None` | Force an immediate poll cycle |
| `app.run(port=8080)` | `None` | Start HTTP server, poller, signal handling |

### Decorators

#### `@app.poll` — Periodic work function

```python
@app.poll(interval_env="POLL_INTERVAL", default=3600)
def scan(pce):
    workloads = pce.get("/workloads").json()
    app.state["count"] = len(workloads)
```

- One per plugin (enforced)
- Runs in a daemon thread
- `pce` argument is the authenticated PCE client
- First call on startup, then repeats on interval
- Exceptions caught and logged, never crashes the loop
- Label cache refreshed before each call

#### `@app.api` — HTTP route handler

```python
@app.api("GET", "/api/data")
def get_data(request):
    return app.state  # dict → JSON response

@app.api("POST", "/api/action")
def do_action(request):
    data = request.json
    return {"status": "ok"}
```

- Multiple allowed
- Return `dict` → JSON response (200, Content-Type: application/json)
- Return `str` → HTML response (200, Content-Type: text/html)
- Return `(dict, int)` or `(str, int)` → response with custom status code
- `request` object has: `.body` (bytes), `.json` (parsed dict), `.query` (dict from query string), `.method` (str), `.path` (str)
- CORS headers added automatically

#### `@app.dashboard` — Custom HTML page

```python
@app.dashboard
def render():
    return DASHBOARD_HTML
```

- Optional — if not set, SDK serves default page showing `app.state` as formatted JSON
- Called on each `GET /` request
- Returns HTML string

### Built-in Routes

Registered automatically, no plugin code needed:

| Route | Response |
|-------|----------|
| `GET /healthz` | `{"status": "healthy", "plugin": "name", "state_keys": [...]}` |
| `GET /` | Dashboard (custom via `@app.dashboard` or default state viewer) |

### Built-in Behaviors

| Feature | Implementation |
|---------|---------------|
| PCE connection | `PolicyComputeEngine` from env vars, TLS skip from `PCE_TLS_SKIP_VERIFY` |
| Label cache | `pce.get("/labels")` → `{href: {key, value}}`, refreshed before each poll |
| State thread safety | Internal `threading.Lock`, `app.state` reads/writes auto-locked |
| Signal handling | `SIGTERM`/`SIGINT` → graceful HTTP server shutdown |
| Report publishing | HTTP POST to `PLUGGER_URL/api/reports/publish` with bearer token |
| Poller loop | Background thread, interval from env var, try/except around each call |
| Logging | `%(asctime)s [%(levelname)s] %(message)s` with `%Y-%m-%dT%H:%M:%S` |

## File Structure

### The SDK file

```
plugin-templates/plugger_sdk.py   # ~300 lines, single file
```

Replaces `plugin-templates/plugger_report.py` (reporting is now built into `app.report()`).

### Per-plugin structure

```
my-plugin/
  main.py              # Plugin logic (50-200 lines)
  plugger_sdk.py        # Copied from templates
  plugin.yaml
  .plugger/metadata.yaml
  Dockerfile
  requirements.txt      # illumio (+ any plugin-specific deps)
```

### Dockerfile pattern

```dockerfile
COPY plugger_sdk.py /app/plugger_sdk.py
COPY main.py /app/main.py
```

## Internal Architecture

### Plugin class internals (~300 lines)

```
Plugin.__init__()
  ├── logging setup
  ├── env var reading
  └── state dict + lock init

Plugin.pce (property)
  └── lazy PolicyComputeEngine creation from env vars

Plugin.labels (property)
  └── lazy fetch_labels() → label_cache dict

Plugin.run(port)
  ├── register built-in routes (/healthz, /)
  ├── initial poll call
  ├── start poller thread
  ├── register signal handlers
  └── HTTPServer.serve_forever()

_PluggerHandler(BaseHTTPRequestHandler)
  ├── do_GET()  → route lookup → call handler → serialize response
  ├── do_POST() → route lookup → parse body → call handler → serialize
  ├── do_OPTIONS() → CORS preflight
  └── log_message() → suppressed

_Request
  ├── .method, .path, .query
  ├── .body (bytes)
  └── .json (lazy parsed dict)
```

### Thread model

```
Main thread:     HTTPServer.serve_forever()
Poller thread:   while True: poll_fn(pce); sleep(interval)
Report thread:   fire-and-forget POST (per report, via threading.Thread)
```

## Migration Examples

### stale-workloads (591 → ~200 lines)

**Before (key boilerplate sections removed):**
- get_pce(): 12 lines
- fetch_labels(): 15 lines
- resolve_labels(): 12 lines
- state_lock + state dict: 10 lines
- StaleHandler class: 65 lines
- poller_loop(): 8 lines
- main(): 28 lines
- signal handling: embedded in main
- Total boilerplate: ~150 lines

**After:**
```python
from plugger_sdk import Plugin

app = Plugin("stale-workloads")

@app.poll(interval_env="POLL_INTERVAL", default=3600)
def check_stale(pce):
    # ... 150 lines of actual stale detection logic (unchanged) ...
    app.state["stale"] = stale_list
    app.state["summary"] = summary
    if stale_list:
        app.report(f"{len(stale_list)} stale workloads", ...)

@app.api("GET", "/api/state")
def get_state(req): return app.state

@app.api("POST", "/api/cleanup")
def cleanup(req): ...

@app.dashboard
def render(): return DASHBOARD_HTML

DASHBOARD_HTML = """..."""

app.run()
```

### traffic-reporter and network-discovery

Same pattern — extract the poll function, register API routes, keep dashboard HTML. Plugin-specific logic stays identical.

## Plugins to Migrate (Proof of Concept)

1. **stale-workloads** — simple daemon, single poll function, one POST action
2. **traffic-reporter** — traffic flow queries, Chart.js dashboard, label resolution
3. **network-discovery** — complex (DNS, subnets, workload creation, persistent state)

These three cover the range: simple → medium → complex.

## What the SDK Does NOT Do

- **Dashboard HTML** — plugin authors own their HTML completely
- **Plugin-specific PCE queries** — the SDK provides `app.pce`, not wrappers around every API
- **State persistence** — plugins manage their own file I/O for persistent state
- **Container networking** — that's plugger's job, not the SDK's
- **Go SDK** — designed separately, future work

## Dependencies

The SDK file depends only on:
- Python stdlib (`http.server`, `threading`, `signal`, `logging`, `json`, `os`, `re`, `time`, `urllib`)
- `illumio` (already in every plugin's requirements.txt)

No new dependencies introduced.

## Verification

1. Build `plugger_sdk.py` with all features
2. Migrate stale-workloads → verify dashboard, API, polling, reporting all work
3. Migrate traffic-reporter → verify traffic queries and Chart.js dashboard work
4. Migrate network-discovery → verify DNS, workload creation, state persistence work
5. Run all three side by side in plugger
6. Write a new trivial plugin from scratch using the SDK to verify the "new plugin" experience
