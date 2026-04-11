# CLI Reference

## Commands

### `plugger init`

Initialize the plugger configuration directory.

```bash
plugger init
```

Creates `~/.plugger/` with a default `config.yaml`. Safe to run multiple times — won't overwrite existing config.

---

### `plugger run`

Start all enabled plugins with scheduling, health checks, and the web dashboard.

```bash
plugger run [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `localhost:8800` | Dashboard listen address |
| `--no-dashboard` | `false` | Run without the web dashboard |

**What it does:**
1. Reconciles stored state vs actual Docker containers
2. Starts daemon plugins with auto-restart (exponential backoff)
3. Starts cron plugins with scheduling
4. Registers event plugins for webhook triggering
5. Starts health checkers for plugins with health endpoints
6. Embeds the web dashboard
7. Handles SIGTERM/SIGINT for graceful shutdown

**Examples:**
```bash
plugger run                         # Default: dashboard on localhost:8800
plugger run --addr 0.0.0.0:8800     # Listen on all interfaces
plugger run --no-dashboard          # Headless mode
```

---

### `plugger create`

Scaffold a new plugin project from a template.

```bash
plugger create <name> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --template` | `go` | Template type: `go`, `shell`, or `python` |

**Templates:**
- **go** — compiled Go binary with HTTP server, health endpoint, signal handling
- **shell** — lightweight shell script with curl + jq for PCE API calls
- **python** — Python 3 with the [illumio](https://pypi.org/project/illumio/) SDK pre-installed

**Example:**
```bash
plugger create workload-tagger -t python
cd workload-tagger
# Edit main.py
docker build -t workload-tagger:latest .
plugger install plugin.yaml
```

---

### `plugger install`

Install a plugin from a manifest file, URL, or container image.

```bash
plugger install <source> [flags]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `-e, --env KEY=VALUE` | Environment variable overrides (repeatable) |

**Sources:**
```bash
plugger install ./plugin.yaml                           # Local file
plugger install https://example.com/plugin.yaml         # Remote URL
plugger install ghcr.io/org/my-plugin:v1.0              # Container image
```

**What it does:**
1. Loads/fetches the manifest
2. Pulls the Docker image
3. Discovers in-container metadata (`/.plugger/metadata.yaml`)
4. Validates required config variables
5. Saves plugin state

---

### `plugger uninstall`

Remove a plugin and its container.

```bash
plugger uninstall <name>
```

Stops and removes the container, then deletes the plugin from the store.

---

### `plugger start`

Start a single plugin container.

```bash
plugger start <name>
```

Creates a new container, injects environment variables, exposes ports, mounts volumes, and starts it.

---

### `plugger stop`

Stop a running plugin container.

```bash
plugger stop <name>
```

Gracefully stops the container (10s timeout), then removes it.

---

### `plugger restart`

Restart a plugin container.

```bash
plugger restart <name>
```

Stops (if running), then starts with fresh container.

---

### `plugger list`

List all installed plugins and their state.

```bash
plugger list
```

Output:
```
NAME                VERSION  MODE    STATE    ENABLED
pce-health-monitor  0.1.0    daemon  running  true
traffic-reporter    0.1.0    daemon  running  true
policy-diff         0.1.0    daemon  running  true
pce-events          0.1.0    daemon  running  true
```

Alias: `plugger ls`

---

### `plugger status`

Show detailed status of a plugin.

```bash
plugger status <name>
```

Displays: plugin info, container state, ports, volumes, environment variables, metadata, and errors.

---

### `plugger logs`

View logs from a plugin container.

```bash
plugger logs <name> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --follow` | `false` | Follow log output |
| `-n, --tail` | `100` | Number of lines to show |
| `--since` | | Show logs since timestamp or duration (e.g. `1h`) |

---

### `plugger dashboard`

Start only the web dashboard (without the orchestrator).

```bash
plugger dashboard [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `localhost:8800` | Listen address |

Use this when you want the dashboard UI without auto-restart and scheduling. For production, use `plugger run` instead.

---

### `plugger version`

Print the plugger version.

```bash
plugger version
```

## Global Flags

| Flag | Description |
|------|-------------|
| `--config <path>` | Config file path (default: `~/.plugger/config.yaml`) |
| `-h, --help` | Help for any command |
