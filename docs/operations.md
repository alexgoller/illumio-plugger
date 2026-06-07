# Operations Guide

Running plugger in production: deployment, monitoring, troubleshooting, and maintenance.

## Production Deployment

### Running as a Service

`plugger run` is designed to run as a foreground daemon, suitable for systemd, launchd, or any process manager.

```bash
# systemd example
plugger run --addr 0.0.0.0:8800
```

**systemd unit file** (`/etc/systemd/system/plugger.service`):

```ini
[Unit]
Description=Plugger - Illumio Plugin Framework
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=plugger
Environment=DOCKER_HOST=unix:///var/run/docker.sock
ExecStart=/usr/local/bin/plugger run --addr 0.0.0.0:8800
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### What `plugger run` Does

1. **Reconciles state** — compares plugin store vs Docker containers, fixes mismatches
2. **Starts daemons** — auto-restarts on crash with exponential backoff (1s → 5m cap)
3. **Schedules cron** — runs cron plugins on their defined schedule
4. **Registers events** — enables webhook endpoint for event-driven plugins
5. **Health checks** — polls `/healthz` on each daemon, restarts unhealthy plugins
6. **Dashboard** — serves web UI at the configured address
7. **Graceful shutdown** — SIGTERM/SIGINT stops everything cleanly

### Auto-Restart Behavior

When a daemon plugin crashes:

| Attempt | Backoff | Total Wait |
|---------|---------|------------|
| 1 | 1s | 1s |
| 2 | 2s | 3s |
| 3 | 4s | 7s |
| 4 | 8s | 15s |
| 5 | 16s | 31s |
| 6+ | gives up | state → errored |

After 5 consecutive failures, the plugin is marked `errored` and plugger stops retrying. Manually restart it with `plugger restart <name>` to reset the counter.

If the container stays running for 30+ seconds after a restart, the failure counter resets.

## Health Checks

Health checks are automatic for any plugin with `health:` in its manifest:

```yaml
health:
  endpoint: /healthz    # HTTP GET path
  port: 8080            # Container port
  interval: 30s         # Check frequency
  timeout: 5s           # Request timeout
  retries: 3            # Failures before restart
```

After `retries` consecutive failures, the health checker triggers a restart.

Check health check status via the dashboard or container logs.

## Monitoring

### Dashboard

Access at `http://localhost:8800`:

- Plugin tiles with live status
- Start/stop/restart controls
- Container logs (SSE streaming)
- Plugin detail with ports, volumes, config
- Reverse proxy to each plugin's web UI

### JSON API

```bash
# List all plugins
curl http://localhost:8800/api/plugins

# Plugin detail
curl http://localhost:8800/api/plugins/<name>

# Event scheduler stats
curl http://localhost:8800/api/events/stats
```

### CLI

```bash
plugger list                  # All plugins and states
plugger status <name>         # Detailed status
plugger logs <name> -f        # Follow container logs
```

### Container-Level

```bash
docker ps --filter label=io.plugger.managed=true    # All plugger containers
docker logs plugger-<name>                           # Container logs
docker stats plugger-<name>                          # Resource usage
```

## Troubleshooting

### Plugin won't start

**"container name already in use"** — a stale container exists:
```bash
plugger restart <name>    # handles cleanup automatically
```

**"image not found"** — image not pulled or not built:
```bash
docker build -t <image>:latest .    # Rebuild
plugger install plugin.yaml         # Reinstall
```

**"port not exposed"** — the container's port isn't in the metadata:
Check `/.plugger/metadata.yaml` in the Docker image declares the port.

### Plugin keeps crashing

Check the logs:
```bash
plugger logs <name> -n 200
```

If in `errored` state (5+ consecutive crashes):
```bash
plugger restart <name>    # Resets the backoff counter
```

### Dashboard shows "Plugin unreachable"

The reverse proxy can't reach the container. Check:
1. Container is running: `docker ps | grep plugger-<name>`
2. Port is exposed: `docker port plugger-<name>`
3. Container has the `io.plugger.managed` label

### Docker socket issues

If you see "no such file or directory" for the Docker socket:
```bash
export DOCKER_HOST=unix:///path/to/docker.sock
```

Or configure `docker.socket` in `~/.plugger/config.yaml`.

### Volume mount permission errors

Docker Desktop on macOS may not have access to certain paths. Use a path under your home directory or `/tmp`:

```yaml
plugger:
  dataDir: /tmp/plugger    # or ~/.plugger
```

## Authentication

By default, authentication is disabled and all dashboard and API endpoints are open. When deploying plugger on a network where others can reach port 8800, enable API key authentication to control who can view data and who can make changes.

### Enabling Authentication

Add an `auth` section to `~/.plugger/config.yaml`:

```yaml
plugger:
  auth:
    enabled: true
    masterKey: "pk_master_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    dashboard:
      method: key        # "key" = require login; "none" = open dashboard
      sessionTTL: 86400  # session cookie lifetime in seconds (24h)
    keys: []             # API keys (see below)
```

Set `auth.enabled: true` to activate authentication. When disabled (the default), all endpoints behave as before with no authentication required.

### Master Key

The `masterKey` grants full write access to every plugin and the dashboard. Use it for initial setup and emergency access. You can generate one with the CLI:

```bash
plugger auth create-key --name "master"
```

Copy the generated `pk_...` value into the `masterKey` field. The master key can also be set via the environment variable `PLUGGER_PLUGGER_AUTH_MASTERKEY`.

### Creating API Keys

Use the CLI to generate keys with specific plugin permissions:

```bash
# Key with write access to one plugin and read access to another
plugger auth create-key \
  --name "SOC Team" \
  --plugins workload-isolator:write,ai-security-report:read \
  --dashboard

# Read-only key for all plugins
plugger auth create-key --name "Viewer" --plugins "*:read" --dashboard

# API-only key (no dashboard access)
plugger auth create-key \
  --name "CrowdStrike EDR" \
  --plugins workload-isolator:write \
  --no-dashboard
```

The command outputs the key value and a YAML snippet to paste into your `config.yaml` under `plugger.auth.keys`.

### Per-Plugin Permissions

Each key specifies access per plugin using `read` or `write` levels:

| Level | GET / HEAD | POST / PUT / DELETE | Dashboard view | Dashboard actions |
|-------|:---:|:---:|:---:|:---:|
| `read` | Allowed | Denied | Allowed | Denied |
| `write` | Allowed | Allowed | Allowed | Allowed |

Plugins not listed in a key's `plugins` map are denied by default. Use `"*"` with a default `access` level for broad access:

```yaml
keys:
  - key: "pk_soc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    name: "SOC Team"
    plugins:
      workload-isolator: "write"
      ai-security-report: "read"
    dashboard: true

  - key: "pk_viewer_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    name: "Read-Only Viewer"
    plugins: "*"
    access: "read"
    dashboard: true
```

### Dashboard Login Flow

When `dashboard.method` is set to `key` (the default):

1. Navigate to the plugger dashboard in a browser.
2. If no valid session cookie exists, you are redirected to a login page.
3. Paste an API key into the login form.
4. Plugger validates the key and sets an `HttpOnly` session cookie.
5. Subsequent requests use the cookie until it expires (controlled by `sessionTTL`).

No username or password is needed -- just an API key with `dashboard: true`.

Set `dashboard.method` to `none` to keep the dashboard open while still requiring API keys for `POST`/`PUT`/`DELETE` requests.

### Using API Keys with curl

Pass the key as a Bearer token in the `Authorization` header:

```bash
# Read plugin data
curl -H "Authorization: Bearer pk_soc_xxx" \
  https://plugger:8800/api/plugins

# Trigger an action (requires write access)
curl -X POST -H "Authorization: Bearer pk_soc_xxx" \
  https://plugger:8800/api/plugins/workload-isolator/start
```

You can also pass the key as a query parameter (`?token=pk_...`), though the header method is preferred.

### Disabling Authentication

Authentication is disabled by default. To explicitly disable it after it was previously enabled:

```yaml
plugger:
  auth:
    enabled: false
```

When disabled, all endpoints are open with no authentication checks. The `/healthz` endpoint is always open regardless of the auth setting.

### Configuration Example: SOC + Network Teams

```yaml
plugger:
  auth:
    enabled: true
    masterKey: "pk_master_xxx"
    dashboard:
      method: key
      sessionTTL: 86400
    keys:
      - key: "pk_soc_xxx"
        name: "SOC"
        description: "Security Operations — incident response"
        plugins:
          workload-isolator: "write"
          ai-security-report: "read"
          ai-assisted-rules: "read"
        dashboard: true

      - key: "pk_net_xxx"
        name: "Network"
        description: "Firewall and network management"
        plugins:
          policy-resolver: "write"
          traffic-reporter: "read"
        dashboard: true

      - key: "pk_edr_xxx"
        name: "CrowdStrike EDR"
        description: "Automated isolation from EDR"
        plugins:
          workload-isolator: "write"
        dashboard: false
```

## Backup & Recovery

### Config Backup

```bash
cp ~/.plugger/config.yaml ~/.plugger/config.yaml.bak
```

### Plugin State

Plugin state is stored in `~/.plugger/plugins.json`. This file is auto-managed. To export:

```bash
cat ~/.plugger/plugins.json | python3 -m json.tool
```

### Volume Data

Plugin persistent data is stored under `~/.plugger/volumes/<plugin>/`. Back up as needed.

## Updating Plugins

To update a plugin to a newer image version:

```bash
# Pull or build the new image
docker build -t my-plugin:latest .

# Reinstall (uninstall + install)
plugger uninstall my-plugin
plugger install plugin.yaml
plugger start my-plugin
```

Or if using `plugger run`, just restart the specific plugin from the dashboard.
