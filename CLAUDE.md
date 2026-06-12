# Plugger — Illumio PCE Plugin Framework

## Plugin Creation Guide

When creating or modifying plugger plugins, follow these patterns.

### Plugin Structure

Every plugin needs these files:

```
my-plugin/
  plugin.yaml              # Plugger manifest — lifecycle config
  .plugger/metadata.yaml   # Runtime metadata — ports, config, volumes, info
  Dockerfile               # Must COPY both yaml files into /.plugger/
  main.py                  # Plugin logic (or Go/JS/Shell equivalent)
  README.md                # Plugin documentation
  requirements.txt         # Python dependencies (if Python)
```

### plugin.yaml — Plugger Manifest

Controls how plugger manages the plugin container.

```yaml
apiVersion: plugger/v1
name: my-plugin              # unique name, kebab-case
version: 0.1.0
image: plugger-my-plugin:latest   # local or GHCR image name

schedule:
  mode: daemon               # daemon | cron
  # cron: "0 */6 * * *"     # cron expression (only for mode: cron)

env:
  - name: POLL_INTERVAL       # env var name injected into container
    required: false
    default: "3600"
  - name: MY_SECRET
    required: true
    secret: true               # marks as sensitive — UI masks the value

health:
  endpoint: /healthz           # HTTP health check path
  port: 8080                   # container port to check
  interval: 30s
  timeout: 5s
  retries: 3                   # failures before restart

resources:
  memoryLimit: 256m            # container memory limit
  cpuLimit: "0.5"              # CPU shares
```

**Key rules:**
- `name` must match the directory name
- `env` entries are merged with PCE credentials at container start
- `secret: true` env vars are never logged or exposed in the dashboard
- `health` is optional — without it, no auto-restart on crash
- `mode: daemon` runs continuously; `mode: cron` runs once per schedule

### .plugger/metadata.yaml — Runtime Metadata

Discovered by plugger from inside the container image. Describes ports, config UI, volumes, and plugin info.

```yaml
plugger: v1

ports:
  - port: 8080
    protocol: tcp
    name: dashboard            # human-readable name
    description: My plugin dashboard
    type: ui                   # ui = proxied through plugger dashboard
    path: /                    # base path inside the container

config:
  - name: POLL_INTERVAL
    description: Seconds between poll cycles
    required: false
    type: int                  # string | int | bool | secret
    default: "3600"
  - name: MY_SECRET
    description: API token for external service
    required: true
    type: secret

volumes:
  - path: /data
    description: Persistent state directory
    required: false            # true = plugger warns if missing

info:
  title: My Plugin
  version: "0.1.0"
  description: One-line description of what this plugin does
  author: Illumio
  license: Apache-2.0
  homepage: https://github.com/alexgoller/illumio-plugger/tree/main/my-plugin
```

**Key rules:**
- `type: ui` ports get proxied through the plugger dashboard
- `config` entries appear in the dashboard settings UI with descriptions
- `volumes` are auto-created under `{dataDir}/volumes/{plugin-name}/`
- `info.title` is the display name in the dashboard

### Dockerfile Requirements

Every Dockerfile must copy both manifests into `/.plugger/`:

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# REQUIRED: plugger discovers these at install time
COPY plugin.yaml /.plugger/plugin.yaml
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

EXPOSE 8080
CMD ["python3", "main.py"]
```

Without these COPY lines, `plugger install` fails with "image does not contain a plugger manifest".

### PCE Connection

PCE credentials are injected as env vars by plugger automatically:
- `PCE_HOST` — hostname (e.g., `poc3.illum.io`)
- `PCE_PORT` — port (e.g., `443`)
- `PCE_ORG_ID` — organization ID
- `PCE_API_KEY` — API key username
- `PCE_API_SECRET` — API key secret

Standard Python PCE client setup:
```python
from illumio import PolicyComputeEngine

def get_pce():
    pce = PolicyComputeEngine(
        url=os.environ["PCE_HOST"],
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ["PCE_API_KEY"],
        password=os.environ["PCE_API_SECRET"],
    )
    verify = os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() != "true"
    pce.set_tls_settings(verify=verify)
    return pce
```

If credentials are rotated, plugger auto-restarts containers with stale credentials on next startup.

### PCE Object Linking

Every PCE object has an API HREF. When displaying PCE objects in plugin UIs, always render them as clickable links to the PCE console.

```python
import re

def pce_console_url(href):
    """Convert a PCE API HREF to a clickable console URL."""
    pce_host = os.environ.get("PCE_HOST", "localhost")
    m = re.match(r'.*/orgs/\d+/(.*)', href)
    path = m.group(1) if m else href.lstrip('/')
    path = path.replace('sec_policy/draft/', '').replace('sec_policy/active/', '')
    return f"https://{pce_host}/#/{path}"
```

**HREF-to-console mapping:**

| API HREF pattern | Console URL |
|---|---|
| `/orgs/{id}/workloads/{uuid}` | `/#/workloads/{uuid}` |
| `/orgs/{id}/sec_policy/draft/rule_sets/{id}` | `/#/rulesets/{id}` |
| `/orgs/{id}/labels/{uuid}` | `/#/labels/{uuid}` |
| `/orgs/{id}/sec_policy/draft/ip_lists/{id}` | `/#/iplists/{id}` |
| `/orgs/{id}/services/{id}` | `/#/services/{id}` |
| `/orgs/{id}/label_groups/{uuid}` | `/#/labelgroups/{uuid}` |

In HTML: `<a href="${url}" target="_blank" class="text-blue-400 hover:underline">${name}</a>`

### Poll Intervals

Be reasonable with poll intervals — the PCE is a shared platform serving many consumers. Default to 3600s (1 hour) for most plugins. Shorter intervals are fine when justified (e.g., event listeners, active incident response), but don't poll aggressively without a good reason. Multiple plugins each polling at 30s adds up fast.

### Dashboard UI Pattern

Plugins with `type: ui` ports use this standard stack:
- **Python**: `http.server.BaseHTTPRequestHandler` with inline HTML
- **CSS**: Tailwind via CDN (`https://cdn.tailwindcss.com`)
- **Dark theme**: Catppuccin Mocha colors (`bg-dark-900: #11111b`, `bg-dark-800: #1e1e2e`, `bg-dark-700: #313244`)
- **Charts**: Chart.js via CDN
- **Health endpoint**: `/healthz` returning `{"status": "healthy"}`

### Maturity Levels

Every plugin has a maturity rating in the registry:

| Level | Meaning |
|-------|---------|
| **example** | Proof of concept, demonstrates the idea |
| **preview** | Functional code, needs real-world validation |
| **prototype** | Works end-to-end, evolving rapidly |
| **production** | Verified against live PCE, reliable for customer environments |

### Registry & CI Checklist

After adding or modifying a plugin:

1. **registry.json** — add/update entry in `docs/portal/registry.json` with all fields:
   - `name`, `version`, `image`, `description`, `mode`, `has_ui`, `language`, `tags`, `author`, `homepage`, `maturity`
   - Internal plugins: image = `ghcr.io/alexgoller/plugger-{name}:latest`
   - External plugins (policy-gitops, policy-workflow): image = `ghcr.io/alexgoller/illumio-{name}:latest`

2. **CI matrix** — add to `.github/workflows/build.yml` plugin matrix (unless external)

3. **Portal** — add card to `docs/portal/index.html` with `data-plugin`, `data-categories`, `data-maturity` attributes

4. **Validation** — run `python3 .github/scripts/validate-registry.py` and `python3 .github/scripts/validate-manifests.py` locally before pushing

### Illumio Policy Concepts (for plugin developers)

- **Labels**: key-value pairs (app, env, role, loc) assigned to workloads
- **App|env tuples**: the primary grouping — e.g., `exchange|Production`
- **Rulesets**: contain rules, scoped by labels. Multiple scopes act like a for loop (no OR/AND between them)
- **Intra-scope rules**: traffic within a scope (e.g., within `exchange|Production`)
- **Extra-scope / unscoped_consumers**: traffic crossing scope boundaries
- **Enforcement modes**: idle → visibility_only → selective → full (progression path)
- **Draft vs Active policy**: changes go to draft first, then must be provisioned to active
- **IP lists**: named sets of IP ranges used in rules
- **Services**: port/protocol definitions (can reference well-known services)
- **Deny rules**: explicit deny, processed after allow rules
- **Override deny rules**: deny that overrides allow rules
