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

### Customer Branding

Plugger serves brand assets from `~/.plugger/brand/` at `/brand/*`. Plugins opt in by referencing these URLs in their HTML.

**Setup**: Drop files into `~/.plugger/brand/`:
- `logo.png` / `logo.svg` — customer logo
- `style.css` — CSS overrides (colors, fonts, header bar)
- `config.json` — `{"company": "Acme Corp", "primaryColor": "#1a5f7a"}`

**Plugin opt-in** (one line in dashboard HTML):
```html
<link rel="stylesheet" href="/brand/style.css" onerror="this.remove()">
```

The `onerror="this.remove()"` makes it a no-op when no brand directory exists (404 → stylesheet removed). Plugins that don't reference `/brand/*` are unaffected.

### Dashboard UI Pattern

Plugins with `type: ui` ports use this standard stack:
- **Python**: `http.server.BaseHTTPRequestHandler` with inline HTML
- **CSS**: Tailwind via CDN (`https://cdn.tailwindcss.com`)
- **Dark theme**: Catppuccin Mocha colors (`bg-dark-900: #11111b`, `bg-dark-800: #1e1e2e`, `bg-dark-700: #313244`)
- **Charts**: Chart.js via CDN
- **Health endpoint**: `/healthz` returning `{"status": "healthy"}`

### Portal Website Style Guide

The portal at `docs/portal/index.html` is a single-page static site. All updates must follow these patterns.

**Theme**: Catppuccin Mocha dark, with light mode overrides via `html:not(.dark)` selectors.

**Colors** (Tailwind custom):
- `bg-dark-900: #11111b` — page background
- `bg-dark-800: #1e1e2e` — cards, panels
- `bg-dark-700: #313244` — inputs, secondary surfaces
- Text: `text-white` for headings, `text-gray-300` for body, `text-gray-400/500` for secondary

**Plugin cards** — each card in `#plugin-grid` needs:
- `class="card bg-dark-800 rounded-xl border border-gray-700 p-5 fade-in cursor-pointer"`
- `data-plugin="plugin-name"` — matches registry name
- `data-categories="cat1,cat2"` — for category filter (monitoring, policy, ai, integration, operations)
- `data-maturity="level"` — for maturity filter (example, preview, prototype, production)
- `onclick="showDocs('plugin-name')"` — opens docs modal
- Title badge colors: sky for mode, violet for AI, rose for new, emerald for new, amber for untested

**Maturity badge colors** (injected by JS):
- production: `bg-green-500/15 text-green-300 border-green-500/30`
- prototype: `bg-amber-500/15 text-amber-300 border-amber-500/30`
- beta: `bg-orange-500/15 text-orange-300 border-orange-500/30`
- preview: `bg-blue-500/15 text-blue-300 border-blue-500/30`
- example: `bg-gray-500/15 text-gray-400 border-gray-500/30`

**Changelog section** — between Plugins and Docs sections:
- Each release is a `bg-dark-800 rounded-xl border border-gray-700 p-6` card
- Version + "latest" badge on the left, date on the right
- Categories with colored headings: blue for New Plugins, purple for Features, red for Bug Fixes, yellow for Documentation
- Content as `<ul>` with `<strong>` for the item name and `&mdash;` before the description
- Keep entries concise — one line per item, no paragraphs
- Update with every tagged release

**Filters** — two rows of pills:
- `.cat-pill` for categories, `.mat-pill` for maturity
- Active state: `bg-rgba(137,180,250,0.2) text-#89b4fa border-rgba(137,180,250,0.4)`
- Both filters combine (AND logic)

**Nav bar**: horizontal links to `#plugins`, `#changelog`, `#docs`, plus GitHub link and theme toggle.

### Maturity Levels

Every plugin has a maturity rating in the registry:

| Level | Meaning |
|-------|---------|
| **example** | Proof of concept, demonstrates the idea |
| **preview** | Functional code, needs real-world validation |
| **beta** | Feature-complete but untested in production, actively being validated |
| **prototype** | Works end-to-end, evolving rapidly |
| **production** | Verified against live PCE, reliable for customer environments |

### Registry & CI Checklist

After adding or modifying a plugin:

1. **registry.json** — add/update entry in `docs/portal/registry.json` with all fields:
   - `name`, `version`, `image`, `description`, `mode`, `has_ui`, `language`, `tags`, `author`, `homepage`, `maturity`
   - Internal plugins: image = `ghcr.io/alexgoller/plugger-{name}:{version}` — the image tag **must equal** the `version` field (validated by `validate-registry.py`). When you bump `version`, bump the image tag too.
   - External plugins (policy-gitops, policy-workflow): image = `ghcr.io/alexgoller/illumio-{name}:latest` (built from their own repos)

2. **CI** — no action needed. `.github/workflows/plugins.yaml` auto-discovers every dir with a `plugin.yaml` + `Dockerfile` and builds it when its `:{version}` tag isn't yet published, tagging the image `:{version}` and `:latest`. (No static build matrix to maintain.)

3. **Portal** — update `docs/portal/index.html`:
   - Add plugin card in `#plugin-grid` with `data-plugin`, `data-categories`, `data-maturity`
   - Add PLUGIN_DOCS entry with full markdown documentation
   - Add plugin name to docs accordion `order` array
   - Update plugin count in All filter, meta description, hero text, stats

4. **README.md** — update the root README:
   - Add to the plugin table in the correct category
   - Update plugin count in badge and section heading
   - For complex plugins: write a detailed `README.md` in the plugin directory

5. **Changelog** — add entry to portal changelog section with version and date

6. **Version bump** — increment version in `plugin.yaml`, `metadata.yaml`, and `registry.json`

7. **Validation** — run locally before pushing:
   ```bash
   python3 .github/scripts/validate-registry.py
   python3 .github/scripts/validate-manifests.py
   node -e "..." # JS syntax check (see docs backtick memory)
   ```

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

### Reporting / Output Framework

Plugins publish reports via a simple HTTP POST. Plugger routes them to configured output channels (Slack, email, webhook) based on filters. Plugins don't know where reports go — routing is configured centrally.

**Plugin-side** (any language, one POST):
```python
import os, requests

requests.post(
    os.environ["PLUGGER_URL"] + "/api/reports/publish",
    headers={"Authorization": f"Bearer {os.environ['PLUGGER_WEBHOOK_TOKEN']}"},
    json={
        "plugin": os.environ["PLUGGER_PLUGIN_NAME"],
        "title": "42 new IPs discovered",
        "severity": "info",          # info | warning | critical
        "body": "## Summary\n- 42 resolved, 12 created",
        "tags": ["discovery", "dns"],
        "data": {"resolved": 42, "created": 12}
    }
)
```

Every container gets `PLUGGER_PLUGIN_NAME`, `PLUGGER_URL`, and `PLUGGER_WEBHOOK_TOKEN` injected automatically.

**Config** (in `~/.plugger/config.yaml`):
```yaml
plugger:
  outputs:
    - name: slack-alerts
      type: slack                    # slack | email | webhook
      webhook: https://hooks.slack.com/services/...
      dryRun: false                  # true = log only, don't send
      filter:
        severity: [warning, critical]  # empty = all severities
        plugins: []                    # empty = all plugins
        tags: []                       # empty = all tags

    - name: weekly-digest
      type: email
      smtpHost: smtp.corp.com
      smtpPort: 587
      smtpUser: plugger@corp.com
      smtpPasswordEnv: SMTP_PASSWORD  # env var name, not the value
      to: [security@corp.com]
      schedule: "0 8 * * 1"           # cron: Monday 08:00
      aggregate: true                 # bundle all reports since last send

    - name: incidents
      type: webhook
      url: https://api.example.com/incidents
      method: POST
      headers:
        Authorization: "Bearer ${API_TOKEN}"  # env var expansion
      filter:
        severity: [critical]
```

**Output types**:
- `slack` — Slack Block Kit webhooks, severity emoji, tag context
- `email` — SMTP with HTML rendering (Catppuccin-styled), supports digest mode
- `webhook` — generic HTTP with configurable method, headers, env var expansion

**Framework features**:
- Filter matching: severity AND plugins AND tags (all AND, empty = match all)
- Retry: 3 attempts with exponential backoff (2s, 4s, 8s)
- Aggregate: buffer reports, flush on cron schedule via SendBatch
- DryRun: logs what would send without sending
- Test messages: `POST /api/reports/test/{output-name}` sends a test to verify connectivity
- Dashboard: `/reports` page shows output health (green/red dot), delivery stats, and recent report table

**Adding new output types**: implement the `Output` interface in `internal/reports/`:
```go
type Output interface {
    Name() string
    Type() string
    Send(ctx context.Context, report *Report) error
    SendBatch(ctx context.Context, reports []*Report) error
}
```
Then add to the `newOutput()` factory in `router.go` and the `OutputConfig` struct in `config.go`.
