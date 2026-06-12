# Plugger — Illumio PCE Plugin Framework

## Plugin Creation Guide

When creating or modifying plugger plugins, follow these patterns.

### PCE Object Linking

Every PCE object has an API HREF (e.g. `/orgs/1/workloads/abc123`). When displaying PCE objects in plugin UIs, always render them as clickable links to the PCE console.

**Helper function** — include in every plugin with a web UI:

```python
def pce_console_url(href):
    """Convert a PCE API HREF to a clickable console URL."""
    pce_host = os.environ.get("PCE_HOST", "localhost")
    # Strip /api/v2/orgs/{id}/ prefix, keep the object path
    import re
    m = re.match(r'.*/orgs/\d+/(.*)', href)
    path = m.group(1) if m else href.lstrip('/')
    # Map API paths to console fragment paths
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

**In HTML templates**, render as:
```html
<a href="${pce_url}" target="_blank" class="text-blue-400 hover:underline">${name}</a>
```

### Plugin Structure

Every plugin needs:
- `plugin.yaml` — manifest (name, version, image, schedule, health, resources)
- `.plugger/metadata.yaml` — runtime metadata (ports, config, volumes, info)
- `Dockerfile` — with `COPY plugin.yaml /.plugger/plugin.yaml` and `COPY .plugger/metadata.yaml /.plugger/metadata.yaml`
- `main.py` (or equivalent) — plugin logic

### PCE Connection

PCE credentials are injected as env vars by plugger:
- `PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`, `PCE_API_SECRET`

Use `PCE_TLS_SKIP_VERIFY=true` for self-signed certs.

### Poll Intervals

Default poll intervals should be >= 3600s (1 hour) to avoid overloading the PCE. Only health checks and event listeners should poll more frequently.

### Registry

After adding a plugin, update `docs/portal/registry.json` and ensure it's in `.github/workflows/build.yml` matrix.
