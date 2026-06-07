# API Authentication & Authorization

**Status:** Proposed
**Priority:** Critical — security audit flagged no auth on dashboard (H1)
**Complexity:** Medium
**Dependencies:** Changes to plugger Go core (reverse proxy + config)

## Problem

Every plugin API endpoint is unauthenticated. Anyone with network access to the plugger dashboard or any plugin port can:
- Start/stop/restart plugins
- Change plugin configuration (including secrets)
- Trigger scans, exports, provisioning
- View security reports, traffic data, policy details
- Isolate workloads (workload-isolator)
- Approve policy changes (policy-workflow)
- Install plugins from registry

There are no users, no roles, no API keys. The workload-isolator has its own per-plugin Bearer token, but that's a plugin-level workaround, not a system-wide solution.

## Design Goals

1. **No user management** — no database, no passwords, no sessions to manage
2. **Granular per-plugin control** — different keys can access different plugins with different permissions
3. **Easy for API consumers** — standard Bearer token, works with curl, SOAR, EDR, scripts
4. **Dashboard just works** — browser access should be simple, not require login for every click
5. **Backward compatible** — existing plugins don't need code changes
6. **Supports external callers** — EDR webhooks, SOAR playbooks, CI/CD pipelines need API access

## Architecture

Two layers, composable:

### Layer 1: Proxy-Level API Keys (core)

The plugger reverse proxy enforces authentication on all requests before they reach any plugin.

```
                                    ┌──────────────────────┐
                                    │   Plugger Proxy      │
External API call ──────────────────│                      │
  Authorization: Bearer pk_abc123   │   1. Validate key    │
                                    │   2. Check plugin    │──── Plugin container
                                    │      permission      │     (no auth needed)
                                    │   3. Check access    │
                                    │      level           │
Dashboard browser ──────────────────│                      │
  Cookie: plugger_session=xxx       │   Session cookie     │
                                    │   from dashboard     │
                                    │   login              │
                                    └──────────────────────┘
```

### Layer 2: JWT Tokens (on top, for external consumers)

For external systems (EDR, SOAR, CI/CD) that need time-limited, scope-restricted tokens.

```
1. External system authenticates with API key:
   POST /api/auth/token
   Authorization: Bearer pk_abc123
   Body: {"plugins": ["workload-isolator"], "ttl": 3600}

2. Receives a JWT:
   {"token": "eyJ...", "expires_at": "2026-06-07T13:00:00Z"}

3. Uses JWT for subsequent calls:
   POST /plugins/workload-isolator/ui/api/isolate
   Authorization: Bearer eyJ...

4. Plugin proxy validates JWT signature + plugin scope
```

---

## Layer 1: API Key Configuration

### Config file (`~/.plugger/config.yaml`)

```yaml
auth:
  enabled: true

  # Master key — full access to everything (for initial setup, emergencies)
  master_key: "pk_master_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

  # Dashboard access
  dashboard:
    # How to authenticate browser access
    method: "key"          # "key" (enter key once, get session cookie)
                           # "none" (no dashboard auth — local-only deployments)
    session_ttl: 86400     # Session cookie lifetime in seconds (24h)

  # API keys with per-plugin permissions
  keys:
    - key: "pk_soc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      name: "SOC Team"
      description: "Security Operations — incident response"
      plugins:
        workload-isolator: "write"      # Can isolate/release
        ai-security-report: "read"      # Can view reports
        policy-resolver: "read"         # Can view resolved rules
        traffic-reporter: "read"        # Can view traffic data
      dashboard: true                    # Can access dashboard UI
      created: "2026-06-07"

    - key: "pk_net_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      name: "Network Team"
      description: "Firewall and network management"
      plugins:
        policy-resolver: "write"        # Can trigger resolution + export
        traffic-reporter: "read"
      dashboard: true

    - key: "pk_edr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      name: "CrowdStrike Integration"
      description: "EDR automated isolation"
      plugins:
        workload-isolator: "write"      # Can isolate/release
      dashboard: false                   # No dashboard access (API only)

    - key: "pk_cicd_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      name: "CI/CD Pipeline"
      description: "GitOps provisioning pipeline"
      plugins:
        policy-gitops: "write"
        policy-workflow: "write"
      dashboard: false

    - key: "pk_viewer_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      name: "Read-Only Viewer"
      description: "Dashboard viewer — all plugins, no changes"
      plugins: "*"                       # All plugins
      access: "read"                     # Read-only for all
      dashboard: true
```

### Key Format

```
pk_{name}_{32 random hex chars}
```

Generated via: `plugger auth create-key --name "SOC Team"`

### Access Levels

| Level | GET endpoints | POST endpoints | Dashboard view | Dashboard actions |
|-------|:---:|:---:|:---:|:---:|
| `read` | ✅ | ❌ | ✅ | ❌ |
| `write` | ✅ | ✅ | ✅ | ✅ |
| `none` | ❌ | ❌ | ❌ | ❌ |

### Per-Plugin Permissions

```yaml
plugins:
  workload-isolator: "write"     # Full access to this plugin
  ai-security-report: "read"     # Read-only
  pce-health-monitor: "none"     # No access (explicitly denied)
  # Unlisted plugins: no access (deny by default)
```

Or use wildcard for broad access:
```yaml
plugins: "*"           # All plugins
access: "read"         # Default access level for wildcard
```

---

## Layer 2: JWT Tokens

### Token Request

```
POST /api/auth/token
Authorization: Bearer pk_soc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Content-Type: application/json

{
  "plugins": ["workload-isolator"],    # Scope: which plugins
  "access": "write",                    # Access level (cannot exceed key's level)
  "ttl": 3600                          # Token lifetime in seconds (max: key's limit)
}
```

### Token Response

```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwa19zb2NfLi4uIiwicGx1Z2lucyI6WyJ3b3JrbG9hZC1pc29sYXRvciJdLCJhY2Nlc3MiOiJ3cml0ZSIsImV4cCI6MTcxOTMyMjgwMH0.xxxxx",
  "expires_at": "2026-06-07T13:00:00Z",
  "plugins": ["workload-isolator"],
  "access": "write"
}
```

### JWT Claims

```json
{
  "sub": "pk_soc_xxx...",           // API key that created this token
  "name": "SOC Team",               // Key name
  "plugins": ["workload-isolator"], // Allowed plugins
  "access": "write",                // Access level
  "exp": 1719322800,                // Expiration (Unix timestamp)
  "iat": 1719319200                 // Issued at
}
```

### JWT Validation

- Signed with HMAC-SHA256 using the master key as secret
- Validated at the proxy level (same as API keys)
- Plugin scope checked: JWT's `plugins` claim must include the target plugin
- Access level checked: JWT's `access` must allow the HTTP method
- Expiration checked: reject if `exp` < now

### Why JWT on Top of API Keys?

| Scenario | API Key | JWT |
|----------|---------|-----|
| Dashboard browser session | ✅ (enter once, get cookie) | Overkill |
| SOAR playbook (long-running) | ✅ (stored in vault) | ✅ (time-limited) |
| EDR webhook (automated) | ✅ | ✅ (narrower scope) |
| CI/CD pipeline | ✅ | ✅ (short-lived per run) |
| Shared with contractor | ❌ (can't expire) | ✅ (expires after project) |
| Cross-team delegation | ❌ (full key access) | ✅ (scoped to specific plugin) |

API keys are simpler for most cases. JWTs add time-limiting and scope-narrowing for cases where you can't trust the consumer to keep the key forever.

---

## Proxy Enforcement

### Request Flow

```python
def handle_request(request):
    # 1. Check if auth is enabled
    if not config.auth.enabled:
        return forward_to_plugin(request)

    # 2. Extract credentials
    token = extract_token(request)  # Bearer header, cookie, or query param

    if not token:
        if is_dashboard_request(request):
            return redirect_to_login()
        return 401, {"error": "Authentication required"}

    # 3. Validate: API key or JWT?
    if token.startswith("pk_"):
        key_config = validate_api_key(token)
    elif token.startswith("eyJ"):
        key_config = validate_jwt(token)
    else:
        return 401, {"error": "Invalid token format"}

    if not key_config:
        return 401, {"error": "Invalid or expired token"}

    # 4. Check plugin permission
    plugin_name = extract_plugin_name(request.path)
    access = get_access_level(key_config, plugin_name)

    if access == "none":
        return 403, {"error": f"No access to plugin '{plugin_name}'"}

    if request.method in ("POST", "PUT", "DELETE") and access == "read":
        return 403, {"error": f"Read-only access to plugin '{plugin_name}'"}

    # 5. Forward to plugin
    return forward_to_plugin(request)
```

### Paths and What They Protect

| Path Pattern | What | Default (no auth) | With Auth |
|-------------|------|-------------------|-----------|
| `/` | Dashboard home | Open | Requires key/session |
| `/api/plugins` | Plugin list | Open | Requires read access |
| `/api/plugins/{name}/start` | Start plugin | Open | Requires write access |
| `/api/plugins/{name}/stop` | Stop plugin | Open | Requires write access |
| `/api/plugins/{name}/config` | Plugin config | Open | Requires write access |
| `/api/plugins/{name}/uninstall` | Uninstall | Open | Requires write access |
| `/plugins/{name}/ui/` | Plugin dashboard | Open | Requires read for plugin |
| `/plugins/{name}/ui/api/*` | Plugin API (GET) | Open | Requires read for plugin |
| `/plugins/{name}/ui/api/*` | Plugin API (POST) | Open | Requires write for plugin |
| `/api/registry/install` | Install from registry | Open | Requires master key |
| `/api/events/trigger` | Webhook trigger | Token (own) | Webhook token OR API key |
| `/api/auth/token` | Create JWT | N/A | Requires API key |
| `/healthz` | Health check | Always open | Always open |

### Dashboard Login Flow

For browser access (not API):

1. User navigates to `https://plugger:8800/`
2. Proxy checks for `plugger_session` cookie
3. No cookie → show login page (simple form: "Enter API Key")
4. User enters API key → proxy validates → sets `plugger_session` cookie (HttpOnly, Secure, SameSite)
5. Cookie contains: encrypted API key reference + expiry
6. Subsequent requests use cookie → proxy decrypts → validates → forwards

No username/password. Just paste an API key once.

---

## CLI Commands

```bash
# Create a new API key
plugger auth create-key --name "SOC Team" --plugins workload-isolator:write,ai-security-report:read
# → pk_soc_a1b2c3d4e5f6...

# List keys (masked)
plugger auth list-keys
# NAME            KEY PREFIX    PLUGINS                          DASHBOARD
# SOC Team        pk_soc_a1b2   workload-isolator:write, ...     yes
# CrowdStrike     pk_edr_d4e5   workload-isolator:write          no

# Revoke a key
plugger auth revoke-key pk_soc_a1b2

# Generate a JWT (for scripting)
plugger auth create-token --key pk_soc_xxx --plugins workload-isolator --ttl 3600
# → eyJhbGciOi...

# Test a key
plugger auth test-key pk_soc_xxx
# → Valid: SOC Team (workload-isolator:write, ai-security-report:read)
```

---

## Migration Path

### Phase 1: API Keys (build this first)
- Add `auth` section to config.yaml
- Implement proxy-level key validation
- Add dashboard login page
- Add `plugger auth` CLI commands
- Default: `auth.enabled: false` (backward compatible)

### Phase 2: JWT Tokens (add later)
- Add `/api/auth/token` endpoint
- JWT signing with HMAC-SHA256
- JWT validation in proxy
- Token revocation (optional — JWTs are stateless, just let them expire)

### Phase 3: Enhancements (future)
- Rate limiting per key
- Audit log of all API key usage
- Key rotation (create new, grace period, revoke old)
- IP allowlisting per key
- OIDC/OAuth2 integration (for SSO environments)

---

## What Plugins Need to Change

**Nothing.** That's the beauty of proxy-level auth.

Plugins continue to serve their APIs on port 8080 without any auth. The proxy handles everything. Plugins never see the API key or JWT — they just receive authenticated requests.

The only plugin-level change: remove per-plugin auth tokens (like workload-isolator's `AUTH_TOKEN`). They become unnecessary when the proxy handles it.

---

## Configuration Examples

### Minimal (just protect the dashboard)

```yaml
auth:
  enabled: true
  master_key: "pk_master_generate_this_with_plugger_auth"
  dashboard:
    method: "key"
  keys: []   # Master key is the only key
```

### SOC + Network Teams

```yaml
auth:
  enabled: true
  master_key: "pk_master_xxx"
  keys:
    - key: "pk_soc_xxx"
      name: "SOC"
      plugins:
        workload-isolator: "write"
        ai-security-report: "read"
        ai-assisted-rules: "read"
      dashboard: true

    - key: "pk_net_xxx"
      name: "Network"
      plugins:
        policy-resolver: "write"
        traffic-reporter: "read"
      dashboard: true
```

### EDR Integration (API-only, no dashboard)

```yaml
auth:
  enabled: true
  master_key: "pk_master_xxx"
  keys:
    - key: "pk_crowdstrike_xxx"
      name: "CrowdStrike Falcon"
      plugins:
        workload-isolator: "write"
      dashboard: false
```

### Open Dashboard, Protected APIs

```yaml
auth:
  enabled: true
  master_key: "pk_master_xxx"
  dashboard:
    method: "none"           # Dashboard open, but...
  keys:
    - key: "pk_api_xxx"
      name: "API Access"
      plugins: "*"
      access: "write"
      dashboard: false       # ...API writes still need a key
```

---

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Key stored in config file | File permissions 0600 (same as PCE credentials) |
| Key in transit | HTTPS required (TLS already implemented) |
| Key in Docker env vars | Only master_key in plugger config; plugin keys don't exist in containers |
| Key rotation | Create new key, update consumers, revoke old key |
| Brute force | Rate limit on auth failures (10 per minute per IP) |
| Session hijacking | HttpOnly + Secure + SameSite cookies; short TTL |
| JWT key compromise | Short TTL (1h default); rotate master_key to invalidate all JWTs |
| Backward compatibility | `auth.enabled: false` is the default; existing deployments unaffected |

## Files to Change

### Phase 1
- `internal/config/config.go` — add `AuthConfig` struct
- `internal/dashboard/handler.go` — add auth middleware to the mux
- `internal/dashboard/auth.go` — new: key validation, session management, login page
- `internal/cli/auth.go` — new: `plugger auth` subcommands
- `internal/cli/root.go` — register auth commands
- Dashboard templates — login page HTML

### Phase 2
- `internal/dashboard/jwt.go` — new: JWT creation and validation
- `internal/dashboard/handler.go` — add `/api/auth/token` endpoint
