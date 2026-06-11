# Workload Isolator

> **Status: Untested**

Instant workload quarantine via REST API and web dashboard. Designed for integration with EDR platforms (CrowdStrike, SentinelOne), SOAR tools, and manual incident response. Isolate a compromised workload with a single API call, get Slack/Teams notifications, and auto-release after a configurable TTL.

## Install

```bash
plugger install workload-isolator
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_TOKEN` | _(required)_ | Bearer token for API authentication. If unset, the API is unauthenticated (a warning is logged at startup). |
| `ISOLATION_METHOD` | `enforcement` | How to isolate: `enforcement` changes the workload to full enforcement mode (with no rules = deny all) |
| `NOTIFICATION_WEBHOOK` | _(empty)_ | Slack or Teams webhook URL for isolation/release notifications |
| `DEFAULT_TTL` | `0` | Default auto-release time in seconds. `0` means no auto-release. |
| `MAX_ISOLATED` | `100` | Maximum concurrent isolated workloads (safety limit to prevent runaway automation) |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification |

## Features

- **Instant isolation** -- Quarantine a workload by hostname, IP address, or PCE href via a single POST request
- **Automatic release** -- Configure a TTL (time-to-live) per isolation or globally; a background thread auto-releases workloads when the timer expires
- **Bulk isolation** -- Isolate multiple workloads in one API call with a safety confirmation flag
- **Dry-run mode** -- Test what would happen without actually isolating (`"dry_run": true`)
- **Authentication** -- Bearer token authentication on all mutating endpoints; tokens can be passed as `Authorization: Bearer <token>` header or `?token=<token>` query parameter
- **Slack/Teams notifications** -- Sends isolation and release notifications to a configured webhook URL
- **Audit trail** -- Full history of all isolate/release events with timestamps, reasons, sources, and durations
- **Dashboard** -- Web UI with quick-isolate form, active isolation table with release buttons, and scrollable audit log
- **State restoration** -- On release, the workload is restored to its previous enforcement mode (not hardcoded to a specific mode)
- **Safety limits** -- Configurable maximum concurrent isolations to prevent runaway automation from quarantining the entire fleet

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard with quick-isolate form and audit log |
| GET | `/healthz` | Health check |
| GET | `/api/state` | Current state: active isolations, audit log, config |
| GET | `/api/isolated` | List currently isolated workloads (auth required) |
| GET | `/api/audit` | Isolation/release audit history (auth required) |
| POST | `/api/isolate` | Isolate a single workload (auth required) |
| POST | `/api/release` | Release an isolated workload (auth required) |
| POST | `/api/isolate/bulk` | Isolate multiple workloads (auth required) |

### Isolate a Workload

```bash
curl -X POST http://localhost:8080/api/isolate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "compromised-host.prod",
    "reason": "CrowdStrike malware detection",
    "source": "crowdstrike-soar",
    "ttl": 3600
  }'
```

Response:
```json
{
  "status": "isolated",
  "workload": "compromised-host.prod",
  "workload_href": "/orgs/1/workloads/abc123",
  "isolated_at": "2025-01-15T10:30:00+00:00",
  "auto_release_at": "2025-01-15T11:30:00+00:00",
  "method": "enforcement"
}
```

### Release a Workload

```bash
curl -X POST http://localhost:8080/api/release \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "compromised-host.prod", "reason": "Threat remediated"}'
```

### Bulk Isolate

```bash
curl -X POST http://localhost:8080/api/isolate/bulk \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["host1.prod", "host2.prod", "10.0.1.50"],
    "reason": "Lateral movement detected",
    "source": "sentinel-one",
    "ttl": 7200,
    "confirm": true
  }'
```

The `"confirm": true` field is required for bulk operations as a safety measure.

## Integration Examples

### CrowdStrike Falcon SOAR

Configure a CrowdStrike response action to call the isolate endpoint when a detection triggers:

```
POST http://plugger-host:8080/api/isolate
Authorization: Bearer YOUR_TOKEN
{"target": "{{ hostname }}", "reason": "{{ detection_name }}", "source": "crowdstrike"}
```

### Generic Webhook / SOAR

Any system that can make HTTP POST requests can trigger isolation. The `source` field tracks which system initiated the quarantine for audit purposes.
