# Workload Isolator

**Status:** Proposed
**Priority:** High — fastest build, highest operational impact
**Complexity:** Low
**Dependencies:** PCE enforcement boundaries API

## Problem

When CrowdStrike/SentinelOne/Defender detects a compromise, or a SOC analyst identifies a breach, the immediate need is to **network-isolate** the compromised workload. EDR containment is endpoint-only; Illumio can enforce network-level isolation. Today this requires manual action in the PCE GUI or expensive SOAR platforms.

## Solution

A lightweight plugin with a webhook endpoint that instantly quarantines a workload by moving it to a deny-all enforcement boundary. Rollback restores the original state.

## API

### Isolate
```
POST /api/isolate
{
  "target": "web01.prod.example.com",   // hostname, IP, or workload href
  "reason": "CrowdStrike alert CS-2026-1234",
  "severity": "critical",
  "source": "crowdstrike",              // who triggered the isolation
  "ttl": 3600                           // optional: auto-release after N seconds
}

Response:
{
  "status": "isolated",
  "workload": "web01.prod.example.com",
  "workload_href": "/orgs/1/workloads/abc123",
  "previous_mode": "visibility_only",
  "isolated_at": "2026-05-29T15:00:00Z",
  "auto_release_at": "2026-05-29T16:00:00Z"
}
```

### Release
```
POST /api/release
{
  "target": "web01.prod.example.com",
  "reason": "Investigation complete, false positive"
}
```

### Status
```
GET /api/isolated

[
  {
    "workload": "web01.prod.example.com",
    "isolated_at": "2026-05-29T15:00:00Z",
    "reason": "CrowdStrike alert CS-2026-1234",
    "source": "crowdstrike",
    "auto_release_at": "2026-05-29T16:00:00Z"
  }
]
```

### Bulk Isolate
```
POST /api/isolate/bulk
{
  "targets": ["web01.prod.example.com", "10.0.1.5", "web02.prod.example.com"],
  "reason": "Ransomware incident IR-2026-001"
}
```

## Isolation Mechanism

### Option A: Enforcement Mode Change (simplest)
- Change workload enforcement mode to `full` with no matching rules → deny all
- Fast, works immediately
- Rollback: restore previous enforcement mode

### Option B: Enforcement Boundary (recommended)
- Move workload into a dedicated "quarantine" enforcement boundary
- More explicit, visible in the PCE GUI
- Other teams can see what's quarantined and why
- Rollback: remove from quarantine boundary

### Option C: Deny Rules (most granular)
- Create deny rules targeting the specific workload
- Most surgical — can deny specific ports while keeping monitoring
- Slower to apply, more complex

**Recommendation:** Option B for standard isolation, Option A as fast fallback.

## Integration Points

### EDR Webhooks
- **CrowdStrike Falcon**: Webhook on detection → POST /api/isolate
- **SentinelOne**: Webhook on threat → POST /api/isolate
- **Microsoft Defender**: Alert webhook → POST /api/isolate
- **Any SIEM/SOAR**: Generic webhook support

### Slack/Teams Notification
- On isolate: "🔴 Workload web01.prod.example.com isolated — CrowdStrike alert CS-2026-1234"
- On release: "🟢 Workload web01.prod.example.com released — investigation complete"

### Audit Trail
- Every isolate/release action logged with timestamp, user/source, reason
- Queryable via API: `GET /api/audit`

## Dashboard

- **Active Isolations** — list of currently isolated workloads with reason, time, source
- **History** — past isolations with duration, who released, why
- **Quick Actions** — isolate by hostname/IP, bulk isolate, release buttons
- **Stats** — total isolations, avg duration, by source (EDR, manual, SOAR)

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ISOLATION_METHOD` | `boundary` | `boundary`, `enforcement`, or `deny_rules` |
| `QUARANTINE_BOUNDARY` | _(auto-create)_ | Enforcement boundary href for quarantine |
| `AUTH_TOKEN` | _(required)_ | Bearer token for API authentication |
| `NOTIFICATION_WEBHOOK` | _(empty)_ | Slack/Teams webhook URL for notifications |
| `DEFAULT_TTL` | `0` | Default auto-release seconds (0 = no auto-release) |
| `MAX_ISOLATED` | `100` | Safety limit on concurrent isolations |

## Safety Features

- **Authentication required** — Bearer token on all endpoints
- **Confirmation for bulk** — bulk isolate requires explicit `"confirm": true`
- **Max limit** — configurable cap on simultaneous isolations
- **Auto-release** — optional TTL prevents forgotten isolations
- **Dry-run mode** — `"dry_run": true` shows what would happen without acting
- **Audit everything** — full log of who isolated what, when, why

## Why This Matters

- **#1 automated response use case** — every security team wants this
- **Bridges EDR and network** — EDR detects, Illumio enforces network isolation
- **Faster than manual** — seconds vs minutes of GUI navigation
- **Works with any webhook source** — not locked to specific EDR vendor
- **Complements SOAR** — lightweight alternative for teams without SOAR
- **Half-day build** — simple webhook + PCE API calls
