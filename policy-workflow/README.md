# Policy Workflow

Approval workflow for Illumio PCE policy changes. Detects draft policy
changes, classifies them by risk, routes approval requests to external
workflow systems (Slack, ServiceNow, webhook), and gates provisioning
on approval.

**Status: Skeleton / Work-in-progress.** The RiskClassifier is fully
functional. Change detection, approval routing, and provisioning are
stubbed with TODO markers for implementation.

See [DESIGN.md](DESIGN.md) for the full design document, architecture
diagrams, and detailed specifications.

## Install

```
plugger install policy-workflow
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL` | `300` | Seconds between draft change detection |
| `APPROVAL_ADAPTER` | `webhook` | `webhook`, `slack`, or `servicenow` |
| `APPROVAL_TIMEOUT` | `604800` | Seconds before pending changes expire (7d) |
| `AUTO_PROVISION` | `false` | Provision automatically on approval |
| `AUTO_APPROVE_LOW` | `true` | Auto-approve low/info risk changes |
| `REQUIRE_ALL_APPROVERS` | `true` | All approvers must approve (vs any-one) |
| `SLACK_BOT_TOKEN` | | Slack bot token (for Slack adapter) |
| `SLACK_SIGNING_SECRET` | | Slack signing secret |
| `SNOW_INSTANCE` | | ServiceNow instance URL |
| `SNOW_USER` | | ServiceNow API user |
| `SNOW_PASSWORD` | | ServiceNow API password |
| `WEBHOOK_URL` | | Generic webhook URL |
| `WEBHOOK_CALLBACK_TOKEN` | | Token for authenticating callbacks |

### Approval Configuration

Mount an `approval-config.yaml` at `/data/approval-config.yaml` to define
scope-to-team mappings. See `approval-config.yaml.example` for the format.

## Dashboard

The web dashboard at port 8080 has three tabs:

- **Pending Approvals** — changes waiting for review, with approve/reject/provision buttons
- **Recent Activity** — last 50 changes with status
- **Configuration** — current approver config and adapter status

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/changes` | All tracked changes |
| GET | `/api/changes/{id}` | Single change detail |
| GET | `/api/pending` | Pending changes only |
| GET | `/api/config` | Current configuration |
| POST | `/api/approve/{id}` | Approve a change |
| POST | `/api/reject/{id}` | Reject a change |
| POST | `/api/provision/{id}` | Trigger provisioning |
| POST | `/api/scan` | Trigger immediate scan |

## What Works Now

- **RiskClassifier** — fully functional, classifies changes by:
  - Critical: any-to-any rules, port ranges >1000, enforcement boundary deletion
  - High: cross-scope rules, risky ports (RDP, SMB, FTP, etc.), broad CIDRs
  - Medium: new intra-scope rules, rule modifications, IP list changes
  - Low: rule disabling, metadata changes
  - Info: label groups, service definitions
- **ApprovalManager** — state machine (DETECTED->PENDING->APPROVED/REJECTED/EXPIRED->PROVISIONED/FAILED)
- **Dashboard** — renders and serves on port 8080
- **HTTP API** — all endpoints respond

## What Needs Implementation (TODO)

- `ChangeDetector._compare_rulesets()` — draft vs active ruleset comparison
- `ChangeDetector._compare_ip_lists()` — draft vs active IP list comparison
- `ChangeDetector._compare_services()` — draft vs active service comparison
- `WebhookAdapter.send_approval_request()` — actual HTTP POST
- `SlackAdapter.send_approval_request()` — Slack Block Kit message
- `ServiceNowAdapter.send_approval_request()` — ServiceNow CR creation
- `ApprovalManager.provision()` — actual PCE provision API call
- Cross-scope detection and multi-team approval routing
- Change fingerprinting and deduplication

## Testing Plan

From the design document:

### Phase 1: Change Detection (no external systems)

| Test | Expected Result |
|------|----------------|
| Detect new ruleset | Plugin detects it, classifies risk, shows in dashboard |
| Detect new rule | Plugin detects the new rule with correct scope |
| Detect modification | Plugin shows old vs new values |
| Detect deletion | Plugin detects deletion |
| Risk: any-to-any | Classified as CRITICAL |
| Risk: cross-scope | Classified as HIGH, identifies both scopes |
| Risk: risky port | Classified as HIGH with port name in reason |
| Risk: intra-scope normal | Classified as MEDIUM or LOW |
| No false positives | No changes detected when nothing changed |

### Phase 2: Approval Routing

| Test | Expected Result |
|------|----------------|
| Single-scope approval | Approval sent to scope owner only |
| Cross-scope approval | Approval sent to both scope owners + security |
| Critical escalation | Approval sent to critical contacts |
| Approve via callback | Status moves to APPROVED |
| Reject via callback | Status moves to REJECTED |
| Timeout expiry | Status moves to EXPIRED |

### Phase 3: Provisioning

| Test | Expected Result |
|------|----------------|
| Auto-provision on approve | Draft provisioned to active |
| Manual provision | Provisioned on button click |
| Provision failure | Status moves to FAILED |
| Multi-approver gate | Only provisions when all approve |

## Dependencies

- `illumio` — PCE SDK
- `requests` — HTTP client
- `pyyaml` — approval config parsing
