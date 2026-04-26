# Policy Workflow — Design Document

## Problem Statement

Illumio has draft/active policy versioning but no approval workflow. Anyone with API/GUI access can create rules and provision them. There is no:
- Risk classification of changes (is this a minor tweak or a broad any-to-any rule?)
- Approval gate before provisioning
- Notification to affected teams when policy touches their scope
- Audit trail of who approved what
- Integration with existing ITSM/workflow tools

This is especially painful for:
- **Cross-scope rules**: Team A needs a rule into Team B's scope — who approves?
- **Overly permissive rules**: Someone creates an any-to-any rule — who catches it?
- **Compliance**: Auditors ask "who approved this firewall change?" — no answer exists

## Solution

A bridge plugin that **detects** policy changes in PCE draft, **classifies** them by risk, and **routes** approval requests to the customer's existing workflow system (ServiceNow, Slack, Jira, or generic webhook). Provisioning is gated on approval.

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   Illumio PCE    │     │   policy-workflow     │     │  Approval System │
│                  │     │   plugin              │     │                 │
│  Draft changes   │────▶│ 1. Detect changes     │────▶│ ServiceNow CR   │
│  detected via    │     │ 2. Classify risk      │     │ Slack message   │
│  polling         │     │ 3. Route to approver  │     │ Jira ticket     │
│                  │     │ 4. Wait for approval  │     │ GitHub Issue    │
│  Provision       │◀────│ 5. Provision on OK    │◀────│ Webhook callback│
│  (draft→active)  │     │ 6. Log result         │     │                 │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
```

## Change Detection

### What constitutes a "change"

The plugin polls PCE draft policy and compares against active policy:

| Object Type | How Changes Are Detected |
|------------|------------------------|
| Rulesets | New rulesets in draft not in active |
| Rules | New/modified/deleted rules within rulesets |
| IP Lists | New/modified IP lists in draft |
| Services | New/modified service definitions |
| Label Groups | New/modified label groups |
| Enforcement Boundaries | Changes to enforcement scope |

### Detection Method

```
Every SCAN_INTERVAL:
  1. GET /sec_policy/draft/rule_sets → draft_rulesets
  2. GET /sec_policy/active/rule_sets → active_rulesets
  3. Compare: identify additions, modifications, deletions
  4. For each change: classify risk, determine approvers, create request
```

Changes are identified by comparing object content (ignoring metadata like `updated_at`, `href` differences between draft/active).

## Risk Classification

Each detected change is assigned a risk level:

### Critical (auto-escalate)
- Any rule with `actors: ams` on BOTH providers and consumers (any-to-any)
- Any rule with port range > 1000 ports
- Deletion of a deny rule or enforcement boundary
- Change to a ruleset with `enabled: false` → `true` on a large scope

### High
- Cross-scope rules (unscoped_consumers: true)
- Rules allowing known risky ports (21/FTP, 23/Telnet, 445/SMB, 3389/RDP)
- New rulesets with broad scope (env-only, no app constraint)
- IP list changes adding 0.0.0.0/0 or broad CIDRs

### Medium
- New intra-scope rules with specific services
- Modifications to existing rules (port changes, label changes)
- New IP lists with specific ranges

### Low
- Rule description/name changes
- Disabling a rule (reducing access)
- Adding a deny rule (increasing security)

### Info
- Label group changes
- Service definition changes (adding a named service)

## Scope Ownership and Approval Routing

### Who approves what

The plugin maintains a scope-to-approver mapping:

```yaml
# approval-config.yaml (mounted in /data)
approvers:
  # Per-scope approvers
  scopes:
    "app=payments AND env=prod":
      team: payments-team
      slack_channel: "#payments-approvals"
      email: payments-team@example.com
      servicenow_group: "Payments Engineering"
    
    "app=shareddb AND env=prod":
      team: database-team
      slack_channel: "#dba-approvals"
      email: dba-team@example.com
  
  # Default approver for unmatched scopes
  default:
    team: security-team
    slack_channel: "#security-approvals"
    email: security@example.com

  # Cross-scope rules always need security review
  cross_scope:
    team: security-team
    slack_channel: "#security-approvals"

  # Critical risk always escalates to
  critical:
    team: security-leadership
    slack_channel: "#security-urgent"
    email: ciso@example.com

# Risk levels that require approval (others auto-approve)
require_approval:
  - critical
  - high
  - medium
  # 'low' and 'info' are auto-approved

# Auto-provision after approval?
auto_provision: true
```

### Cross-scope approval flow

When a change touches multiple scopes:

```
1. Rule detected: consumers in scope A, providers in scope B (extra-scope)
2. Plugin identifies both scope owners from config
3. Creates approval request requiring BOTH:
   - Scope A owner (requester)
   - Scope B owner (affected party)
   - Security team (all cross-scope changes)
4. All three must approve before provisioning
```

## Approval Adapters

### ServiceNow
- Creates a Change Request in ServiceNow via Table API
- Sets assignment_group based on scope owner config
- Polls CR status until approved/rejected/closed
- On approval: provisions and updates CR with result
- Fields: short_description, description (full diff), category, risk_level, assignment_group

### Slack
- Posts approval request to configured channel with:
  - Risk badge (Critical/High/Medium)
  - Change summary (what changed, who changed it, risk reason)
  - Approve/Reject buttons (Slack interactive components)
- Listens for button clicks via Slack interactivity webhook
- Multi-approver: requires all configured approvers to click Approve
- Thread updates with provisioning result

### Jira
- Creates issue in configured project
- Sets priority based on risk level
- Assigns to scope owner's Jira user/group
- Polls issue status (or webhook on transition)
- Provisions when issue moves to "Approved" status

### GitHub Issues
- Creates issue with risk label (critical/high/medium)
- Assigns to scope owner's GitHub team
- Uses issue comments for approve/reject (e.g., `/approve` command)
- Closes issue with provisioning result

### Generic Webhook
- POST to configured URL with full change details as JSON
- Expects callback POST to `/api/approve/{change-id}` with decision
- Most flexible — works with any system

## Change Request Object

```json
{
  "id": "cr-20260426-001",
  "created": "2026-04-26T10:30:00Z",
  "status": "pending",
  "risk_level": "high",
  "risk_reasons": [
    "Cross-scope rule (unscoped consumers)",
    "Allows RDP (3389/tcp)"
  ],

  "change_type": "new_rule",
  "ruleset": "payments-prod",
  "ruleset_href": "/orgs/1/sec_policy/draft/rule_sets/123",
  "scope": "app=payments AND env=prod",

  "change_summary": "New rule: processing → shareddb:5432/tcp (extra-scope)",
  "change_detail": {
    "rule": {
      "consumers": [{"label": {"key": "role", "value": "processing"}}],
      "providers": [{"label": {"key": "role", "value": "db"}}],
      "ingress_services": [{"port": 5432, "proto": 6}],
      "unscoped_consumers": true
    }
  },

  "requester": {
    "user": "api_1e35e68192bfd2c45",
    "detected_from": "PCE draft change"
  },

  "required_approvals": [
    {"team": "payments-team", "status": "pending", "via": "slack"},
    {"team": "database-team", "status": "pending", "via": "slack"},
    {"team": "security-team", "status": "pending", "via": "slack"}
  ],

  "provisioned": false,
  "provisioned_at": null,
  "provision_result": null
}
```

## State Machine

```
DETECTED → PENDING → APPROVED → PROVISIONING → PROVISIONED
                  ↘ REJECTED                  ↘ FAILED
                  ↘ EXPIRED (timeout)
```

- **DETECTED**: Change found in draft policy
- **PENDING**: Approval request sent, waiting for response
- **APPROVED**: All required approvers approved
- **REJECTED**: Any approver rejected (with reason)
- **EXPIRED**: No response within configured timeout (default 7 days)
- **PROVISIONING**: Provision API call in progress
- **PROVISIONED**: Successfully provisioned to active
- **FAILED**: Provision failed (API error)

## Dashboard

### Views

1. **Pending Approvals** — changes waiting for review, sorted by risk level
   - Risk badge, change summary, scope, required approvers with status
   - "Provision Now" button for auto-approved items
   
2. **Recent Activity** — last 50 changes with status timeline
   - Detected → Approved → Provisioned flow visualization
   
3. **Risk Overview** — chart of changes by risk level over time
   
4. **Scope Map** — which teams own which scopes, approval stats per team

5. **Configuration** — current approver config, adapter status

### Approval Card (example)

```
┌─────────────────────────────────────────────────────┐
│ 🔴 HIGH RISK                          cr-20260426-001│
│                                                     │
│ New extra-scope rule in payments-prod               │
│ processing → shareddb:5432/tcp (PostgreSQL)         │
│                                                     │
│ Risk: Cross-scope rule, touches database scope      │
│                                                     │
│ Approvals needed:                                   │
│   ✅ payments-team (approved via Slack, 10:32 AM)   │
│   ⏳ database-team (pending, notified via Slack)    │
│   ⏳ security-team (pending, notified via Slack)    │
│                                                     │
│ Detected: 15 minutes ago                            │
│ Timeout: 6d 23h remaining                           │
└─────────────────────────────────────────────────────┘
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/changes` | All tracked changes with status |
| GET | `/api/changes/{id}` | Single change detail |
| GET | `/api/pending` | Only pending changes |
| POST | `/api/approve/{id}` | Approve a change (with approver identity) |
| POST | `/api/reject/{id}` | Reject a change (with reason) |
| POST | `/api/provision/{id}` | Manually trigger provisioning |
| POST | `/api/scan` | Trigger immediate change detection |
| GET | `/api/config` | Current approver configuration |

## Plugin Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL` | `300` | Seconds between draft change detection |
| `APPROVAL_ADAPTER` | `webhook` | `servicenow`, `slack`, `jira`, `github`, `webhook` |
| `APPROVAL_TIMEOUT` | `604800` | Seconds before pending changes expire (7 days) |
| `AUTO_PROVISION` | `false` | Provision automatically on approval |
| `AUTO_APPROVE_LOW` | `true` | Auto-approve low/info risk changes |
| `REQUIRE_ALL_APPROVERS` | `true` | All approvers must approve (vs any-one) |
| `SLACK_BOT_TOKEN` | | Slack bot token (for Slack adapter) |
| `SLACK_SIGNING_SECRET` | | Slack signing secret for verifying callbacks |
| `SNOW_INSTANCE` | | ServiceNow instance (e.g., myorg.service-now.com) |
| `SNOW_USER` | | ServiceNow API user |
| `SNOW_PASSWORD` | | ServiceNow API password |
| `JIRA_URL` | | Jira server URL |
| `JIRA_TOKEN` | | Jira API token |
| `JIRA_PROJECT` | | Jira project key for approval tickets |
| `WEBHOOK_URL` | | Generic webhook URL for notifications |
| `WEBHOOK_CALLBACK_TOKEN` | | Token for authenticating callbacks |

## Dependencies

- `illumio` — PCE SDK
- `requests` — HTTP client
- `pyyaml` — approval config parsing
- No adapter-specific SDKs — all use REST APIs

## Testing Plan

### Phase 1: Change Detection (no external systems)

| Test | Steps | Expected Result |
|------|-------|----------------|
| Detect new ruleset | Create a ruleset in PCE draft via GUI | Plugin detects it, classifies risk, shows in dashboard |
| Detect new rule | Add a rule to existing draft ruleset | Plugin detects the new rule with correct scope |
| Detect modification | Change a rule's service ports | Plugin shows old vs new values |
| Detect deletion | Delete a draft rule | Plugin detects deletion |
| Risk: any-to-any | Create a rule with ams providers and ams consumers | Classified as CRITICAL |
| Risk: cross-scope | Create an extra-scope rule | Classified as HIGH, identifies both scopes |
| Risk: risky port | Create a rule allowing 3389/tcp | Classified as HIGH with "RDP" reason |
| Risk: intra-scope normal | Create a role-to-role rule on specific port | Classified as MEDIUM or LOW |
| No false positives | Make no changes; wait for scan | No changes detected |

### Phase 2: Approval Routing (with Slack or webhook)

| Test | Steps | Expected Result |
|------|-------|----------------|
| Single-scope approval | Create intra-scope rule change | Approval sent to scope owner only |
| Cross-scope approval | Create extra-scope rule | Approval sent to BOTH scope owners + security |
| Critical escalation | Create any-to-any rule | Approval sent to critical escalation contacts |
| Approve via callback | Click Approve in Slack / POST to callback | Change status → APPROVED |
| Reject via callback | Click Reject in Slack / POST to callback | Change status → REJECTED with reason |
| Timeout expiry | Wait for timeout period | Change status → EXPIRED |

### Phase 3: Provisioning

| Test | Steps | Expected Result |
|------|-------|----------------|
| Auto-provision on approve | Approve a change with AUTO_PROVISION=true | Draft provisioned to active automatically |
| Manual provision | Approve, then click "Provision" in dashboard | Provisioned on manual click |
| Provision failure | Approve a change with invalid ruleset | Status → FAILED with error |
| Multi-approver gate | Cross-scope with 3 approvers | Only provisions when ALL 3 approve |

### Phase 4: Multi-Team Workflow (requires multiple PCE users)

| Test | Steps | Expected Result |
|------|-------|----------------|
| Team A requests, Team B approves | User A creates cross-scope rule, User B gets notified | Full flow: detect → notify B → B approves → provision |
| Team B rejects | User A creates rule, User B rejects | Rule stays in draft, rejection reason logged |
| Security team override | Security team can approve any scope | Works regardless of scope ownership |
| Partial approval | 2 of 3 approvers approve, 1 pending | Stays PENDING until all complete |

### Phase 5: Edge Cases

| Test | Steps | Expected Result |
|------|-------|----------------|
| Concurrent changes | Multiple changes in one scan cycle | Each gets its own approval request |
| Change withdrawn | User deletes draft change before approval | Change detected as withdrawn, status updated |
| PCE unavailable | PCE goes down during scan | Error logged, retry on next cycle |
| Adapter unavailable | Slack/SNOW down when sending approval | Retry with backoff, status shows "notify_failed" |
| Duplicate detection | Same change detected twice | Deduplication by change fingerprint |

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Approval fatigue (too many requests) | Auto-approve low/info; batch similar changes; configurable thresholds |
| Blocking legitimate emergency changes | "Emergency override" API endpoint that provisions with post-hoc audit |
| Approver unavailable (vacation) | Timeout mechanism + escalation to backup approver |
| PCE API user identified as "requester" | Enrich with PCE event data to identify the actual human user |
| Adapter credential rotation | Health check on adapter connectivity; alert on auth failures |

## Future Enhancements

- **Slack App with modals**: Rich approval form with comments, conditions
- **Time-boxed approvals**: "Approved for 48 hours, then auto-revoke"
- **Approval templates**: Pre-approved change patterns (e.g., "adding monitoring port is always OK")
- **Risk scoring model**: Machine learning on historical approvals to predict risk
- **Multi-PCE**: Route changes from multiple PCEs through one workflow instance
- **Compliance integration**: Auto-attach approval evidence to compliance-reporter exports
