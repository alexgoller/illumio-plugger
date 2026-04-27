# Policy Workflow

An approval workflow plugin for Illumio PCE policy changes. It continuously monitors
the PCE for draft policy modifications, classifies every change by risk, routes
approval requests to external workflow systems, and blocks provisioning until
authorized reviewers sign off.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Change Detection](#change-detection)
4. [Risk Classification](#risk-classification)
5. [Approval Routing](#approval-routing)
6. [State Machine](#state-machine)
7. [Approval Adapters](#approval-adapters)
8. [Dashboard](#dashboard)
9. [API Reference](#api-reference)
10. [approval-config.yaml Reference](#approval-configyaml-reference)
11. [Testing Plan](#testing-plan)
12. [Getting Started](#getting-started)

---

## Overview

### The Problem

Illumio PCE has a draft/active policy model but no built-in approval workflow.
Anyone with API or GUI access can create rules and provision them to production.
There is no mechanism for:

- **Risk classification** -- is this a minor tweak or a catastrophic any-to-any rule?
- **Approval gates** -- who authorized this firewall change before it went live?
- **Scope-aware routing** -- Team A needs a rule into Team B's scope, but who approves?
- **Audit trail** -- an auditor asks "who approved this firewall change?" and there is no answer.
- **ITSM integration** -- policy changes happen outside ServiceNow, Jira, and Slack entirely.

### Who Needs This

- **Security teams** who need to review and approve all policy changes before they affect production workloads.
- **Network/platform teams** that own specific application scopes and need to know when someone creates a rule touching their scope.
- **Compliance officers** who require evidence of change authorization for SOX, PCI-DSS, HIPAA, or SOC 2 audits.
- **Multi-team organizations** where cross-scope rules require coordination between application owners, database teams, and security.

### What It Does

The plugin acts as a bridge between the PCE's draft policy model and your existing approval systems:

1. **Detects** every draft policy change by polling and comparing draft vs active state.
2. **Classifies** each change by risk level (CRITICAL / HIGH / MEDIUM / LOW / INFO).
3. **Routes** approval requests to the correct team based on scope ownership and risk.
4. **Waits** for all required approvers to authorize or reject the change.
5. **Provisions** the approved change from draft to active policy (automatically or manually).
6. **Logs** the full audit trail: who changed what, who approved it, when it was provisioned.

---

## Architecture

```
+-------------------+     +--------------------------+     +--------------------+
|   Illumio PCE     |     |   policy-workflow        |     |  Approval System   |
|                   |     |   plugin                 |     |                    |
|  Draft changes    |---->| 1. Detect changes        |---->| ServiceNow CR      |
|  detected via     |     | 2. Classify risk         |     | Slack message       |
|  polling          |     | 3. Route to approver     |     | Jira ticket         |
|                   |     | 4. Wait for approval     |     | Generic webhook     |
|  Provision        |<----| 5. Provision on OK       |<----| Callback / polling  |
|  (draft->active)  |     | 6. Log result            |     |                    |
+-------------------+     +--------------------------+     +--------------------+
                                      |
                                      v
                            +--------------------+
                            |   Dashboard        |
                            |   (port 8080)      |
                            |                    |
                            | - Pending Approvals|
                            | - Recent Activity  |
                            | - Configuration    |
                            +--------------------+
```

### Data Flow

```
Every SCAN_INTERVAL seconds:

  1. GET /sec_policy/draft/rule_sets    --> draft rulesets
  2. GET /sec_policy/active/rule_sets   --> active rulesets
  3. GET /sec_policy/draft/ip_lists     --> draft IP lists
  4. GET /sec_policy/active/ip_lists    --> active IP lists
  5. GET /sec_policy/draft/services     --> draft services
  6. GET /sec_policy/active/services    --> active services
  7. Compare each pair: identify additions, modifications, deletions
  8. For each change:
     a. Classify risk level
     b. Determine required approvers from scope ownership config
     c. Create change request and send to approval adapter
  9. Expire any stale pending requests that exceeded the timeout
```

### Runtime Components

| Component | Description |
|-----------|-------------|
| `ChangeDetector` | Polls PCE, compares draft vs active, emits change dicts |
| `RiskClassifier` | Examines change properties, assigns risk level + reasons |
| `ApprovalManager` | Tracks change requests through the full state machine |
| `BaseAdapter` (Webhook / Slack / ServiceNow) | Sends approval requests to external systems |
| `WorkflowHandler` | HTTP server: dashboard, API endpoints, callbacks |
| `scan_loop` | Background thread running detection + expiry on interval |

---

## Change Detection

### What Gets Compared

The plugin polls the PCE API on a configurable interval (`SCAN_INTERVAL`, default 300 seconds) and compares draft state against active state for three object types:

| Object Type | Draft API | Active API | How Differences Are Found |
|-------------|-----------|------------|--------------------------|
| **Rulesets** | `/sec_policy/draft/rule_sets` | `/sec_policy/active/rule_sets` | Indexed by name. New = in draft not in active. Deleted = in active not in draft. Modified = same name, different `enabled`, `scopes`, or `description`. |
| **Rules** (within rulesets) | Embedded in ruleset response (`rules` array) | Embedded in ruleset response (`rules` array) | Indexed by `href`. Compared field-by-field: `providers`, `consumers`, `ingress_services`, `enabled`, `unscoped_consumers`, `sec_connect`. |
| **IP Lists** | `/sec_policy/draft/ip_lists` | `/sec_policy/active/ip_lists` | Indexed by name. Compared fields: `ip_ranges`, `fqdns`, `description`. |
| **Services** | `/sec_policy/draft/services` | `/sec_policy/active/services` | Indexed by name. Compared fields: `service_ports`, `windows_services`, `description`. |

### Rule-Level Change Detection Within Rulesets

When a ruleset exists in both draft and active, the plugin drills into the `rules` array:

1. **New rules**: `href` exists in draft but not in active.
2. **Modified rules**: Same `href` in both, but one or more of these fields differ:
   - `providers` -- who is providing the service
   - `consumers` -- who is consuming the service
   - `ingress_services` -- ports and protocols
   - `enabled` -- whether the rule is active
   - `unscoped_consumers` -- whether consumers can be outside the ruleset scope
   - `sec_connect` -- SecureConnect (encrypted traffic) flag
3. **Deleted rules**: `href` exists in active but not in draft.

For new rulesets (the entire ruleset is new), the plugin emits both a `new_ruleset` change AND individual `new_rule` changes for every rule inside it. This ensures each rule is independently risk-classified.

### Scope Extraction

Each ruleset has a `scopes` field: an array of arrays of label references. The plugin resolves these to human-readable strings like `app=payments AND env=prod` by:

1. Checking for inline `key`/`value` on the label reference.
2. Falling back to a label cache (loaded at startup via `GET /labels`) to resolve `href` references.
3. Multiple scope alternatives are joined with ` | `.
4. Rulesets with no scopes are labeled `unscoped`.

### Deduplication via Fingerprinting

Every change is fingerprinted using a SHA-256 hash of `change_type|href|summary` (truncated to 16 hex characters). Duplicates are suppressed:

- **Within a single scan cycle**: prevents the same change from being reported twice.
- **Across scan cycles**: the previous cycle's fingerprints are retained, so a change detected in cycle N is not re-reported in cycle N+1.

The fingerprint set is replaced entirely each cycle, so if a change is approved and provisioned, it will not be detected again (because draft and active will match).

### Change Types

The plugin tracks 14 distinct change types:

| Change Type | Description |
|-------------|-------------|
| `new_ruleset` | Entire ruleset exists in draft but not in active |
| `modified_ruleset` | Ruleset properties changed (enabled, scopes, description) |
| `deleted_ruleset` | Ruleset exists in active but was removed from draft |
| `new_rule` | Rule added to a ruleset (or new ruleset's embedded rule) |
| `modified_rule` | Rule properties changed (providers, consumers, ports, etc.) |
| `deleted_rule` | Rule removed from a ruleset |
| `new_ip_list` | IP list exists in draft but not in active |
| `modified_ip_list` | IP list ranges, FQDNs, or description changed |
| `new_service` | Service definition exists in draft but not in active |
| `modified_service` | Service ports, windows services, or description changed |
| `new_label_group` | Label group added |
| `modified_label_group` | Label group membership changed |
| `modified_enforcement_boundary` | Enforcement boundary scope modified |
| `deleted_enforcement_boundary` | Enforcement boundary removed |

---

## Risk Classification

Every detected change is assigned a risk level with one or more reasons explaining the classification. The classifier evaluates rules top-down; the first match at a given severity level wins.

### Complete Risk Matrix

#### CRITICAL (auto-escalate to security leadership)

| # | Trigger | What the Classifier Checks | Example |
|---|---------|---------------------------|---------|
| 1 | **Any-to-any rule** | Both `providers` and `consumers` contain `actors: "ams"` (all managed systems). | A rule allowing every workload to talk to every other workload on any port. |
| 2 | **Excessively broad port range** | Any `ingress_services` entry where `to_port - port + 1 > 1000`. | A rule opening ports 1-65535/tcp. |
| 3 | **Enforcement boundary deletion** | Change type is `deleted_enforcement_boundary`. | Removing the boundary that enforces segmentation between environments. |
| 4 | **Enabling a broad disabled ruleset** | A `modified_ruleset` where `enabled` changes from `false` to `true` AND the scope has no `app` label constraint (env-only or unscoped). | A production-wide ruleset that was disabled for safety gets turned on. |

#### HIGH (requires team + security review)

| # | Trigger | What the Classifier Checks | Example |
|---|---------|---------------------------|---------|
| 1 | **Cross-scope rule** | Rule has `unscoped_consumers: true`. | A payments rule that allows consumers from outside the payments scope. |
| 2 | **Risky ports** | Rule allows any of: FTP (21), Telnet (23), RPC (135), NetBIOS (139), SMB (445), MSSQL (1433/1434), RDP (3389), VNC (5900), WinRM (5985/5986). Port ranges that include these ports also trigger. | A rule opening 3389/tcp (RDP) to a database tier. |
| 3 | **New ruleset with broad scope** | Change type is `new_ruleset` and scope has no `app` label (env-only or no scope). | A new ruleset scoped only to `env=prod` with no application constraint. |
| 4 | **Broad CIDRs in IP lists** | New or modified IP list contains `0.0.0.0/0`, `::/0`, or any CIDR with prefix length 0-8. | Adding `10.0.0.0/4` to an IP list (covers 268 million addresses). |

#### MEDIUM (requires scope owner approval)

| # | Trigger | What the Classifier Checks | Example |
|---|---------|---------------------------|---------|
| 1 | **New intra-scope rule** | Change type is `new_rule` and NOT cross-scope. Includes the services summary in the reason. | Adding a rule: web tier -> app tier on 8080/tcp within the same scope. |
| 2 | **Modified existing rule** | Change type is `modified_rule`. | Changing a rule's port from 443 to 8443. |
| 3 | **New IP list** | Change type is `new_ip_list` (without broad CIDRs, which would be HIGH). | Creating a "Partner Networks" IP list with specific /24 ranges. |
| 4 | **Modified IP list** | Change type is `modified_ip_list` (without broad CIDRs). | Adding a new range to an existing IP list. |
| 5 | **New ruleset** (non-broad) | Change type is `new_ruleset` with a properly scoped scope (has `app` label). | Creating a new ruleset for `app=inventory AND env=prod`. |
| 6 | **Deleted ruleset** | Change type is `deleted_ruleset`. | Removing an entire ruleset and all its rules. |

#### LOW (auto-approved by default)

| # | Trigger | What the Classifier Checks | Example |
|---|---------|---------------------------|---------|
| 1 | **Rule disabled** | Modified rule where `enabled` changes from `true` to `false`. | Disabling a rule to reduce access surface. |
| 2 | **Rule deleted** | Change type is `deleted_rule`. | Removing an unnecessary rule. |
| 3 | **Ruleset metadata change** | Modified ruleset where `enabled` is NOT changing from `false` to `true`. | Updating a ruleset description. |

#### INFO (auto-approved, logged only)

| # | Trigger | What the Classifier Checks | Example |
|---|---------|---------------------------|---------|
| 1 | **Label group change** | Change type is `new_label_group` or `modified_label_group`. | Adding a new label group for "PCI Systems". |
| 2 | **Service definition change** | Change type is `new_service` or `modified_service`. | Creating a "Redis" service definition for 6379/tcp. |

### Risky Ports Reference

The following ports are flagged as risky when found in rule ingress services:

| Port | Protocol | Name | Why It's Risky |
|------|----------|------|---------------|
| 21 | TCP | FTP | Unencrypted file transfer, credentials sent in cleartext |
| 23 | TCP | Telnet | Unencrypted remote access, credentials sent in cleartext |
| 135 | TCP | RPC | Windows RPC, frequently exploited for lateral movement |
| 139 | TCP | NetBIOS | Legacy Windows networking, common attack vector |
| 445 | TCP | SMB | File sharing, WannaCry/NotPetya propagation vector |
| 1433 | TCP | MSSQL | Database access, high-value target |
| 1434 | TCP | MSSQL Browser | SQL Server discovery, used in reconnaissance |
| 3389 | TCP | RDP | Remote desktop, brute force and BlueKeep exploits |
| 5900 | TCP | VNC | Remote desktop, often poorly secured |
| 5985 | TCP | WinRM | Windows Remote Management, PowerShell remoting |
| 5986 | TCP | WinRM-HTTPS | WinRM over HTTPS, still a lateral movement vector |

### Broad CIDR Threshold

Any CIDR with a prefix length of /0 through /8 is considered "broad". This includes:

- `0.0.0.0/0` -- all IPv4 addresses
- `::/0` -- all IPv6 addresses
- Anything from `/1` through `/8` (e.g., `10.0.0.0/8` covers 16.7 million addresses)

---

## Approval Routing

### How Scopes Map to Teams

The approval routing is driven by `approval-config.yaml`, which maps Illumio label expressions to team ownership. When a change is detected, the plugin:

1. Extracts the scope from the affected ruleset (e.g., `app=payments AND env=prod`).
2. Matches the scope against patterns in the `approvers.scopes` section of the config.
3. Falls back to `approvers.default` if no scope pattern matches.

### Scope Matching Algorithm

The scope pattern match uses label expression comparison:

- Both scope and pattern are parsed as `key=value AND key=value` expressions.
- A pattern matches if every label constraint in the pattern is satisfied by the scope.
- If the scope contains alternatives separated by ` | `, the pattern must match at least one.
- Matching is case-insensitive.

Examples:

| Scope | Pattern | Match? |
|-------|---------|--------|
| `app=payments AND env=prod` | `app=payments AND env=prod` | Yes (exact) |
| `app=payments AND env=prod` | `env=prod` | Yes (subset) |
| `app=payments AND env=prod` | `app=billing` | No |
| `app=payments AND env=prod \| app=billing AND env=dev` | `app=billing` | Yes (matches second alternative) |

### Single-Scope Approval

When a change affects only one scope:

```
1. Change detected in scope "app=payments AND env=prod"
2. Config lookup: scope matches payments-team
3. Approval request sent to payments-team only
4. payments-team approves -> change provisioned
```

### Cross-Scope Approval

When a rule has `unscoped_consumers: true` (extra-scope rule), the plugin requires multiple approvals:

```
1. Rule detected: consumers in scope A, providers in scope B (extra-scope)
2. Plugin identifies the scope owner from config (Scope A owner)
3. Plugin adds the cross_scope team (security-team) from config
4. Creates approval request requiring BOTH:
   - Scope A owner (the ruleset's scope owner)
   - Security team (all cross-scope changes require security review)
5. All must approve before provisioning (when REQUIRE_ALL_APPROVERS=true)
```

### Critical Escalation Path

When a change is classified as CRITICAL risk:

```
1. Any-to-any rule detected -> classified CRITICAL
2. Plugin bypasses normal scope routing
3. Approval request sent ONLY to the "critical" team (security-leadership)
4. security-leadership must approve before provisioning
```

### REQUIRE_ALL_APPROVERS Behavior

| Setting | Behavior |
|---------|----------|
| `REQUIRE_ALL_APPROVERS=true` (default) | Every team in `required_approvals` must approve. The change stays PENDING until all teams have approved. |
| `REQUIRE_ALL_APPROVERS=false` | Any single approval from any listed team moves the change to APPROVED. Use this for faster workflows where you trust any one team's judgment. |

In both modes, a single rejection from any team immediately moves the change to REJECTED.

---

## State Machine

### State Diagram

```
                           +---> REJECTED
                           |
DETECTED ---> PENDING -----+---> EXPIRED (timeout)
                           |
                           +---> APPROVED ---> PROVISIONING ---> PROVISIONED
                                                            |
                                                            +---> FAILED
```

### State Descriptions

| State | Description | Transitions To |
|-------|-------------|---------------|
| **DETECTED** | Change found in draft policy. If the risk level is in `require_approval`, the adapter is notified and status moves to PENDING. If the risk level is auto-approved (low/info with `AUTO_APPROVE_LOW=true`), status moves directly to APPROVED. | PENDING, APPROVED |
| **PENDING** | Approval request sent to external system, waiting for response. | APPROVED, REJECTED, EXPIRED |
| **APPROVED** | All required approvers approved the change. Ready for provisioning. If `AUTO_PROVISION=true`, provisioning starts immediately. | PROVISIONING |
| **REJECTED** | Any approver rejected the change. The rejection reason and rejecting team are recorded. Terminal state. | (none) |
| **EXPIRED** | No response received within `APPROVAL_TIMEOUT` seconds (default 7 days). Terminal state. | (none) |
| **PROVISIONING** | The `POST /sec_policy` provision API call is in progress. | PROVISIONED, FAILED |
| **PROVISIONED** | Successfully provisioned -- draft changes are now active policy. Records timestamp and result. Terminal state. | (none) |
| **FAILED** | Provisioning API call failed. Records the HTTP error or exception. Terminal state. | (none) |

### Timeout Mechanics

- Each change request records an `expires_at` timestamp at creation time.
- The background scan loop calls `expire_stale()` on every cycle.
- Any PENDING or DETECTED request past its `expires_at` is moved to EXPIRED.
- Default timeout: 604800 seconds (7 days). Configurable via `APPROVAL_TIMEOUT`.

---

## Approval Adapters

The plugin ships with three adapters. Set `APPROVAL_ADAPTER` to choose which one to use.

### Webhook Adapter

The simplest adapter. POSTs the change request as JSON to a URL and expects approval/rejection via HTTP callbacks.

#### Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `APPROVAL_ADAPTER` | Yes | Set to `webhook` |
| `WEBHOOK_URL` | Yes | URL to POST approval requests to |
| `WEBHOOK_CALLBACK_TOKEN` | No | Bearer token sent in the `Authorization` header of outgoing POSTs, and expected on incoming callbacks |

#### Outgoing Request Format

When a change is detected, the plugin POSTs to `WEBHOOK_URL`:

```json
{
  "id": "cr-20260419-a1b2c3",
  "risk_level": "high",
  "risk_reasons": [
    "Cross-scope rule (unscoped consumers)",
    "Allows RDP (3389/tcp)"
  ],
  "change_type": "new_rule",
  "change_summary": "New rule in payments-prod: 3389/tcp",
  "scope": "app=payments AND env=prod",
  "ruleset_name": "payments-prod",
  "ruleset_href": "/orgs/1/sec_policy/draft/rule_sets/123",
  "required_approvals": [
    {"team": "payments-team", "status": "pending", "via": "webhook"},
    {"team": "security-team", "status": "pending", "via": "webhook"}
  ],
  "created": "2026-04-19T10:30:00+00:00",
  "expires_at": "2026-04-26T10:30:00+00:00",
  "callback_approve": "/api/approve/cr-20260419-a1b2c3",
  "callback_reject": "/api/reject/cr-20260419-a1b2c3"
}
```

Headers:
```
Content-Type: application/json
Authorization: Bearer <WEBHOOK_CALLBACK_TOKEN>  (if configured)
```

#### How Approval Comes Back

The external system sends a callback to the plugin:

**Approve:**
```
POST /api/approve/cr-20260419-a1b2c3
Content-Type: application/json

{"team": "payments-team"}
```

**Reject:**
```
POST /api/reject/cr-20260419-a1b2c3
Content-Type: application/json

{"team": "payments-team", "reason": "Not authorized for RDP access"}
```

#### Setup Guide

1. Set `APPROVAL_ADAPTER=webhook` and `WEBHOOK_URL=https://your-system.example.com/illumio-approvals`.
2. Implement an endpoint at that URL that receives the JSON payload and displays it to approvers.
3. When an approver decides, have your system POST back to the plugin's `/api/approve/{id}` or `/api/reject/{id}` endpoint.
4. Optionally set `WEBHOOK_CALLBACK_TOKEN` to a shared secret so both sides can verify authenticity.

---

### Slack Adapter

Posts interactive messages to Slack channels with Approve/Reject buttons using Block Kit.

#### Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `APPROVAL_ADAPTER` | Yes | Set to `slack` |
| `SLACK_BOT_TOKEN` | Yes | Bot User OAuth Token (starts with `xoxb-`) |
| `SLACK_SIGNING_SECRET` | Yes | Signing secret from your Slack app for verifying callbacks |
| `SLACK_DEFAULT_CHANNEL` | No | Fallback channel if the approver config has no `slack_channel` (default: `#security-approvals`) |

#### What Gets Sent

The adapter posts a Block Kit message to the channel specified in the approver config for the matched scope:

```
+--------------------------------------------------------+
|  :large_orange_circle: HIGH RISK -- Policy Change Approval          |
|                                                        |
|  New rule in payments-prod: 3389/tcp                   |
|                                                        |
|  ID: cr-20260419-a1b2c3                                |
|  Scope: app=payments AND env=prod                      |
|  Type: new_rule                                        |
|  Approvers needed: payments-team, security-team        |
|                                                        |
|  Risk reasons:                                         |
|  - Cross-scope rule (unscoped consumers)               |
|  - Allows RDP (3389/tcp)                               |
|                                                        |
|  [ Approve ]  [ Reject ]                               |
+--------------------------------------------------------+
```

The message includes:
- A header with risk level and emoji indicator (red/orange/yellow/green circle).
- Change summary, ID, scope, type, and required approvers.
- Risk reasons as a bulleted list.
- Interactive Approve and Reject buttons (action IDs: `approve_change`, `reject_change`).

#### How Approval Comes Back

When a user clicks Approve or Reject, Slack sends an interaction payload to your configured Request URL (in the Slack app settings). The plugin processes this callback to update the change request status.

#### Setup Guide

1. Create a Slack App at https://api.slack.com/apps.
2. Enable **Interactivity** and set the Request URL to `https://your-plugin-host:8080/api/slack/interact`.
3. Add the **Bot Token Scopes**: `chat:write`, `chat:write.public`.
4. Install the app to your workspace and copy the Bot User OAuth Token.
5. Set environment variables:
   ```
   APPROVAL_ADAPTER=slack
   SLACK_BOT_TOKEN=xoxb-your-token
   SLACK_SIGNING_SECRET=your-signing-secret
   ```
6. Invite the bot to each channel referenced in your `approval-config.yaml` (`/invite @your-bot`).
7. Configure `slack_channel` in each scope entry of your `approval-config.yaml`.

---

### ServiceNow Adapter

Creates Change Requests in ServiceNow via the Table API and polls them for approval status.

#### Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `APPROVAL_ADAPTER` | Yes | Set to `servicenow` |
| `SNOW_INSTANCE` | Yes | ServiceNow instance name (e.g., `myorg` for `myorg.service-now.com`) |
| `SNOW_USER` | Yes | ServiceNow API user with permission to create/read change_request records |
| `SNOW_PASSWORD` | Yes | Password for the ServiceNow API user |

#### What Gets Sent

The adapter creates a Change Request with these fields:

```json
{
  "short_description": "[HIGH] New rule in payments-prod: 3389/tcp",
  "description": "Change ID: cr-20260419-a1b2c3\nRisk Level: HIGH\nRisk Reasons: Cross-scope rule (unscoped consumers); Allows RDP (3389/tcp)\nScope: app=payments AND env=prod\nChange Type: new_rule\nRuleset: payments-prod\nHref: /orgs/1/sec_policy/draft/rule_sets/123\nRequired Approvals: payments-team, security-team\nExpires: 2026-04-26T10:30:00+00:00",
  "category": "Network",
  "type": "Standard",
  "risk": "2",
  "assignment_group": "payments-team",
  "correlation_id": "cr-20260419-a1b2c3"
}
```

ServiceNow risk mapping: CRITICAL=1, HIGH=2, MEDIUM=3, LOW=4, INFO=4.

The `correlation_id` links the ServiceNow CR back to the plugin's change request ID.

#### How Approval Comes Back

The adapter polls ServiceNow for the CR's `approval` field:

| ServiceNow `approval` Value | Plugin Action |
|-----------------------------|--------------|
| `approved` | Move change to APPROVED |
| `rejected` | Move change to REJECTED |
| `not yet requested` / `requested` | Stay PENDING |

Polling happens as part of the background scan loop.

#### Setup Guide

1. Create a ServiceNow API user with roles: `itil`, `change_manager` (or equivalent permissions to create and read `change_request` records).
2. Set environment variables:
   ```
   APPROVAL_ADAPTER=servicenow
   SNOW_INSTANCE=myorg
   SNOW_USER=illumio_api_user
   SNOW_PASSWORD=your-password
   ```
3. Configure `servicenow_group` in each scope entry of your `approval-config.yaml` to match ServiceNow assignment group names.
4. Verify the integration by creating a test draft change and confirming the CR appears in ServiceNow.

---

## Dashboard

The web dashboard runs on port 8080 and provides a real-time view of all policy change approvals. It auto-refreshes every 30 seconds.

### Header

The header bar shows the plugin title and a **Scan Now** button that triggers an immediate change detection cycle (calls `POST /api/scan`).

### Statistics Bar

Five summary counters at the top of the page:

| Counter | Color | Description |
|---------|-------|-------------|
| Pending | Yellow | Changes waiting for approval |
| Approved | Green | Changes approved but not yet provisioned (or auto-provisioned) |
| Rejected | Red | Changes rejected by an approver |
| Provisioned | Blue | Changes successfully provisioned to active |
| Total | White | All-time total of tracked changes |

### Tab: Pending Approvals

Displays all changes in PENDING or DETECTED status, sorted by risk level (CRITICAL first).

Each card shows:
- **Risk badge** -- color-coded pill (red for critical, orange for high, yellow for medium, green for low, gray for info) with the risk level text.
- **Change request ID** -- e.g., `cr-20260419-a1b2c3`.
- **Change summary** -- e.g., "New rule in payments-prod: 3389/tcp".
- **Scope and type** -- e.g., "Scope: app=payments AND env=prod | Type: new_rule".
- **Risk reasons** -- dark pills listing each reason.
- **Approver status** -- each required approver with a checkmark (approved) or hourglass (pending) and their team name.
- **Action buttons**:
  - **Approve** (green) -- calls `POST /api/approve/{id}`.
  - **Reject** (red) -- prompts for a reason, then calls `POST /api/reject/{id}`.
  - **Provision** (blue) -- calls `POST /api/provision/{id}` (only works on approved changes).

When no pending approvals exist, the tab shows "No pending approvals."

### Tab: Recent Activity

Displays the last 50 changes (all statuses) sorted by creation time, newest first.

Each row shows:
- Risk badge (small, colored).
- Change summary and scope/timestamp.
- Status badge (colored pill: blue for detected, yellow for pending, green for approved/provisioned, red for rejected/failed, gray for expired).
- Change request ID.

### Tab: Configuration

Two cards:

1. **Approval Configuration** -- the full YAML config rendered as a `<pre>` block.
2. **Adapter Status** -- current runtime settings:
   - Active adapter name
   - Auto-provision setting
   - Auto-approve low/info setting
   - Scan interval
   - Approval timeout (in days)

---

## API Reference

All API endpoints return JSON (except `/` which returns HTML). The server listens on port 8080 by default (configurable via `HTTP_PORT`).

### GET /

Returns the HTML dashboard. See [Dashboard](#dashboard) for details.

### GET /healthz

Health check endpoint.

**Response:**
```json
{
  "status": "healthy"
}
```

### GET /api/changes

List all tracked change requests.

**Response:**
```json
{
  "changes": [
    {
      "id": "cr-20260419-a1b2c3",
      "created": "2026-04-19T10:30:00+00:00",
      "status": "pending",
      "risk_level": "high",
      "risk_reasons": ["Cross-scope rule (unscoped consumers)", "Allows RDP (3389/tcp)"],
      "change_type": "new_rule",
      "ruleset_name": "payments-prod",
      "ruleset_href": "/orgs/1/sec_policy/draft/rule_sets/123",
      "scope": "app=payments AND env=prod",
      "change_summary": "New rule in payments-prod: 3389/tcp",
      "change_detail": { ... },
      "required_approvals": [
        {"team": "payments-team", "status": "pending", "via": "webhook"},
        {"team": "security-team", "status": "pending", "via": "webhook"}
      ],
      "provisioned": false,
      "provisioned_at": null,
      "provision_result": null,
      "expires_at": "2026-04-26T10:30:00+00:00"
    }
  ],
  "total": 1
}
```

### GET /api/changes/{id}

Get a single change request by ID.

**Response (200):**
```json
{
  "id": "cr-20260419-a1b2c3",
  "created": "2026-04-19T10:30:00+00:00",
  "status": "pending",
  "risk_level": "high",
  "risk_reasons": ["Cross-scope rule (unscoped consumers)"],
  "change_type": "new_rule",
  "ruleset_name": "payments-prod",
  "ruleset_href": "/orgs/1/sec_policy/draft/rule_sets/123",
  "scope": "app=payments AND env=prod",
  "change_summary": "New rule in payments-prod: 3389/tcp",
  "change_detail": { ... },
  "required_approvals": [
    {"team": "payments-team", "status": "approved", "via": "webhook", "approved_at": "2026-04-19T10:35:00+00:00"},
    {"team": "security-team", "status": "pending", "via": "webhook"}
  ],
  "provisioned": false,
  "provisioned_at": null,
  "provision_result": null,
  "expires_at": "2026-04-26T10:30:00+00:00"
}
```

**Response (404):**
```json
{
  "error": "not found"
}
```

### GET /api/pending

List only pending change requests (status is `pending` or `detected`).

**Response:**
```json
{
  "pending": [ ... ],
  "total": 3
}
```

### GET /api/config

Return the current approval configuration (loaded from `approval-config.yaml`).

**Response:**
```json
{
  "approvers": {
    "scopes": {
      "app=payments AND env=prod": {
        "team": "payments-team",
        "slack_channel": "#payments-approvals",
        "email": "payments-team@example.com"
      }
    },
    "default": {
      "team": "security-team",
      "slack_channel": "#security-approvals",
      "email": "security@example.com"
    },
    "cross_scope": {
      "team": "security-team",
      "slack_channel": "#security-approvals"
    },
    "critical": {
      "team": "security-leadership",
      "slack_channel": "#security-urgent"
    }
  },
  "require_approval": ["critical", "high", "medium"],
  "auto_provision": false
}
```

### POST /api/approve/{id}

Approve a change request. If `REQUIRE_ALL_APPROVERS=true`, the change stays PENDING until all teams approve. If `AUTO_PROVISION=true` and the change becomes fully APPROVED, provisioning starts immediately.

**Request body (optional):**
```json
{
  "team": "payments-team"
}
```

If `team` is omitted, defaults to `"manual"` which approves on behalf of all teams.

**Response (200):** The updated change request object (same format as GET /api/changes/{id}).

**Response (404):**
```json
{
  "error": "not found or not pending"
}
```

### POST /api/reject/{id}

Reject a change request. Any single rejection moves the request to REJECTED immediately.

**Request body (optional):**
```json
{
  "team": "security-team",
  "reason": "RDP access not permitted to database tier per policy SEC-2024-003"
}
```

**Response (200):** The updated change request object with `status: "rejected"`, `rejection_reason`, `rejected_by`, and `rejected_at` fields.

**Response (404):**
```json
{
  "error": "not found or not pending"
}
```

### POST /api/provision/{id}

Manually trigger provisioning for an approved change. Only works on changes with `status: "approved"`.

The plugin calls `POST /sec_policy` on the PCE with the ruleset href in a `change_subset` to provision only the specific ruleset (not all draft changes).

**Response (200):** The updated change request object with `status: "provisioned"` or `status: "failed"`.

**Response (404):**
```json
{
  "error": "not found or not approved"
}
```

### POST /api/scan

Trigger an immediate change detection cycle outside the regular `SCAN_INTERVAL`.

**Response (200):**
```json
{
  "status": "scan complete",
  "changes_found": 3
}
```

**Response (500):**
```json
{
  "error": "scan failed"
}
```

---

## approval-config.yaml Reference

The approval configuration file defines scope ownership, team routing, escalation paths, and approval behavior. Mount it at `/data/approval-config.yaml` inside the container (or set `APPROVAL_CONFIG` env var to a custom path).

### Complete Example

```yaml
# ============================================================
# Scope-to-Team Approval Routing
# ============================================================

approvers:
  # Per-scope approvers: map Illumio label expressions to team ownership.
  # The key is a label expression in "key=value AND key=value" format.
  # The plugin matches change scopes against these patterns.
  scopes:
    "app=payments AND env=prod":
      team: payments-team                       # Team identifier (used in approval tracking)
      slack_channel: "#payments-approvals"       # Slack channel for notifications (Slack adapter)
      email: payments-team@example.com           # Email address (for future email adapter)
      servicenow_group: "Payments Engineering"   # ServiceNow assignment group (ServiceNow adapter)

    "app=shareddb AND env=prod":
      team: database-team
      slack_channel: "#dba-approvals"
      email: dba-team@example.com
      servicenow_group: "Database Engineering"

    "app=frontend AND env=prod":
      team: frontend-team
      slack_channel: "#frontend-approvals"
      email: frontend-team@example.com

    # Broader patterns: "env=dev" matches any scope containing env=dev,
    # regardless of the app label.
    "env=dev":
      team: dev-team
      slack_channel: "#dev-changes"
      email: dev-team@example.com

  # Default approver for scopes that don't match any pattern above.
  # This is the catch-all — if you have a ruleset scoped to
  # "app=newproject AND env=prod" and there's no entry for it,
  # the default team handles it.
  default:
    team: security-team
    slack_channel: "#security-approvals"
    email: security@example.com
    servicenow_group: "Information Security"

  # Cross-scope approver: automatically added (in addition to scope
  # owners) whenever a rule has unscoped_consumers: true.
  # This ensures security always reviews extra-scope rules.
  cross_scope:
    team: security-team
    slack_channel: "#security-approvals"
    email: security@example.com

  # Critical escalation: CRITICAL-risk changes bypass normal scope
  # routing and go directly to this team.
  critical:
    team: security-leadership
    slack_channel: "#security-urgent"
    email: ciso@example.com

# ============================================================
# Approval Behavior
# ============================================================

# Risk levels that require explicit approval.
# Changes at these levels must be approved before provisioning.
# Risk levels NOT in this list are auto-approved (logged but not gated).
require_approval:
  - critical
  - high
  - medium
  # 'low' and 'info' are auto-approved by default

# Automatically provision to active policy after all approvals are received?
# true  = approved changes are provisioned immediately with no manual step.
# false = approved changes wait for someone to click "Provision" or call
#         POST /api/provision/{id}.
auto_provision: false
```

### Field Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `approvers.scopes` | map | No | `{}` | Map of label expressions to team configs. Each key is a scope pattern like `"app=payments AND env=prod"`. |
| `approvers.scopes.<pattern>.team` | string | Yes | | Team identifier, used in approval tracking and logging. |
| `approvers.scopes.<pattern>.slack_channel` | string | No | | Slack channel for notifications (Slack adapter). |
| `approvers.scopes.<pattern>.email` | string | No | | Email address for notifications (future use). |
| `approvers.scopes.<pattern>.servicenow_group` | string | No | | ServiceNow assignment group name (ServiceNow adapter). |
| `approvers.default` | map | No | security-team defaults | Catch-all approver for unmatched scopes. Same fields as scope entries. |
| `approvers.cross_scope` | map | No | security-team defaults | Additional approver added for cross-scope (extra-scope) rules. Same fields as scope entries. |
| `approvers.critical` | map | No | Falls back to `default` | Escalation target for CRITICAL-risk changes. Bypasses normal scope routing. Same fields as scope entries. |
| `require_approval` | list of strings | No | `["critical", "high", "medium"]` | Risk levels that require explicit approval. Others are auto-approved. Valid values: `critical`, `high`, `medium`, `low`, `info`. |
| `auto_provision` | boolean | No | `false` | Whether to automatically provision changes after approval. |

---

## Testing Plan

The testing plan is organized into 5 phases, progressing from isolated unit testing to full end-to-end workflows.

### Phase 1: Change Detection (9 test cases, no external systems)

| # | Test | Steps | Expected Result |
|---|------|-------|----------------|
| 1 | Detect new ruleset | Create a ruleset in PCE draft via GUI or API | Plugin detects it, classifies risk, shows in dashboard |
| 2 | Detect new rule | Add a rule to an existing draft ruleset | Plugin detects the new rule with correct scope |
| 3 | Detect modification | Change a rule's service ports in draft | Plugin shows old vs new values |
| 4 | Detect deletion | Delete a draft rule | Plugin detects deletion |
| 5 | Risk: any-to-any | Create a rule with `actors: ams` on both providers and consumers | Classified as CRITICAL |
| 6 | Risk: cross-scope | Create an extra-scope rule (`unscoped_consumers: true`) | Classified as HIGH, identifies both scopes |
| 7 | Risk: risky port | Create a rule allowing 3389/tcp | Classified as HIGH with "RDP" in reason |
| 8 | Risk: intra-scope normal | Create a role-to-role rule on a specific port within one scope | Classified as MEDIUM or LOW |
| 9 | No false positives | Make no changes; wait for a full scan cycle | No changes detected |

### Phase 2: Approval Routing (6 test cases, with webhook or Slack)

| # | Test | Steps | Expected Result |
|---|------|-------|----------------|
| 1 | Single-scope approval | Create an intra-scope rule change | Approval sent to scope owner only |
| 2 | Cross-scope approval | Create an extra-scope rule | Approval sent to BOTH scope owners + security team |
| 3 | Critical escalation | Create an any-to-any rule | Approval sent to critical escalation contacts only |
| 4 | Approve via callback | Click Approve in Slack or POST to callback URL | Change status moves to APPROVED |
| 5 | Reject via callback | Click Reject in Slack or POST to callback URL with reason | Change status moves to REJECTED with reason |
| 6 | Timeout expiry | Wait for the timeout period to pass | Change status moves to EXPIRED |

### Phase 3: Provisioning (4 test cases)

| # | Test | Steps | Expected Result |
|---|------|-------|----------------|
| 1 | Auto-provision on approve | Approve a change with `AUTO_PROVISION=true` | Draft provisioned to active automatically |
| 2 | Manual provision | Approve a change, then click "Provision" in dashboard | Provisioned on manual click |
| 3 | Provision failure | Approve a change referencing an invalid ruleset href | Status moves to FAILED with error message |
| 4 | Multi-approver gate | Cross-scope change with 3 required approvers | Only provisions when ALL 3 approve |

### Phase 4: Multi-Team Workflow (4 test cases, requires multiple PCE users)

| # | Test | Steps | Expected Result |
|---|------|-------|----------------|
| 1 | Team A requests, Team B approves | User A creates cross-scope rule; User B gets notified | Full flow: detect -> notify B -> B approves -> provision |
| 2 | Team B rejects | User A creates rule; User B rejects with reason | Rule stays in draft; rejection reason logged |
| 3 | Security team override | Security team approves a change in any scope | Works regardless of scope ownership |
| 4 | Partial approval | 2 of 3 approvers approve; 1 still pending | Stays PENDING until all complete |

### Phase 5: Edge Cases (5 test cases)

| # | Test | Steps | Expected Result |
|---|------|-------|----------------|
| 1 | Concurrent changes | Multiple changes in one scan cycle | Each gets its own approval request |
| 2 | Change withdrawn | User deletes draft change before approval completes | Change detected as withdrawn; status updated |
| 3 | PCE unavailable | PCE goes down during scan | Error logged; retry on next cycle |
| 4 | Adapter unavailable | Slack/ServiceNow down when sending approval | Retry with backoff; status shows notification failure |
| 5 | Duplicate detection | Same change persists across two scan cycles | Deduplication by change fingerprint prevents duplicate requests |

---

## Getting Started

### Prerequisites

- A running Illumio PCE (on-prem or SaaS) with API credentials.
- The `plugger` CLI installed and configured.
- An external approval system (or just use the webhook adapter with `curl` for testing).

### Step 1: Install the Plugin

```bash
plugger install policy-workflow
```

This builds the Docker image and registers the plugin with the plugger framework.

### Step 2: Create the Approval Config

Create an `approval-config.yaml` file. Start with the example:

```bash
cp approval-config.yaml.example /path/to/your/data/approval-config.yaml
```

Edit it to match your organization's scope ownership:

```yaml
approvers:
  scopes:
    "app=myapp AND env=prod":
      team: myapp-team
      slack_channel: "#myapp-approvals"
  default:
    team: security-team
    slack_channel: "#security-approvals"
  cross_scope:
    team: security-team
  critical:
    team: security-leadership

require_approval:
  - critical
  - high
  - medium

auto_provision: false
```

### Step 3: Configure the Adapter (Webhook for Testing)

For initial testing, use the webhook adapter. You do not need an external system -- you can approve changes via the dashboard or `curl`.

Set the required environment variables in your plugger configuration or pass them at startup:

```bash
# Minimum configuration
export APPROVAL_ADAPTER=webhook
export SCAN_INTERVAL=60          # Scan every 60s for faster testing
export AUTO_APPROVE_LOW=true     # Auto-approve low/info changes
export AUTO_PROVISION=false      # Require manual provision click
```

If you want webhook notifications sent to an external URL:

```bash
export WEBHOOK_URL=https://your-system.example.com/illumio-approvals
export WEBHOOK_CALLBACK_TOKEN=your-shared-secret
```

### Step 4: Start the Plugin

```bash
plugger start policy-workflow
```

The plugin connects to the PCE, loads the approval config, and starts scanning for draft changes.

Check the logs:

```bash
plugger logs policy-workflow
```

You should see:
```
2026-04-19T10:00:00 [INFO] Starting policy-workflow plugin...
2026-04-19T10:00:00 [INFO] Approval config loaded from /data/approval-config.yaml
2026-04-19T10:00:00 [INFO] Using approval adapter: webhook
2026-04-19T10:00:00 [INFO] Connected to PCE: https://pce.example.com:8443
2026-04-19T10:00:00 [INFO] Loaded 150 labels into cache
2026-04-19T10:00:00 [INFO] Change detection loop started (interval=60s)
2026-04-19T10:00:00 [INFO] Dashboard listening on http://0.0.0.0:8080
```

### Step 5: Make a Draft Policy Change in the PCE

In the PCE GUI or via API, create a draft change. For example, add a new rule to an existing ruleset:

```bash
curl -u "$PCE_API_KEY:$PCE_API_SECRET" \
  -X POST "https://pce.example.com:8443/api/v2/orgs/1/sec_policy/draft/rule_sets/42/sec_rules" \
  -H "Content-Type: application/json" \
  -d '{
    "providers": [{"label": {"href": "/orgs/1/labels/789"}}],
    "consumers": [{"label": {"href": "/orgs/1/labels/456"}}],
    "ingress_services": [{"port": 8080, "proto": 6}],
    "enabled": true
  }'
```

### Step 6: Watch It Appear in the Dashboard

Open http://localhost:8080 in your browser. After the next scan cycle (up to `SCAN_INTERVAL` seconds), the change appears in the Pending Approvals tab.

Or trigger an immediate scan:

```bash
curl -X POST http://localhost:8080/api/scan
```

Response:
```json
{
  "status": "scan complete",
  "changes_found": 1
}
```

Verify it is tracked:

```bash
curl http://localhost:8080/api/pending
```

### Step 7: Approve via API

Approve the change request:

```bash
curl -X POST http://localhost:8080/api/approve/cr-20260419-a1b2c3 \
  -H "Content-Type: application/json" \
  -d '{"team": "myapp-team"}'
```

If `REQUIRE_ALL_APPROVERS=true` and multiple teams are required, repeat for each team. The change moves to APPROVED once all teams have approved.

### Step 8: Provision

If `AUTO_PROVISION=true`, provisioning happens automatically on approval. Otherwise, trigger it manually:

```bash
curl -X POST http://localhost:8080/api/provision/cr-20260419-a1b2c3
```

Or click the **Provision** button in the dashboard.

### Step 9: Verify Provisioning

Check the change request status:

```bash
curl http://localhost:8080/api/changes/cr-20260419-a1b2c3
```

The response should show:
```json
{
  "id": "cr-20260419-a1b2c3",
  "status": "provisioned",
  "provisioned": true,
  "provisioned_at": "2026-04-19T10:45:00+00:00",
  "provision_result": "success"
}
```

Confirm in the PCE that the rule is now in active policy.

---

## Environment Variable Reference

Complete list of all environment variables, in one place:

| Variable | Default | Description |
|----------|---------|-------------|
| `PCE_HOST` | (required) | PCE hostname or URL |
| `PCE_PORT` | `8443` | PCE API port |
| `PCE_ORG_ID` | `1` | PCE organization ID |
| `PCE_API_KEY` | (required) | PCE API key (username) |
| `PCE_API_SECRET` | (required) | PCE API secret (password) |
| `PCE_TLS_SKIP_VERIFY` | `false` | Skip TLS certificate verification |
| `SCAN_INTERVAL` | `300` | Seconds between draft change detection scans |
| `APPROVAL_ADAPTER` | `webhook` | Adapter to use: `webhook`, `slack`, or `servicenow` |
| `APPROVAL_TIMEOUT` | `604800` | Seconds before pending changes expire (default 7 days) |
| `APPROVAL_CONFIG` | `/data/approval-config.yaml` | Path to the approval configuration YAML file |
| `AUTO_PROVISION` | `false` | Automatically provision on approval |
| `AUTO_APPROVE_LOW` | `true` | Auto-approve LOW and INFO risk changes |
| `REQUIRE_ALL_APPROVERS` | `true` | All approvers must approve (vs any one) |
| `HTTP_PORT` | `8080` | Port for the dashboard and API server |
| `WEBHOOK_URL` | | URL to POST approval requests to (webhook adapter) |
| `WEBHOOK_CALLBACK_TOKEN` | | Bearer token for webhook authentication |
| `SLACK_BOT_TOKEN` | | Slack Bot User OAuth Token (slack adapter) |
| `SLACK_SIGNING_SECRET` | | Slack app signing secret (slack adapter) |
| `SLACK_DEFAULT_CHANNEL` | `#security-approvals` | Fallback Slack channel |
| `SNOW_INSTANCE` | | ServiceNow instance name (servicenow adapter) |
| `SNOW_USER` | | ServiceNow API username (servicenow adapter) |
| `SNOW_PASSWORD` | | ServiceNow API password (servicenow adapter) |

## Dependencies

| Package | Purpose |
|---------|---------|
| `illumio` | PCE SDK for API communication |
| `requests` | HTTP client for adapter outbound calls |
| `pyyaml` | Parsing the approval-config.yaml file |

No adapter-specific SDKs are required. All adapters (Slack, ServiceNow, webhook) use REST APIs directly via `requests`.

## Container Details

- **Base image**: `python:3.12-slim`
- **Exposed port**: 8080
- **Data volume**: `/data` (for `approval-config.yaml`)
- **Runs as**: non-root user (`plugin`, UID 1000)
- **Memory limit**: 256 MB
- **CPU limit**: 0.5 cores
- **Health check**: `GET /healthz` on port 8080 every 30s
