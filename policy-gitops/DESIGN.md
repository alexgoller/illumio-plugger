# Policy GitOps — Design Document

> This may become a standalone project outside of plugger. The plugin component handles PCE sync. The GitHub Actions workflow, security checks, and PR visualization live in the customer's policy repo.

## Problem Statement

Illumio policy is managed through a GUI or REST API. There is no version control, no peer review process, no multi-team approval workflow, and no audit trail beyond PCE events. When multiple teams own different parts of the policy (different app scopes), cross-scope rules require out-of-band coordination.

**Who feels this pain:**
- Security architects who want policy-as-code discipline
- Compliance teams who need evidence of change review processes
- Multi-team environments where Team A can't unilaterally create rules touching Team B's scope
- Operations teams who want rollback capability when a policy change breaks something

## Solution

Export Illumio policy to a Git repository as structured YAML files, organized by scope ownership. Changes flow through Git's native PR/MR workflow with CODEOWNERS-enforced reviews. A GitHub Actions pipeline validates changes, runs security checks, queries traffic evidence, renders beautiful PR comments, and provisions approved changes.

## Architecture

```
                    ┌─────────────────────┐
                    │    Illumio PCE       │
                    │                     │
                    │  Draft Policy       │
                    │  Active Policy      │
                    │  Traffic Flows      │──── evidence for rule requests
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼─────┐  ┌────▼──────┐  ┌────▼──────────┐
     │ policy-gitops │  │  GitHub   │  │ GitHub Actions │
     │ plugin        │  │  Actions  │  │ (in policy     │
     │               │  │  (CI/CD)  │  │  repo)         │
     │ Export PCE→Git│  │           │  │                │
     │ Drift detect  │  │ On PR:    │  │ Security check │
     │ Import Git→PCE│  │  validate │  │ Traffic query  │
     │               │  │  comment  │  │ PR comment     │
     │ (plugger      │  │  approve  │  │ Provision      │
     │  container)   │  │  provision│  │                │
     └──────────────┘  └───────────┘  └────────────────┘
```

Two components:
1. **plugger plugin** (`policy-gitops`) — handles PCE↔Git sync, drift detection
2. **GitHub Actions workflow** (lives in the policy repo) — handles PR validation, security checks, traffic evidence, visualization, provisioning on merge

---

## Repository Structure

```
illumio-policy/                        ← The customer's policy repo
├── README.md
├── CODEOWNERS
│
├── .github/
│   └── workflows/
│       ├── validate-policy.yml        ← Runs on PR: lint + security check + traffic evidence
│       └── provision-policy.yml       ← Runs on merge to main: provision to PCE
│
├── .illumio/
│   ├── config.yaml                    ← PCE connection + repo settings
│   ├── security-rules.yaml            ← Security check rules (what to flag)
│   └── team-config.yaml               ← Scope→team ownership mapping
│
├── scopes/
│   ├── _global/                       ← Unscoped rulesets
│   │   ├── default.yaml
│   │   └── coreservices.yaml
│   │
│   ├── payments-prod/
│   │   ├── _scope.yaml                ← Scope definition
│   │   ├── intra-rules.yaml
│   │   └── cross-scope/
│   │       └── to-shareddb.yaml
│   │
│   ├── shareddb-prod/
│   │   ├── _scope.yaml
│   │   ├── intra-rules.yaml
│   │   └── inbound/
│   │       └── from-payments.yaml
│   │
│   └── ordering-prod/
│       ├── _scope.yaml
│       └── intra-rules.yaml
│
├── ip-lists/
│   ├── any.yaml
│   ├── rfc1918.yaml
│   └── zscaler-ips.yaml
│
├── services/
│   ├── https.yaml
│   └── postgresql.yaml
│
└── labels/
    └── labels.yaml
```

---

## GitHub Actions: validate-policy.yml

Runs on every PR. Four stages: lint, security check, traffic evidence, PR comment.

```yaml
name: Validate Policy Change

on:
  pull_request:
    branches: [main]
    paths:
      - 'scopes/**'
      - 'ip-lists/**'
      - 'services/**'

permissions:
  contents: read
  pull-requests: write

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Need full history for diff

      # 1. Determine what changed
      - name: Detect changed policy files
        id: changes
        run: |
          CHANGED=$(git diff --name-only origin/main...HEAD -- scopes/ ip-lists/ services/)
          echo "files<<EOF" >> $GITHUB_OUTPUT
          echo "$CHANGED" >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT
          echo "count=$(echo "$CHANGED" | wc -l)" >> $GITHUB_OUTPUT

      # 2. Lint YAML
      - name: Lint policy YAML
        run: |
          pip install pyyaml
          python3 .github/scripts/lint-policy.py ${{ steps.changes.outputs.files }}

      # 3. Security check
      - name: Security analysis
        id: security
        env:
          PCE_HOST: ${{ secrets.PCE_HOST }}
          PCE_API_KEY: ${{ secrets.PCE_API_KEY }}
          PCE_API_SECRET: ${{ secrets.PCE_API_SECRET }}
        run: |
          pip install illumio pyyaml
          python3 .github/scripts/security-check.py \
            --changed-files "${{ steps.changes.outputs.files }}" \
            --output security-report.json

      # 4. Query traffic evidence
      - name: Traffic evidence
        id: traffic
        env:
          PCE_HOST: ${{ secrets.PCE_HOST }}
          PCE_API_KEY: ${{ secrets.PCE_API_KEY }}
          PCE_API_SECRET: ${{ secrets.PCE_API_SECRET }}
        run: |
          python3 .github/scripts/traffic-evidence.py \
            --changed-files "${{ steps.changes.outputs.files }}" \
            --lookback-days 30 \
            --output traffic-report.json

      # 5. Render PR comment
      - name: Post PR comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const security = JSON.parse(fs.readFileSync('security-report.json', 'utf8'));
            const traffic = JSON.parse(fs.readFileSync('traffic-report.json', 'utf8'));
            // ... render markdown comment (see below)
```

---

## Security Check Pipeline

### security-rules.yaml

Configurable rules that the pipeline evaluates against every changed policy file:

```yaml
# .illumio/security-rules.yaml

rules:
  # CRITICAL — block the PR
  - id: SEC-001
    name: "No any-to-any rules"
    severity: critical
    action: block
    check: |
      Rule must not have both providers=[{actors: ams}] 
      and consumers=[{actors: ams}]
    message: "Any-to-any rules defeat micro-segmentation. Use specific labels."

  - id: SEC-002
    name: "No broad port ranges"
    severity: critical
    action: block
    check: |
      No service with port range > 1000 ports
    message: "Port ranges over 1000 are too broad. Specify exact services."

  - id: SEC-003
    name: "No insecure protocols"
    severity: critical
    action: block
    ports: [21, 23, 69, 513, 514]
    message: "FTP, Telnet, TFTP, rlogin, rsh are insecure. Use SSH/SFTP."

  # HIGH — warn but don't block
  - id: SEC-004
    name: "Cross-scope rules need justification"
    severity: high
    action: warn
    check: |
      Cross-scope rules (unscoped_consumers: true) must have
      a 'justification' field
    message: "Cross-scope rules require a justification comment."

  - id: SEC-005
    name: "RDP/SMB restricted"
    severity: high
    action: warn
    ports: [3389, 445]
    message: "RDP and SMB are lateral movement vectors. Verify this is necessary."

  - id: SEC-006
    name: "Database ports restricted to app tier"
    severity: high
    action: warn
    ports: [5432, 3306, 1433, 1521, 27017]
    message: "Database ports should only be accessible from application tier, not broadly."

  # MEDIUM — informational
  - id: SEC-007
    name: "New ruleset review"
    severity: medium
    action: info
    check: |
      New rulesets (file added, not modified) are flagged for awareness
    message: "New ruleset created — verify scope and rules are correct."

  - id: SEC-008
    name: "IP List with broad CIDR"
    severity: medium
    action: warn
    check: |
      IP lists with /8 or broader CIDRs
    message: "Very broad CIDR range. Consider narrowing."

# Override: rules that are always allowed (bypass security checks)
exemptions:
  - ruleset_pattern: "coreservices"
    exempt_rules: [SEC-005]  # Allow SMB in coreservices for AD
    reason: "Active Directory requires SMB for domain operations"
```

### security-check.py

The Python script loaded by GitHub Actions:

```python
# .github/scripts/security-check.py
# Reads changed YAML files, evaluates against security-rules.yaml
# Outputs: security-report.json with findings per file

Findings structure:
{
  "findings": [
    {
      "file": "scopes/payments-prod/cross-scope/to-shareddb.yaml",
      "rule_id": "SEC-004",
      "severity": "high",
      "action": "warn",
      "message": "Cross-scope rules require a justification comment",
      "line": 12,
      "context": "unscoped_consumers: true"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "blocked": false
  }
}
```

---

## Traffic Evidence Pipeline

The most powerful part. When someone adds a rule like "allow web→db on 5432/tcp", the pipeline **queries the PCE for actual traffic** to prove the rule is needed.

### traffic-evidence.py

```python
# .github/scripts/traffic-evidence.py
# For each new/changed rule, queries PCE traffic flows to find evidence

For a rule:
  consumers: [{label: {role: web}}]
  providers: [{label: {role: db}}]  
  services: [{port: 5432, proto: tcp}]

Queries PCE:
  TrafficQuery for blocked/potentially_blocked flows
  Where: src labels match consumer, dst labels match provider
  Service: port 5432

Output:
{
  "evidence": [
    {
      "file": "scopes/payments-prod/intra-rules.yaml",
      "rule_name": "web-to-db",
      "traffic_found": true,
      "blocked_connections": 4523,
      "unique_sources": 3,
      "unique_destinations": 2,
      "first_seen": "2026-04-01T10:00:00Z",
      "last_seen": "2026-04-27T08:30:00Z",
      "sample_flows": [
        {
          "src": "web01.payments.prod (10.0.1.5)",
          "dst": "db01.payments.prod (10.0.2.1)",
          "port": "5432/tcp",
          "connections": 1823,
          "decision": "blocked"
        }
      ],
      "verdict": "JUSTIFIED — 4,523 blocked connections over 26 days from 3 sources"
    }
  ]
}
```

If **no traffic evidence** is found, the PR comment flags it:
```
⚠️ No blocked traffic found for rule "web-to-db" (5432/tcp)
   This rule may not be needed, or the traffic hasn't occurred yet.
   Consider: is this a proactive rule for a new deployment?
```

---

## PR Comment Visualization

The pipeline posts a single, beautiful markdown comment on each PR:

````markdown
## 🔒 Illumio Policy Change Report

### Summary
| Metric | Value |
|--------|-------|
| Files changed | 3 |
| Rules added | 2 |
| Rules modified | 1 |
| Security findings | 1 warning |
| Traffic evidence | 2 of 2 rules justified |

---

### 📋 Changes

#### `scopes/payments-prod/intra-rules.yaml`

<table>
<tr><th>Change</th><th>Details</th></tr>
<tr>
<td>➕ <b>New Rule: web-to-db</b></td>
<td>

| | |
|---|---|
| **Consumers** | `role:web` (3 workloads: web01, web02, web03) |
| **Providers** | `role:db` (2 workloads: db01, db02) |
| **Services** | PostgreSQL (5432/tcp) |
| **Scope** | payments / prod (intra-scope) |

</td>
</tr>
</table>

#### `scopes/payments-prod/cross-scope/to-shareddb.yaml`

<table>
<tr><th>Change</th><th>Details</th></tr>
<tr>
<td>➕ <b>New Cross-Scope Rule: payments-to-shareddb</b></td>
<td>

| | |
|---|---|
| **From** | `app:payments, role:processing` → `app:shareddb, role:db` |
| **Services** | PostgreSQL (5432/tcp) |
| **Type** | ⚠️ Extra-scope (requires database-team approval) |
| **Justification** | Payment processing requires direct DB access for transaction writes |

</td>
</tr>
</table>

---

### 🛡️ Security Analysis

| | Rule | Severity | Finding |
|---|---|---|---|
| ✅ | SEC-001: No any-to-any | — | Pass |
| ✅ | SEC-002: No broad ports | — | Pass |
| ✅ | SEC-003: No insecure protocols | — | Pass |
| ⚠️ | SEC-005: RDP/SMB restricted | High | `to-shareddb.yaml` — verify cross-scope DB access |
| ✅ | SEC-006: DB ports restricted | — | Pass (consumers scoped to role:processing) |

**Result: ✅ No blockers** (1 warning)

---

### 📊 Traffic Evidence

<table>
<tr>
<th>Rule</th>
<th>Evidence</th>
<th>Verdict</th>
</tr>
<tr>
<td><b>web-to-db</b><br><code>5432/tcp</code></td>
<td>

```
4,523 blocked connections (last 30 days)
├── web01 → db01: 1,823 connections
├── web02 → db01: 1,502 connections
├── web03 → db02: 1,198 connections
First seen: Apr 1, 2026
Last seen:  Apr 27, 2026 (8:30 AM)
```

</td>
<td>✅ <b>Justified</b><br>High volume blocked traffic confirms this rule is needed</td>
</tr>
<tr>
<td><b>payments-to-shareddb</b><br><code>5432/tcp</code></td>
<td>

```
891 blocked connections (last 30 days)
├── proc01 → shareddb01: 891 connections
First seen: Apr 10, 2026
Last seen:  Apr 27, 2026 (7:15 AM)
```

</td>
<td>✅ <b>Justified</b><br>Consistent blocked traffic from processing tier</td>
</tr>
</table>

---

### 👥 Approval Status

| Team | Scope | Status |
|------|-------|--------|
| @org/payments-team | `payments-prod` (owner) | ✅ Author |
| @org/database-team | `shareddb-prod` (affected) | ⏳ Review required |
| @org/security-team | Cross-scope review | ⏳ Review required |

---

<sub>🤖 Generated by <a href="https://github.com/alexgoller/illumio-plugger">Illumio Policy GitOps</a> · <a href="https://github.com/alexgoller/illumio-plugger/tree/main/policy-gitops">Docs</a></sub>
````

---

## GitHub Actions: provision-policy.yml

Runs on merge to main. Provisions changed policy to PCE.

```yaml
name: Provision Policy

on:
  push:
    branches: [main]
    paths:
      - 'scopes/**'
      - 'ip-lists/**'
      - 'services/**'

permissions:
  contents: read

jobs:
  provision:
    runs-on: ubuntu-latest
    environment: production  # Requires environment approval in GitHub settings
    steps:
      - uses: actions/checkout@v4

      - name: Detect changed files
        id: changes
        run: |
          CHANGED=$(git diff --name-only HEAD~1 -- scopes/ ip-lists/ services/)
          echo "files=$CHANGED" >> $GITHUB_OUTPUT

      - name: Provision to PCE
        env:
          PCE_HOST: ${{ secrets.PCE_HOST }}
          PCE_PORT: ${{ secrets.PCE_PORT }}
          PCE_API_KEY: ${{ secrets.PCE_API_KEY }}
          PCE_API_SECRET: ${{ secrets.PCE_API_SECRET }}
        run: |
          pip install illumio pyyaml
          python3 .github/scripts/provision.py \
            --changed-files "${{ steps.changes.outputs.files }}" \
            --mode draft  # or --mode active for auto-provision

      - name: Post result to Slack
        if: always()
        run: |
          # Notify on success or failure
          python3 .github/scripts/notify-provision.py \
            --status ${{ job.status }}
```

---

## Standalone Project Structure

When broken out of plugger, the project would look like:

```
illumio-policy-gitops/
├── README.md                          ← Project docs
├── LICENSE
│
├── plugin/                            ← The plugger plugin (PCE sync engine)
│   ├── main.py
│   ├── Dockerfile
│   ├── .plugger/metadata.yaml
│   └── plugin.yaml
│
├── action/                            ← Reusable GitHub Action
│   ├── action.yml                     ← GitHub Action definition
│   ├── scripts/
│   │   ├── lint-policy.py
│   │   ├── security-check.py
│   │   ├── traffic-evidence.py
│   │   ├── provision.py
│   │   └── render-comment.py
│   └── templates/
│       └── pr-comment.md.j2           ← Jinja2 template for PR comment
│
├── template/                          ← Starter repo template
│   ├── .github/
│   │   └── workflows/
│   │       ├── validate-policy.yml
│   │       └── provision-policy.yml
│   ├── .illumio/
│   │   ├── config.yaml
│   │   ├── security-rules.yaml
│   │   └── team-config.yaml
│   ├── scopes/
│   │   └── _global/
│   ├── ip-lists/
│   ├── services/
│   ├── labels/
│   ├── CODEOWNERS
│   └── README.md
│
└── docs/
    ├── getting-started.md
    ├── security-rules-reference.md
    ├── yaml-format.md
    └── multi-team-workflows.md
```

The **action/** could be published as a reusable GitHub Action:
```yaml
# Customer's workflow can just reference:
- uses: alexgoller/illumio-policy-gitops/action@v1
  with:
    pce-host: ${{ secrets.PCE_HOST }}
    pce-api-key: ${{ secrets.PCE_API_KEY }}
    pce-api-secret: ${{ secrets.PCE_API_SECRET }}
    mode: validate  # or: provision
```

---

## YAML Format

### Scope definition (`_scope.yaml`)
```yaml
name: payments-prod
labels:
  app: payments
  env: prod
owners:
  - team: payments-team
    github: @org/payments-team
description: "Payment processing application — production environment"
```

### Intra-scope ruleset
```yaml
name: payments-prod-intra
description: "Intra-scope rules for payments production"
enabled: true
rules:
  - name: web-to-app
    consumers:
      - label: {role: web}
    providers:
      - label: {role: processing}
    services:
      - {port: 8443, proto: tcp}
      - {port: 8080, proto: tcp}
    enabled: true

  - name: app-to-db
    consumers:
      - label: {role: processing}
    providers:
      - label: {role: db}
    services:
      - {port: 5432, proto: tcp}
    enabled: true
```

### Cross-scope rule request
```yaml
name: payments-to-shareddb
description: "Payments app needs access to shared database"
type: extra-scope

requester:
  scope: payments-prod
  consumers:
    - label: {role: processing}

target:
  scope: shareddb-prod
  providers:
    - label: {role: db}

services:
  - {port: 5432, proto: tcp}

justification: "Payment processing requires direct DB access for transaction writes"
requested_by: alice@example.com
requested_date: "2026-04-26"
```

### CODEOWNERS
```
# Global policy — security team must review
scopes/_global/         @org/security-team
ip-lists/               @org/security-team
services/               @org/security-team

# Per-scope ownership
scopes/payments-prod/   @org/payments-team
scopes/shareddb-prod/   @org/database-team
scopes/ordering-prod/   @org/ordering-team

# Cross-scope rules require BOTH teams
scopes/*/cross-scope/   @org/security-team
scopes/*/inbound/       @org/security-team
```

---

## Cross-Scope Rule Flow

```
1. Team A (payments) creates a PR:
   - Adds: scopes/payments-prod/cross-scope/to-shareddb.yaml
   - Adds: scopes/shareddb-prod/inbound/from-payments.yaml (mirror)

2. GitHub Actions validate-policy runs:
   - Security check: flags as HIGH (cross-scope, DB access)
   - Traffic evidence: queries PCE, finds 891 blocked flows → JUSTIFIED
   - Posts beautiful PR comment with all details

3. CODEOWNERS triggers reviews:
   - @org/payments-team → auto-approved (their own scope)
   - @org/database-team → MUST review (touches their inbound dir)
   - @org/security-team → MUST review (cross-scope policy)

4. Team B (database) reviews:
   - Sees the PR comment with traffic evidence
   - "891 blocked connections over 17 days — this is real traffic"
   - Approves

5. Security team reviews:
   - Validates least-privilege (specific port, specific roles)
   - No security findings blocking
   - Approves

6. PR merges → provision-policy runs:
   - Creates the extra-scope ruleset on PCE draft
   - Provisions to active
   - Comments with result

7. Full audit trail in Git:
   - PR author = requester
   - PR reviewers = approvers
   - Merge timestamp = approval time
   - Git diff = exact change
   - PR comment = security analysis + traffic evidence
```

---

## Source of Truth

**Recommended: Git as source of truth**

- Git repo is the canonical state of policy
- PCE is the enforcement engine
- Changes in PCE GUI detected as "drift" and flagged
- Emergency changes: allow in PCE, auto-create reconciliation PR

**The plugin handles:**
- Initial export of existing PCE policy → Git (bootstrap)
- Periodic drift detection (Git vs PCE)
- The Git→PCE provisioning (called by GitHub Actions or manually)

---

## Configuration

### Plugin config (plugger environment)

| Variable | Default | Description |
|----------|---------|-------------|
| `GIT_REPO_URL` | _(required)_ | Policy Git repository URL |
| `GIT_BRANCH` | `main` | Target branch |
| `GIT_TOKEN` | _(required)_ | Git personal access token |
| `GIT_PROVIDER` | `github` | `github`, `gitlab`, `bitbucket` |
| `SYNC_MODE` | `export` | `export`, `provision`, `bidirectional` |
| `SCAN_INTERVAL` | `3600` | Seconds between sync/drift checks |
| `AUTO_PROVISION` | `false` | Auto-provision on Git→PCE sync |
| `DRIFT_ALERT` | `true` | Alert on drift |

### Policy repo config (`.illumio/config.yaml`)

```yaml
pce:
  # PCE connection (used by GitHub Actions, not stored in plugin)
  # Credentials come from GitHub Secrets
  host: pce.example.com
  port: 8443
  org_id: 1

policy:
  # What to manage
  export_rulesets: true
  export_ip_lists: true
  export_services: true
  export_labels: false  # Labels usually managed outside policy-as-code

  # Provisioning
  provision_mode: draft  # draft | active
  provision_on_merge: true

security:
  # Security check enforcement
  block_on_critical: true
  block_on_high: false
  require_traffic_evidence: false  # If true, rules without traffic evidence are flagged

traffic:
  # Traffic evidence settings
  lookback_days: 30
  min_connections: 10  # Minimum blocked connections to consider "evidence"
```

---

## Dependencies

### Plugin
- `illumio` — PCE SDK
- `requests` — HTTP client
- `pyyaml` — YAML serialization
- `subprocess` — Git operations (no gitpython needed)

### GitHub Actions scripts
- `illumio` — PCE SDK (pip installed in action)
- `pyyaml` — YAML parsing
- Standard library only otherwise

---

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Bidirectional sync loops | Bot commits identified by author; ignore on import |
| Emergency changes bypassing Git | Drift detector flags; auto-create reconciliation PR |
| Label HREFs differ between export and import | YAML uses key:value; resolve at provision time |
| Large policy repos | Only export changed objects; Git handles scale well |
| Git conflicts | Scope-per-directory minimizes conflicts |
| CODEOWNERS not enforced | Docs require branch protection enabled |
| Traffic evidence query slow | Cache results; query only for new/changed rules |
| Secrets in PR comments | Never include API keys; only show traffic counts and workload names |

---

## Future

- **GitLab MR support** (CODEOWNERS works in GitLab too)
- **Bitbucket support** (reviewer rules instead of CODEOWNERS)
- **Policy validation CI**: more sophisticated linting
- **Slack/Teams notification**: when cross-scope PR needs review
- **Terraform bridge**: export policy as Terraform HCL
- **Policy simulation**: "what would change if this rule is applied" using PCE's draft mode
- **Auto-remediation PRs**: when drift is detected, auto-create a PR to bring Git back in sync
