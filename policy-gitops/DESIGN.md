# Policy GitOps — Design Document

## Problem Statement

Illumio policy is managed through a GUI or REST API. There is no version control, no peer review process, no multi-team approval workflow, and no audit trail beyond PCE events. When multiple teams own different parts of the policy (different app scopes), cross-scope rules require out-of-band coordination.

**Who feels this pain:**
- Security architects who want policy-as-code discipline
- Compliance teams who need evidence of change review processes
- Multi-team environments where Team A can't unilaterally create rules touching Team B's scope
- Operations teams who want rollback capability when a policy change breaks something

## Solution

Export Illumio policy to a Git repository as structured YAML files, organized by scope ownership. Changes flow through Git's native PR/MR workflow with CODEOWNERS-enforced reviews. Merged changes are automatically provisioned back to the PCE.

## Architecture

```
                    ┌─────────────────────┐
                    │    Illumio PCE       │
                    │                     │
                    │  Draft Policy       │──── manual GUI changes
                    │  Active Policy      │
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │   policy-gitops      │
                    │   plugin             │
                    │                     │
                    │  1. Export PCE→Git   │
                    │  2. Detect drift     │
                    │  3. Provision Git→PCE│
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │    Git Repository    │
                    │                     │
                    │  CODEOWNERS         │──── enforces team ownership
                    │  Branch protection  │──── enforces reviews
                    │  PR workflow        │──── multi-team approval
                    │  Git history        │──── full audit trail
                    └─────────────────────┘
```

## Repository Structure

```
illumio-policy/
├── README.md                           # Policy overview + team contacts
├── CODEOWNERS                          # Scope → team mapping
├── .github/
│   └── workflows/
│       └── provision.yml               # GitHub Actions: provision on merge
│
├── config.yaml                         # Repo-level settings (PCE target, etc.)
│
├── scopes/                             # One directory per RBAC scope
│   ├── _global/                        # Unscoped rulesets (e.g., Default, coreservices)
│   │   ├── default.yaml
│   │   └── coreservices.yaml
│   │
│   ├── payments-prod/                  # Team A's scope: app=payments, env=prod
│   │   ├── _scope.yaml                 # Scope definition (labels)
│   │   ├── intra-rules.yaml            # Intra-scope rules
│   │   └── cross-scope/               # Rules requiring other team's approval
│   │       └── to-shareddb.yaml        # Extra-scope: payments → shareddb
│   │
│   ├── shareddb-prod/                  # Team B's scope: app=shareddb, env=prod
│   │   ├── _scope.yaml
│   │   ├── intra-rules.yaml
│   │   └── inbound/                   # Inbound cross-scope approvals
│   │       └── from-payments.yaml      # Mirror of payments' cross-scope request
│   │
│   └── ordering-prod/                  # Team C's scope
│       ├── _scope.yaml
│       └── intra-rules.yaml
│
├── ip-lists/                           # Shared IP lists
│   ├── any.yaml
│   ├── rfc1918.yaml
│   └── zscaler-ips.yaml
│
├── services/                           # Service definitions
│   ├── https.yaml
│   └── postgresql.yaml
│
└── labels/                             # Label definitions (optional export)
    └── labels.yaml
```

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
      - {port: 5432, proto: tcp}  # PostgreSQL
    enabled: true
```

### Cross-scope rule request
```yaml
# File: scopes/payments-prod/cross-scope/to-shareddb.yaml
# This file is in payments' directory (they initiate)
# But it ALSO requires a mirror in shareddb-prod/inbound/from-payments.yaml
# CODEOWNERS ensures Team B reviews changes to shareddb's directory

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
  - {port: 5432, proto: tcp}  # PostgreSQL

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

## Sync Modes

### 1. Export (PCE → Git)
- `POST /api/export` or automatic on schedule
- Reads all active rulesets, IP lists, services from PCE
- Maps rulesets to scope directories based on ruleset scope labels
- Writes YAML files to the configured Git repo
- Creates a commit with change summary

### 2. Drift Detection
- Compares current PCE active policy against Git repo contents
- Reports: "Git says X, PCE says Y" for each object
- Dashboard shows drift items with diff view

### 3. Provision (Git → PCE)
- Triggered by: merge to main, manual API call, or schedule
- Reads YAML files from Git
- Resolves labels to HREFs, services to HREFs
- Creates/updates rulesets on PCE draft
- Optionally auto-provisions draft → active

## Cross-Scope Rule Flow

This is the key workflow that makes multi-team governance work:

```
1. Team A (payments) creates a PR:
   - Adds: scopes/payments-prod/cross-scope/to-shareddb.yaml
   - Adds: scopes/shareddb-prod/inbound/from-payments.yaml (mirror)

2. GitHub CODEOWNERS triggers:
   - @org/payments-team → auto-approved (their own scope)
   - @org/database-team → MUST review (touches their inbound dir)
   - @org/security-team → MUST review (cross-scope policy)

3. Team B reviews the rule:
   - Sees: "payments-processing wants 5432/tcp to shareddb-db"
   - Approves or requests changes via PR review

4. Security team reviews:
   - Validates the rule follows least-privilege
   - Approves or rejects

5. All required reviews pass → PR merges

6. GitHub Actions workflow runs:
   - Reads the YAML files
   - Creates the extra-scope ruleset on PCE
   - Provisions to active
   - Comments on PR with provisioning result

7. Full audit trail in Git:
   - Who requested (PR author)
   - Who reviewed (PR reviewers)
   - When approved (merge timestamp)
   - What changed (Git diff)
```

## Source of Truth Decision

**Recommended: Git as source of truth (with PCE import)**

- Git repo is the canonical state of policy
- PCE is the enforcement engine
- Changes in PCE GUI are detected as "drift" and flagged
- Teams are trained to make changes via PR, not GUI
- Exception: emergency changes can be made in PCE and reconciled later

**Alternative: PCE as source of truth (export only)**

- PCE is canonical, Git is the audit/backup copy
- Export runs on schedule, creating commits for each change
- No provisioning from Git → PCE
- Simpler but loses the multi-team approval benefit

## Plugin Components

### 1. Git Client
- Clone/pull/push to Git repo (GitHub, GitLab, Bitbucket)
- Auth via SSH key or personal access token
- Create branches, commits, PRs programmatically

### 2. Policy Serializer
- PCE objects → YAML (export direction)
- YAML → PCE API calls (provision direction)
- Label resolution: YAML uses `{role: web}`, maps to PCE label HREFs
- Service resolution: YAML uses `{port: 5432, proto: tcp}`, maps to PCE service HREFs

### 3. Scope Mapper
- Maps Illumio RBAC scopes to directory structure
- Reads ruleset scopes and determines which directory a ruleset belongs to
- Handles unscoped (global) rulesets → `_global/` directory

### 4. Drift Detector
- Compares Git YAML state against PCE active state
- Reports additions, modifications, deletions
- Ignores metadata fields (created_at, updated_at, hrefs)

### 5. Dashboard
- Export/import status
- Drift report with diff view
- Cross-scope request status
- Provisioning history

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GIT_REPO_URL` | _(required)_ | Git repository URL (SSH or HTTPS) |
| `GIT_BRANCH` | `main` | Target branch |
| `GIT_TOKEN` | _(required)_ | Personal access token or SSH key path |
| `GIT_PROVIDER` | `github` | `github`, `gitlab`, or `bitbucket` |
| `SYNC_MODE` | `export` | `export` (PCE→Git), `provision` (Git→PCE), `bidirectional` |
| `SCAN_INTERVAL` | `3600` | Seconds between sync cycles |
| `AUTO_PROVISION` | `false` | Auto-provision draft→active after Git→PCE sync |
| `DRIFT_ALERT` | `true` | Alert on drift between Git and PCE |

## Dependencies

- `illumio` — PCE SDK
- `requests` — HTTP client
- `pyyaml` — YAML serialization
- `gitpython` — Git operations (or shell out to `git`)

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Bidirectional sync loops | Commits by the plugin use a bot account; ignore bot commits on import |
| Emergency changes bypassing Git | Drift detector flags them; reconcile manually or auto-create PR |
| Label HREFs changing between PCEs | YAML uses label key:value, not HREFs; resolve at provision time |
| Large policy export | Paginate PCE API calls; only export changed objects |
| Git conflicts on concurrent PRs | Each scope is a separate directory; conflicts are rare |
| CODEOWNERS not enforced | Document that branch protection rules must be enabled |

## Future Enhancements

- GitLab MR support (CODEOWNERS equivalent: `CODEOWNERS` file works in GitLab too)
- Bitbucket support (uses `CODEOWNERS` in `.github/` or Bitbucket's own reviewer rules)
- Policy validation CI: lint YAML, check for common mistakes (any-to-any, broad ranges)
- Visual diff in PR comments: rendered table of rule changes
- Slack notification when a cross-scope PR needs review
