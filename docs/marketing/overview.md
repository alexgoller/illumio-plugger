# Plugger — Plugin Framework for Illumio PCE

**Community project by Alex Goller, Illumio Solutions Architect**
GitHub: https://github.com/alexgoller/illumio-plugger | Portal: https://alexgoller.github.io/illumio-plugger/

---

## The Problem

Illumio PCE handles segmentation well. But every deployment generates a list of adjacent requirements: export policy as firewall rules, quarantine a compromised workload from an EDR alert, generate a posture score for auditors, keep CMDB attributes in sync with labels, analyze which applications break if a shared service goes down.

Building these as standalone scripts works once. It doesn't scale — credentials scattered across hosts, no restart logic, no observability, no upgrade path.

---

## The Solution

Plugger is an open-source Go CLI that manages PCE extensions as Docker containers. It handles the operational boilerplate so each plugin can focus on its function:

- Install plugins from a registry, a local file, a URL, or a container image
- Three scheduling modes: daemon (continuous), cron (periodic), event (webhook-triggered)
- Auto-restart with exponential backoff; HTTP health checks
- Unified web dashboard at `http://localhost:8800` — all plugin UIs proxied under one port
- PCE credentials injected at runtime; never baked into images
- Plugin scaffolding in Go, Python, Shell, or JavaScript

---

## How It Works

```
Step 1: Build
  git clone https://github.com/alexgoller/illumio-plugger && make build

Step 2: Initialize
  plugger init          # creates ~/.plugger/config.yaml with PCE connection

Step 3: Install and run
  plugger install ai-security-report
  plugger run           # starts all installed plugins; dashboard at :8800
```

---

## Plugin Reference (20 plugins)

### Monitoring & Visibility

| Plugin | Description | Mode |
|--------|-------------|------|
| pce-health-monitor | Real-time PCE health dashboard — endpoint checks, CPU/memory/disk | Daemon + UI |
| traffic-reporter | Interactive traffic flow analysis — top talkers, blocked flows, Sankey diagram | Daemon + UI |
| policy-diff | Git-like policy change tracker — field-level diffs, user attribution, audit trail | Daemon + UI |
| pce-events | PCE event fan-out — Slack, Teams, PagerDuty, Email, 15+ output adapters | Daemon + UI |
| ven-fleet-manager | VEN fleet visibility — enforcement progress, compatibility, version distribution | Daemon + UI |
| stale-workloads | Find offline, unresponsive, and traffic-silent workloads with optional cleanup | Daemon + UI |

### AI & Security Analysis

| Plugin | Description | Mode |
|--------|-------------|------|
| ai-security-report | AI posture scoring across 10 categories — NIST CSF/PCI-DSS mapping, heatmap, roadmap | Daemon + UI |
| ai-assisted-rules | Policy advisor — blocked traffic analysis, tiered rule generation, LLM recommendations | Daemon + UI |
| pce-posture-report | Enforcement/label/policy coverage scoring — HTML+JSON output | Cron |
| app-dependency-intel | Application dependency graph — blast radius, SPOF detection, resiliency scoring | Daemon + UI |

### Policy Management

| Plugin | Description | Mode |
|--------|-------------|------|
| policy-resolver | Resolve label-based policy to IP-level firewall rules — searchable dashboard, JSON export | Daemon + UI |
| rule-scheduler | Time-based rule scheduling — business hours, maintenance windows, weekend lockdowns | Daemon + UI |
| workload-isolator | Webhook-triggered workload quarantine — EDR/SOAR integration, TTL auto-release | Daemon + UI |
| policy-gitops | Policy-as-code — YAML sync to Git with drift detection and PR-based change control | Daemon + UI |
| policy-workflow | Approval workflow engine — multi-stage pipelines, Slack/ServiceNow integration | Daemon + UI |

### Integrations

| Plugin | Description | Mode |
|--------|-------------|------|
| palo-alto-dag-sync | Sync Illumio labels to Palo Alto Dynamic Address Groups via PAN-OS XML API | Daemon + UI |
| ztna-sync | Sync workloads to ZTNA apps — Zscaler ZPA, Netskope NPA, Cloudflare Access, Cisco | Daemon + UI |
| infoblox-ipam-sync | Bi-directional sync between Illumio labels and Infoblox extensible attributes | Daemon + UI |
| remedy-cmdb-sync | Sync BMC Helix/Remedy CMDB CIs to Illumio labels — analytics and sync modes | Daemon + UI |
| ad-label-sync | Discover AD computers via LDAP, map OU/group/location to Illumio labels | Daemon + UI |

---

## Selected Use Cases

**Incident Response Automation**
CrowdStrike detects a compromise. SOAR calls the Workload Isolator webhook. Illumio flips the workload into selective enforcement. Lateral movement is blocked in seconds, before the analyst finishes reading the alert.

**Audit Readiness**
Run ai-security-report for a scored posture summary mapped to NIST CSF and PCI-DSS controls. Run policy-resolver to produce concrete IP-level firewall rules from your label-based policy. Export both before an audit engagement.

**Change Impact Analysis**
Before a maintenance window or infrastructure change, run app-dependency-intel to see which applications depend on the target service, what the blast radius looks like, and whether any compliance boundaries are crossed.

**Multi-Team Policy Governance**
Use policy-gitops to store rulesets as YAML in Git. Changes go through pull requests with traffic evidence gates — a rule only provisions if observed traffic supports it. Security team reviews, network team reviews, audit trail is automatic.

**VEN Fleet Operations**
Use ven-fleet-manager to see which VENs are candidates for enforcement progression, which are on outdated versions, and which have compatibility issues before a PCE upgrade. Replaces ad hoc API queries with a persistent fleet dashboard.

---

## Building Custom Plugins

```bash
plugger create -t python my-plugin   # scaffold a Python plugin
plugger create -t go my-plugin       # scaffold a Go plugin with Illumio SDK
```

Plugins are standard Docker containers with a `plugin.yaml` manifest. Publish to any registry.json URL — teams install with `plugger install <name>`.

---

## Links

| Resource | URL |
|----------|-----|
| GitHub | https://github.com/alexgoller/illumio-plugger |
| Plugin Portal | https://alexgoller.github.io/illumio-plugger/ |
| Policy GitOps | https://github.com/alexgoller/illumio-policy-gitops |
| Documentation | https://github.com/alexgoller/illumio-plugger/tree/main/docs |

---

*Plugger is an open-source community project. Not an official Illumio product.*
*MIT License — contributions welcome.*
