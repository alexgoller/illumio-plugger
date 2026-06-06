# Compliance Evidence Generator

**Status:** Proposed
**Priority:** High — every auditor asks for this
**Complexity:** Medium
**Dependencies:** PCE policy/workloads API, static compliance mappings

## Problem

PCI-DSS 4.0 now mandates segmentation validation every 6 months with documented evidence (Requirement 11.4.5). SOC2, HIPAA, and NIST 800-207 require continuous proof of network segmentation controls. Auditors want formatted evidence packages — not raw API output or PCE screenshots. FireMon offers this but costs $100K+/year.

## Solution

A plugin that generates audit-ready compliance evidence packages per framework, with timestamped policy snapshots, boundary maps, and who-can-talk-to-what matrices.

## Supported Frameworks

### PCI-DSS 4.0
| Requirement | What We Evidence |
|-------------|-----------------|
| 1.2.1 | Network security controls configured (rulesets + enforcement) |
| 1.2.5 | All services, protocols, ports identified (policy resolver output) |
| 1.2.6 | Security features defined for insecure services (risky service analysis) |
| 1.3.1 | Inbound traffic restricted to CDE (scope boundary evidence) |
| 1.3.2 | Outbound traffic restricted from CDE (scope boundary evidence) |
| 1.4.5 | Segmentation controls between CDE and non-CDE (enforcement boundaries) |
| 11.4.5 | Segmentation penetration testing / validation (traffic analysis) |

### SOC2 (Trust Services Criteria)
| Criteria | What We Evidence |
|----------|-----------------|
| CC6.1 | Logical access controls (enforcement mode distribution) |
| CC6.6 | Network segmentation (ruleset coverage) |
| CC7.1 | Monitoring for unauthorized changes (policy-diff data) |
| CC7.2 | Monitoring for anomalies (traffic anomaly data) |

### HIPAA (Security Rule)
| Standard | What We Evidence |
|----------|-----------------|
| 164.312(a)(1) | Access control (enforcement + policy) |
| 164.312(e)(1) | Transmission security (encrypted vs unencrypted protocols) |
| 164.312(c)(1) | Integrity controls (policy change audit) |

### NIST 800-207 (Zero Trust)
| Control | What We Evidence |
|---------|-----------------|
| ZTA Principle 1 | All resources secured (enforcement coverage) |
| ZTA Principle 4 | Access determined by policy (ruleset analysis) |
| ZTA Principle 7 | Monitor and measure (traffic + posture data) |

### DORA (EU Digital Operational Resilience Act)
| Article | What We Evidence |
|---------|-----------------|
| Art. 9 | Network segmentation controls |
| Art. 10 | ICT risk detection and monitoring |

## Evidence Package Structure

```
compliance-report-pci-dss-2026-05-29/
├── index.html                    # Navigation page
├── summary.pdf                   # Executive summary
├── evidence/
│   ├── 01-enforcement-coverage.html    # Req 1.2.1
│   ├── 02-policy-inventory.html        # Req 1.2.5
│   ├── 03-cde-boundary.html            # Req 1.3.1, 1.4.5
│   ├── 04-traffic-validation.html      # Req 11.4.5
│   ├── 05-risky-services.html          # Req 1.2.6
│   └── 06-change-audit.html           # Supporting evidence
├── raw-data/
│   ├── workloads.json
│   ├── rulesets.json
│   ├── traffic-flows.json
│   └── policy-diff.json
└── metadata.json                 # Report timestamp, PCE version, scope
```

## How It Works

1. **Collect data** from PCE and other plugins:
   - Workloads with enforcement modes (PCE API)
   - Active rulesets and rules (PCE API)
   - Traffic flows — allowed and blocked (PCE API)
   - Policy changes since last report (policy-diff plugin data)
   - Security posture score (ai-security-report plugin data)
   - Policy resolver output (resolved IP-level rules)

2. **Map to framework controls** using static mapping tables

3. **Generate evidence** pages with:
   - Control description
   - Evidence collected (data + analysis)
   - Status: Met / Partially Met / Not Met
   - Remediation guidance for unmet controls

4. **Package** as HTML report (self-contained, no external dependencies)

5. **Store** with timestamp for historical comparison

## Dashboard

- **Framework selector** — PCI-DSS, SOC2, HIPAA, NIST, DORA
- **Control status overview** — met/partial/not-met counts with chart
- **Per-control detail** — click to see evidence
- **Generate report** button — creates the evidence package
- **Historical reports** — list of past reports with comparison
- **Schedule** — configurable auto-generation (monthly, quarterly)

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `FRAMEWORKS` | `pci-dss` | Comma-separated frameworks to report on |
| `CDE_LABELS` | _(empty)_ | JSON: labels defining CDE scope (for PCI) |
| `REPORT_INTERVAL` | `0` | Auto-generate interval seconds (0 = manual only) |
| `REPORT_RETENTION` | `12` | Number of reports to keep |
| `INCLUDE_RAW_DATA` | `true` | Include raw JSON data in package |

## Why This Matters

- **Every auditor asks for this** — segmentation evidence is mandatory
- **PCI-DSS 4.0 specifically requires it** — Req 11.4.5, every 6 months
- **Replaces $100K+ tools** — FireMon, Tufin charge enterprise prices
- **Automated, repeatable** — generate on demand or on schedule
- **Multi-framework** — one plugin covers PCI, SOC2, HIPAA, NIST, DORA
- **Builds on existing plugins** — uses data from ai-security-report, policy-resolver, policy-diff
