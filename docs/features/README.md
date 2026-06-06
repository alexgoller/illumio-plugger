# Feature Proposals

Design documents for proposed plugins and capabilities. Each doc captures the problem, solution, architecture, configuration, and rationale.

## Proposed Plugins

| Plugin | Priority | Complexity | Status |
|--------|----------|-----------|--------|
| [App Dependency Map](app-dependency-map.md) | High | Medium-High | Proposed |
| [Workload Isolator](workload-isolator.md) | High | Low | Proposed |
| [Threat Feed Sync](threat-feed-sync.md) | High | Medium | Proposed |
| [VEN Fleet Manager](ven-fleet-manager.md) | High | Medium | Proposed |
| [Compliance Evidence Generator](compliance-reporter.md) | High | Medium | Proposed |
| [Label Lifecycle Manager](label-lifecycle.md) | High | Medium | Proposed |
| [Segmentation Drift Detector](segmentation-drift.md) | Medium-High | Low-Medium | Proposed |

## Build Priority

Recommended order based on impact vs effort:

1. **Workload Isolator** — half-day build, immediate security value
2. **App Dependency Map** — biggest demo wow-factor
3. **Threat Feed Sync** — every SOC wants this
4. **VEN Fleet Manager** — biggest operational pain at scale
5. **Compliance Evidence Generator** — auditor-ready, replaces $100K tools
6. **Label Lifecycle Manager** — #1 adoption blocker
7. **Segmentation Drift Detector** — PCI-DSS continuous validation

## Existing Plugins (17)

| Plugin | Status | Description |
|--------|--------|-------------|
| pce-health-monitor | Tested | Real-time PCE health dashboard |
| traffic-reporter | Tested | Traffic flow analysis with Sankey diagrams |
| policy-diff | Tested | Draft vs active policy change tracker |
| pce-posture-report | Tested | Scheduled security posture scoring |
| pce-events | Tested | Real-time event monitoring (15+ outputs) |
| ai-assisted-rules | Tested | Policy advisor with AI analysis |
| ai-security-report | Tested | 10-category security posture analysis |
| stale-workloads | Tested | Offline/stale workload detection |
| rule-scheduler | Tested | Time-based rule scheduling |
| policy-resolver | Tested | Label policy → IP firewall rules |
| ztna-sync | Untested | Sync to Zscaler/Netskope/Cloudflare/Cisco |
| infoblox-ipam-sync | Untested | Bi-directional Infoblox IPAM sync |
| palo-alto-dag-sync | Untested | Palo Alto Dynamic Address Group sync |
| ad-label-sync | Untested | Active Directory label mapping |
| remedy-cmdb-sync | Untested | BMC Remedy CMDB sync |
| policy-gitops | External | Policy-as-code with Git workflows |
| policy-workflow | External | Approval workflow for policy changes |
