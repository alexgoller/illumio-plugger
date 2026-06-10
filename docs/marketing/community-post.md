# Illumio Community Post

**Title: Plugger — an open-source plugin framework for PCE (20 plugins, from AI posture scoring to workload quarantine)**

---

One pattern I keep seeing with Illumio customers: the platform does segmentation well, but there's always a list of adjacent things the team needs. Export policy as firewall rules the network team understands. Auto-quarantine a workload when EDR fires. Get a posture score the CISO can look at without a 90-minute deep dive. Sync CMDB attributes to labels so the labeling actually stays current.

Building each of these as a one-off script works, but it doesn't scale — credentials everywhere, no restart logic, nothing to observe, nothing to upgrade.

I've been working on Plugger to solve this. It's an open-source Go CLI that manages PCE extensions as Docker containers. The framework handles the boilerplate — install, scheduling, credential injection, health checks, auto-restart, log streaming, and a unified web dashboard. You write the plugin logic; Plugger keeps it running.

---

## How it works

```bash
plugger install ai-security-report
plugger run
# Dashboard at http://localhost:8800
```

Each plugin has a `plugin.yaml` manifest that declares its scheduling mode, environment variables, and health endpoint. Three modes:

- **Daemon** — runs continuously, auto-restarts on crash with exponential backoff
- **Cron** — runs on a schedule (nightly reports, hourly syncs)
- **Event** — ephemeral container triggered by webhook (incident response, PCE alerts)

Plugins can be installed from the registry, a local file, a URL, or a container image directly. The web dashboard consolidates all plugin UIs under a single port with a reverse proxy that rewrites paths and JavaScript references automatically.

---

## Key plugins with practical use cases

**AI Security Report**

Connects to your PCE, pulls workload and traffic data, and scores your posture across 10 security categories. Findings map to NIST CSF and PCI-DSS controls. Output is an HTML report with a heatmap by environment and a prioritized remediation roadmap. Run it before a QBR, before an audit, or just to get a fast baseline when you onboard a new environment.

```bash
plugger install ai-security-report && plugger run
# Navigate to http://localhost:8800/ai-security-report
```

**Policy Resolver**

Illumio's label-based policy is powerful, but sometimes you need to hand a network engineer a list of IP-level rules they can paste into a Palo Alto or Cisco ACL. Policy Resolver resolves your active rulesets into concrete allow/deny rules, exports them as JSON, and serves a searchable dashboard. Useful for firewall migration projects and compliance audits where you need to show exactly what traffic is permitted.

**Workload Isolator**

Exposes a webhook endpoint. When your EDR (CrowdStrike, SentinelOne) or SOAR (Splunk, Palo Alto XSOAR) detects a compromise, it POSTs the hostname. Plugger flips the workload into selective enforcement, cutting lateral movement before an analyst has finished reading the alert. Optional TTL auto-releases the workload after a configured time so you don't need a manual cleanup step after investigation.

```
POST /isolate
{"hostname": "web-prod-07", "reason": "crowdstrike-detection", "ttl": 3600}
```

**App Dependency Intelligence**

Analyzes PCE traffic flow data to build an application dependency graph. For any application, you can see: what services it depends on, what depends on it, blast radius if it goes down, potential single points of failure, and whether any dependencies cross compliance boundaries. The visualization is interactive D3.js — you can explore the dependency graph directly in the browser. Useful before a change freeze, a DR exercise, or a compliance scoping conversation.

**VEN Fleet Manager**

Gives you a fleet-level view of your VEN estate: which agents are offline, which are past the compatibility check for a new PCE version, which are still in idle mode but could safely progress to visibility, version distribution across your fleet, and upgrade readiness by site or environment. If you're managing hundreds or thousands of VENs, this replaces a lot of ad hoc PCE API queries.

**Policy GitOps**

Policy-as-code for Illumio. Rulesets, IP lists, services, and label groups are exported as YAML files in a Git repository. Changes go through pull requests — with optional security checks and traffic evidence gates that verify a proposed rule change is backed by observed traffic before it provisions. Drift detection flags when the PCE state diverges from the Git state. This one lives in a [standalone repo](https://github.com/alexgoller/illumio-policy-gitops) because it has its own release cycle, but it installs as a Plugger plugin.

---

## The full plugin list

20 plugins across monitoring, AI analysis, policy management, integrations, and operations:

- Monitoring: pce-health-monitor, traffic-reporter, policy-diff, pce-events
- AI & Analysis: ai-security-report, ai-assisted-rules, pce-posture-report, app-dependency-intel
- Policy: policy-resolver, rule-scheduler, workload-isolator, policy-gitops, policy-workflow
- Integrations: palo-alto-dag-sync, ztna-sync (Zscaler/Netskope/Cloudflare/Cisco), infoblox-ipam-sync, remedy-cmdb-sync, ad-label-sync
- Operations: ven-fleet-manager, stale-workloads

---

## Building your own

Scaffold a new plugin with a working template:

```bash
plugger create -t python my-plugin   # Python (most existing plugins use this)
plugger create -t go my-plugin       # Go with Illumio SDK
plugger create -t shell my-plugin    # Shell script
```

The template wires up credential injection, a health endpoint, and a Dockerfile. Publish it to a `registry.json` at any URL and teams can install it with `plugger install my-plugin`.

---

## Links

- GitHub: https://github.com/alexgoller/illumio-plugger
- Plugin portal: https://alexgoller.github.io/illumio-plugger/
- Policy GitOps (standalone): https://github.com/alexgoller/illumio-policy-gitops

This is a community project — not an official Illumio product. I build what I see customers needing in the field, but I'd rather build what you actually need.

**What plugins would you want to see?** Anything you're currently scripting around, missing from the platform, or solving with a fragile one-off integration — I'm genuinely interested.
