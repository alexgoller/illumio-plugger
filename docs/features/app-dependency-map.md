# App Dependency Map

**Status:** Proposed
**Priority:** High — strongest demo piece in the portfolio
**Complexity:** Medium-High
**Dependencies:** PCE traffic flows API

## Problem

Illumio Illumination shows raw traffic flows but doesn't automatically identify application architectures or visualize app-to-app dependencies as a graph. Customers need to understand their application topology before they can write meaningful segmentation policy. Tools like Faddom and ServiceNow Discovery cost $20K+/year.

## Solution

A plugin that analyzes PCE traffic flow data and renders an interactive force-directed graph showing:
- **App-to-app** communication (which applications talk to which)
- **Role-to-role** tiers within each app (web → app → db)
- **Infrastructure dependencies** (DNS, NTP, LDAP, monitoring hubs)
- **Cross-environment flows** (prod talking to dev)

## How It Works

1. Query PCE for allowed traffic flows (configurable lookback)
2. Group flows by app|env labels on source and destination
3. Aggregate by service (port/proto)
4. Build a graph: nodes = app|env groups, edges = traffic flows with service labels
5. Detect infrastructure hubs (fan-out/fan-in > threshold)
6. Render with D3.js force-directed layout

## Visualization

### Main View: App-to-App Graph
```
    [DNS]───────────────┐
      │                 │
 [Payments]──────[SharedDB]──────[Ordering]
      │                 │            │
 [Monitoring]──────────┘       [Frontend]
```

Each node:
- Circle sized by workload count
- Colored by environment (prod=blue, dev=green, staging=yellow)
- Click to expand role-level view

Each edge:
- Thickness by connection volume
- Color by type (intra-env=blue, cross-env=orange, to-infra=gray)
- Hover shows services (ports)

### Expanded View: Role Tiers
```
Payments (prod)
┌─────────────────────────────┐
│  [web] ──443──▶ [processing]│
│                     │       │
│                   5432      │
│                     ▼       │
│                   [db]      │
└─────────────────────────────┘
```

### Infrastructure Hub Detection
Workloads talking to 4+ different app groups are auto-classified as infrastructure:
- DNS, NTP, LDAP, monitoring, syslog, jump hosts
- Displayed as a separate layer or highlighted differently

## Dashboard Features

- **Graph view** — D3.js force-directed with zoom/pan/drag
- **Table view** — sortable list of all app-to-app pairs with services
- **Filters** — by environment, by app, by service port
- **Search** — find an app and highlight its connections
- **Export** — SVG/PNG download, JSON graph data
- **Stats** — total apps, total connections, cross-env count, infrastructure count
- **Time range** — configurable lookback (7d, 30d, 90d)

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOOKBACK_DAYS` | `30` | Days of traffic to analyze |
| `MAX_FLOWS` | `100000` | Max flows to query |
| `HUB_THRESHOLD` | `4` | Min app connections to flag as infrastructure |
| `GROUP_BY` | `app,env` | Label keys for grouping |
| `POLL_INTERVAL` | `3600` | Seconds between analysis runs |
| `INCLUDE_IP_TRAFFIC` | `false` | Include flows from unmanaged IPs |

## Tech Stack

- D3.js v7 for force-directed graph
- Chart.js for stats charts
- Standard Python HTTP server + Tailwind CSS dashboard
- No external dependencies beyond `illumio` SDK

## Why This Matters

- **Demo killer** — customers immediately understand their environment
- **Pre-policy discovery** — must understand dependencies before writing rules
- **Shadow IT detection** — unexpected app-to-app flows
- **Validates segmentation** — "are my apps actually isolated?"
- **Replaces expensive tools** — Faddom, ServiceNow Discovery, etc.
