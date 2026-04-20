# Policy Resolver

Resolve Illumio label-based policy into concrete IP-level firewall rules. Takes abstract rulesets with label scopes and resolves every consumer/provider to actual workload IPs, producing a flat list of source IP / destination IP / port / protocol entries ready for firewall implementation.

## Install

```bash
plugger install policy-resolver
```

## Why

Illumio policy is written using labels (app, env, role). But when firewall teams need to implement these rules on path firewalls, they need IP addresses. This plugin bridges that gap:

- **Ruleset scoped to `app=payments, env=prod`** → resolves to the 12 IPs in that scope
- **Provider `role=db`** → resolves to `10.0.2.1, 10.0.2.2`
- **Consumer `role=web`** → resolves to `10.0.1.1, 10.0.1.2, 10.0.1.3`
- **Service `PostgreSQL`** → resolves to `5432/tcp`

Result: `10.0.1.1-3 → 10.0.2.1-2 : 5432/tcp permit`

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `600` | Seconds between resolution runs |
| `RESOLVE_DRAFT` | `false` | Resolve draft policy instead of active |

## What It Resolves

For each enabled rule in each enabled ruleset:

| Component | Resolution |
|-----------|-----------|
| **Ruleset scope** | Label constraints → matching workloads |
| **Providers** (labels) | Label + scope → workload IPs |
| **Providers** (IP lists) | IP list → CIDRs/ranges/FQDNs |
| **Providers** ("all workloads") | All workloads in scope → IPs |
| **Consumers** (labels) | Label + scope → workload IPs |
| **Consumers** (IP lists) | IP list → CIDRs/ranges/FQDNs |
| **Consumers** (unscoped) | Label without scope constraint → all matching IPs |
| **Services** (references) | Service definition → port/proto pairs |
| **Services** (inline) | Direct port/proto |

## Dashboard

Three views:

- **Firewall Rules** — flat table: `# | Ruleset | Source Label | Source IPs | Dest Label | Dest IPs | Service | Action`. Click any row to expand all IPs. Searchable, copyable as TSV for Excel/Sheets.
- **By Ruleset** — grouped view showing consumer/provider resolution per ruleset with IP counts
- **JSON Export** — full JSON output with copy button, ready for firewall automation

## Export Formats

### JSON (primary)

```json
{
  "firewall_rules": [
    {
      "id": 1,
      "ruleset": "Web to DB",
      "source_label": "role=web",
      "source_ips": ["10.0.1.1", "10.0.1.2"],
      "destination_label": "role=db",
      "destination_ips": ["10.0.2.1"],
      "port": 5432,
      "protocol": "tcp",
      "service_name": "PostgreSQL",
      "action": "permit"
    }
  ]
}
```

### TSV (copy table)

Tab-separated values for paste into Excel, Google Sheets, or firewall management tools.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/resolved` | Full resolved state |
| POST | `/api/resolve` | Trigger immediate resolution |
| GET | `/api/config` | Configuration |

## Features

- Resolves label-based policy to IP-level firewall rules
- Handles all actor types: labels, IP lists, "all workloads", specific workloads
- Handles scoped and unscoped consumers (extra-scope rules)
- Service reference resolution (named services → port/proto)
- Port range support
- JSON export with download button
- TSV copy for spreadsheet paste
- Searchable firewall rule table
- Expandable rows showing all source/destination IPs
- Resolves active or draft policy (configurable)
- Periodic auto-refresh
