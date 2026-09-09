# traffic-reporter

Interactive dashboard for Illumio PCE traffic flows — top talkers, top
services, policy-decision breakdown, and a table of blocked/potentially
blocked connections, with a built-in **squelch (mute) rule** engine to hide
known-noisy flows.

- [What it does](#what-it-does)
- [Why it matters](#why-it-matters)
- [Prerequisites & setup](#prerequisites--setup)
- [Configuration](#configuration)
- [Squelch rule format](#squelch-rule-format)
- [How it works](#how-it-works)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Notes / limitations](#notes--limitations)

## What it does

On a schedule, `traffic-reporter`:

1. Queries the PCE **Explorer** (traffic flow) API for the last `LOOKBACK_HOURS`
   of flows, across all policy decisions (`allowed`, `blocked`,
   `potentially_blocked`, `unknown`).
2. Aggregates flows into:
   - **Top sources** and **top destinations** (by hostname, falling back to IP)
   - **Top services** (`port/proto`)
   - **Policy decision counts** (allowed vs. blocked vs. potentially blocked vs. unknown)
   - A **blocked / potentially blocked flow table** (top 50 by connection count)
   - **Sankey link data** (`source → service → destination`, grouped by the
     workload's `app|env` labels where available, falling back to hostname)
3. Applies any configured **squelch rules** to drop noisy/expected flows (e.g.
   DNS, health checks, a known monitoring subnet) from the aggregates *before*
   they're counted, so top-talker charts and the blocked table aren't drowned
   out by expected traffic.
4. Serves everything on a self-refreshing (30s) Chart.js dashboard, plus a
   JSON API for programmatic use.

## Why it matters

Explorer's native traffic view is powerful but not built for "what's my
top-line traffic story right now" at a glance, and it has no concept of
squelching known noise. `traffic-reporter` gives you a always-on summary
dashboard — useful during enforcement-mode migrations (spotting new blocked
flows as you tighten policy), for a daily/weekly traffic sanity check, or as
a lightweight NOC-style screen — without needing to build Explorer queries by
hand each time.

## Prerequisites & setup

- A running Illumio PCE reachable from the plugin container, with API
  credentials that can read traffic flows (Explorer permission).
- `plugger install traffic-reporter` — PCE credentials (`PCE_HOST`,
  `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`, `PCE_API_SECRET`) are injected
  automatically by plugger; no manual credential configuration is required.
- Nothing else is required to get a working dashboard — all config below has
  a default.

## Configuration

All variables are optional; defaults are applied by plugger if unset.

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `3600` | Seconds between traffic polls |
| `LOOKBACK_HOURS` | `24` | Hours of traffic history to query per poll |
| `MAX_RESULTS` | `10000` | Maximum number of flows to retrieve per query |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification when talking to the PCE |
| `SQUELCH_RULES` | _(none)_ | JSON array of squelch rules applied to every poll (see below) |

`SQUELCH_RULES` is not declared in `plugin.yaml`/`metadata.yaml` as a
dashboard-configurable field — set it as a plain environment variable on the
container if you want squelch rules preloaded at startup. Rules can also be
added/edited entirely at runtime from the dashboard (see [Usage](#usage))
without restarting the plugin, but rules added at runtime are **not
persisted** — a container restart resets to whatever `SQUELCH_RULES` defines
(or empty).

PCE connection variables (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`,
`PCE_API_SECRET`) are injected by plugger and are not set manually.

## Squelch rule format

A squelch rule hides matching flows from every chart, count, and the blocked
table — squelched flows are still fetched from the PCE but excluded before
aggregation. Each rule is a JSON object with a `type` field and type-specific
fields, plus an optional `label` for display:

| `type` | Fields | Matches when |
|--------|--------|--------------|
| `service` | `port` (int), `proto` (`tcp`/`udp`, optional — omit/empty to match any proto) | Flow's service port equals `port` (and proto matches, if given) |
| `ip` | `pattern` (string) | Flow's resolved src/dst name **or** raw src/dst IP equals `pattern` (exact match, not a wildcard) |
| `subnet` | `cidr` (string, e.g. `10.0.0.0/8`) | Src or dst IP falls inside the CIDR |
| `hostname` | `pattern` (regex string, case-insensitive) | Regex matches the resolved src or dst hostname |
| `decision` | `value` (`allowed`/`blocked`/`potentially_blocked`/`unknown`) | Flow's policy decision equals `value` exactly |

Example `SQUELCH_RULES` value (DNS noise, a monitoring subnet, and hiding all
`allowed` traffic):

```json
[
  {"type": "service", "port": 53, "proto": "udp", "label": "DNS"},
  {"type": "subnet", "cidr": "10.50.0.0/16", "label": "Monitoring subnet"},
  {"type": "decision", "value": "allowed", "label": "Hide allowed"}
]
```

Rules loaded via `SQUELCH_RULES` are enabled by default. A malformed
`SQUELCH_RULES` value (bad JSON, invalid CIDR/regex) logs a warning at
startup and is skipped in its entirety — the plugin still starts with zero
squelch rules rather than failing.

## How it works

- Runs as a **daemon** with an internal poll loop (`POLL_INTERVAL`), not a
  cron job — the dashboard always reflects the most recent completed poll.
- Uses the `illumio` Python SDK's `TrafficQuery` + `get_traffic_flows_async`
  against the PCE's async traffic query API, requesting all four policy
  decisions in one query.
- Per flow, resolves source/destination names from the workload hostname
  (falling back to raw IP), and derives the service as `port/proto`.
- For Sankey grouping, resolves each endpoint's `app`/`env` labels via label
  HREF lookups (`app|env`, or whichever of the two is present) — this groups
  the Sankey diagram by application/environment rather than by every
  individual host.
- Squelch rules are evaluated per-flow before any counter is incremented;
  squelched flows are counted and reported (`squelched`, `visible_flows`) but
  excluded from all other aggregates.
- State from the last poll (all charts' data, the blocked table, and the
  current squelch rule list) is held in memory and served to the dashboard
  and `/api/traffic`; nothing is persisted to disk, so a container restart
  clears history back to the next poll.
- `num_connections` is used as the aggregation weight for all counters (not
  raw flow count), so charts reflect actual connection volume.

## Usage

### Dashboard

Open the plugin's UI port (proxied through the plugger dashboard) to see:

- Stat tiles: total flows, allowed, blocked, block rate %, and (if any flows
  are squelched) a squelched-count tile
- Policy Decisions doughnut chart
- Top Services, Top Sources, Top Destinations bar charts
- Blocked / Potentially Blocked Flows table (source, destination, service,
  decision, connection count)
- Squelch Rules panel — view active/inactive rules, add a new rule via a form
  (service/IP/subnet/hostname/decision), toggle a rule on/off, or remove it

The dashboard auto-refreshes every 30 seconds by polling `/api/traffic`.

### API endpoints

| Method | Path | Description |
|--------|------|--------------|
| GET | `/` | Interactive dashboard (HTML) |
| GET | `/healthz` | Health check |
| GET | `/api/traffic` | Full last-poll analysis as JSON (stats, top talkers, blocked flows, sankey links, squelch rules) |
| GET | `/api/squelch` | Current squelch rules + squelched flow count |
| POST | `/api/squelch/add` | Add a squelch rule. Body: `{"type": ..., "label": ..., ...type-specific fields}` (see [Squelch rule format](#squelch-rule-format)). Returns `400` if `type` is missing or a `subnet`/`hostname` rule has an invalid CIDR/regex |
| POST | `/api/squelch/toggle` | Toggle a rule's enabled state. Body: `{"index": <int>}` — index into the current rule list. Returns `400` for an out-of-range index |
| POST | `/api/squelch/remove` | Remove a rule. Body: `{"index": <int>}`. Returns `400` for an out-of-range index |

Squelch rule changes made through the API take effect on the **next poll**
(they don't retroactively re-filter the current in-memory result set), and
are not persisted across a plugin restart.

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Dashboard shows 0 flows | No traffic in the `LOOKBACK_HOURS` window, or the API credential lacks Explorer/traffic read permission on the PCE |
| `total_flows` high but charts look sparse | Check `squelched` / `visible_flows` in `/api/traffic` — a broad squelch rule (e.g. a wide subnet or `decision: allowed`) may be hiding most traffic |
| A squelch rule doesn't seem to apply | `service` rules match on exact port + optional proto; `ip`/`hostname` rules require the flow's *resolved* name (hostname if known, else IP) to match — check `/api/traffic`'s `top_sources`/`top_destinations` for the exact string being matched against |
| `Failed to parse SQUELCH_RULES` in logs | The `SQUELCH_RULES` env var isn't valid JSON, or a `subnet` rule has an invalid CIDR / a `hostname` rule has an invalid regex — the whole list is dropped in that case, not just the bad rule |
| Poll takes a long time / times out on large environments | Lower `MAX_RESULTS` or `LOOKBACK_HOURS`, or increase `POLL_INTERVAL` so polls don't overlap |
| Sankey grouping shows raw hostnames instead of `app|env` | Workload has no `app`/`env` labels assigned, or the label HREF couldn't be resolved — grouping falls back to hostname/IP in that case |

## Notes / limitations

- Squelch rules configured via the dashboard/API are **in-memory only** —
  they do not persist across restarts. For durable rules, set `SQUELCH_RULES`
  as an environment variable.
- `ip` and `hostname` squelch rules match a single pattern/regex per rule —
  there's no bulk/list syntax; add multiple rules for multiple patterns.
- All analysis is scoped to a single rolling window (`LOOKBACK_HOURS`) per
  poll — there's no historical trend view across polls.
- Traffic queries run synchronously inside the poll loop; a very large
  environment with a long `LOOKBACK_HOURS` and high `MAX_RESULTS` will make
  each poll take longer, delaying the next refresh.
- Label resolution for Sankey grouping only considers `app` and `env` — other
  label dimensions (role, loc, custom dimensions) aren't used for grouping.
