# stale-workloads

Find Illumio workloads that are offline, silent (no VEN heartbeat), or
generating no traffic — grouped by `app|env`, scored by severity, with
optional one-click unpair/delete cleanup.

- [What it does](#what-it-does)
- [Why it matters](#why-it-matters)
- [Prerequisites & setup](#prerequisites--setup)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Notes / limitations](#notes--limitations)

## What it does

On a schedule, `stale-workloads`:

1. Fetches every workload from the PCE (`GET /workloads`, up to 10,000).
2. For each one, checks three independent signals: whether it's currently
   **online**, when its VEN last sent a **heartbeat** (managed workloads
   only), and — optionally — whether it has appeared in **any traffic flow**
   (as source or destination) within a lookback window.
3. Flags workloads that fail one or more of those checks, tags each with a
   **reason** (`offline`, `no heartbeat for Nd`, `no heartbeat data`,
   `no traffic`, `unmanaged`) and a **severity** (`info` / `warning` / `high`).
4. Groups the results by `app|env` label pair and by reason, and publishes a
   summary report (via the plugger reporting framework) when stale workloads
   are found.
5. Serves a dashboard with the full breakdown and, if explicitly enabled,
   buttons to **unpair** a managed workload's VEN or **delete** an unmanaged
   workload directly from the PCE.

Cleanup is off by default — the plugin is safe to run in discovery-only mode
indefinitely.

## Why it matters

PCE workload inventories accumulate cruft: decommissioned hosts whose VEN was
never cleanly removed, unmanaged workloads created for assets that no longer
exist, hosts that silently stopped heartbeating. These inflate workload
counts, clutter policy scoping, and can mask real connectivity problems
(a workload showing "no traffic" might mean the app died, or might mean a
segmentation rule is silently breaking it). Surfacing stale workloads by
app|env gives you a triage list instead of hunting through the PCE UI
workload-by-workload.

## Prerequisites & setup

- A running plugger instance with PCE credentials configured (injected
  automatically as `PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`,
  `PCE_API_SECRET`).
- The PCE API key needs read access to workloads and traffic flows, and —
  only if you turn on `ENABLE_CLEANUP` — write access to workloads
  (update and delete).

Install:

```bash
plugger install stale-workloads
```

No plugin-specific credentials are required — it uses the PCE connection
plugger already manages.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `3600` | Seconds between staleness checks |
| `STALE_DAYS` | `7` | Days without a VEN heartbeat before a managed workload is flagged `no heartbeat for Nd` |
| `OFFLINE_HOURS` | `24` | Hours a workload's `online` field must reflect offline before... *(see note below — currently informational, see [How it works](#how-it-works))* |
| `CHECK_TRAFFIC` | `true` | Also flag workloads with zero traffic flows in the lookback window |
| `TRAFFIC_LOOKBACK_HOURS` | `168` | Traffic lookback window in hours (default 7 days) |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification against the PCE |
| `ENABLE_CLEANUP` | `false` | Enable the unpair/delete actions on the dashboard and their API endpoints (disabled by default for safety) |

`POLL_INTERVAL`, `PCE_TLS_SKIP_VERIFY`, and PCE credentials follow the usual
plugger conventions; the rest are specific to this plugin.

## How it works

Each poll cycle evaluates every workload against these signals:

- **Offline** — the PCE's own `online` field on the workload. If `false`,
  the workload is flagged `offline` (severity `warning`).
- **Heartbeat age** (managed workloads only, i.e. those with an
  `agent.href`) — the VEN's `last_heartbeat_on` timestamp is compared
  against `now - STALE_DAYS`. Older than that: flagged
  `no heartbeat for Nd` (severity `high`, the highest severity the plugin
  assigns). If the workload is managed but has no heartbeat timestamp at
  all: flagged `no heartbeat data` (severity `warning`).
- **Traffic** (only when `CHECK_TRAFFIC=true`) — the plugin runs a PCE
  Explorer traffic query over the last `TRAFFIC_LOOKBACK_HOURS` hours
  (policy decisions `allowed`, `blocked`, `potentially_blocked`, `unknown`;
  up to 50,000 flows) and builds a set of every workload href seen as either
  source or destination. Any workload not in that set is flagged
  `no traffic` (severity raised to `warning` if it was still `info`).
- **Unmanaged** — any workload with no `agent.href` (no VEN) is
  unconditionally flagged `unmanaged`. This is added regardless of the
  workload's online/heartbeat/traffic status, so **every unmanaged workload
  in the PCE will appear in the stale list**, typically at `info` severity
  if it's otherwise online and trafficked. Treat `unmanaged` as an inventory
  label, not necessarily a problem.

A workload with none of the above reasons is not included in the results.
Severity is the highest triggered among `info` < `warning` < `high`, and the
final list is sorted by severity (high first) then hostname.

Note on `OFFLINE_HOURS`: the value is read, stored in the summary, and
surfaced on the dashboard footer, but the current offline check only reads
the workload's boolean `online` field — it does not independently measure
how long it has been offline. If this matters for your workflow, treat
`OFFLINE_HOURS` as informational until this is tightened up.

Also note: the dashboard's "By Reason" breakdown groups by the **first word**
of each reason string, so `no heartbeat for 5d`, `no heartbeat data`, and
`no traffic` all collapse into a single `no` bucket alongside the distinct
`offline` and `unmanaged` buckets. The full, specific reason text is still
shown per-workload in the table — only the summary chart is coarser than it
looks.

## Usage

### Dashboard

The dashboard (served at the plugin's root UI path) shows:
- Stat tiles: total workloads, stale count, offline, online, managed
- A doughnut chart of stale counts by reason bucket and a bar chart of the
  top 10 affected `app|env` pairs
- A searchable/filterable table of every stale workload with hostname, IP,
  `app|env`, severity, reasons, last-heartbeat age, and enforcement mode
- Per-row cleanup actions (see below), shown only when cleanup is enabled

It polls `/api/stale` every 30 seconds.

### API endpoints

| Method | Path | Description |
|--------|------|--------------|
| GET | `/api/stale` | Full current state as JSON: `stale_workloads`, `summary`, `by_app_env`, `by_reason`, `last_check`, `check_count`, and `cleanup_enabled` |
| POST | `/api/cleanup/unpair` | Body `{"href": "/orgs/1/workloads/<uuid>"}`. For a **managed** workload, updates it with `{"agent": {"config": {"mode": "idle"}}}` — this sets the VEN's policy mode to idle, it does not call the PCE's dedicated unpair action or remove the VEN pairing itself |
| POST | `/api/cleanup/delete` | Body `{"href": "/orgs/1/workloads/<uuid>"}`. Sends `DELETE` on the workload href, removing it from the PCE entirely |
| GET | `/healthz` | Health check |

Both cleanup endpoints return `403` with `{"error": "Cleanup disabled. Set ENABLE_CLEANUP=true."}` unless `ENABLE_CLEANUP=true`, and `400` if `href` is missing. The dashboard only shows the "Unpair" button for managed workloads and "Delete" for unmanaged ones, but the API itself does not enforce that pairing — calling `/api/cleanup/delete` on a managed workload's href will still delete it.

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|---------------------|
| No stale workloads ever reported, even though you know some are offline | Check `PCE_HOST`/credentials are valid and the API key can list `/workloads`; check plugin logs for `Failed to fetch workloads` |
| Every unmanaged workload shows up as stale | Expected — see [How it works](#how-it-works). Unmanaged workloads are always included, usually at `info` severity |
| "No traffic" flagged for workloads you know are active | Traffic check only looks at the Explorer flow history for `TRAFFIC_LOOKBACK_HOURS`; increase the window, or confirm the PCE's Explorer data retention covers that period. Check logs for `Traffic check failed` |
| Traffic check disabled entirely / slow polling | Set `CHECK_TRAFFIC=false` to skip the Explorer query if you only care about heartbeat/offline status |
| Cleanup buttons missing on the dashboard | `ENABLE_CLEANUP` is `false` (the default) — set it to `true` and restart the plugin |
| Cleanup API calls return 403 | Same as above — cleanup is gated by `ENABLE_CLEANUP` |
| "Unpair" doesn't remove the VEN from the PCE | By design in this version — it sets the workload's agent mode to `idle` rather than performing a true unpair. See [API endpoints](#api-endpoints) |

## Notes / limitations

- **Maturity: preview.** Functional end-to-end but not yet validated across a
  wide range of production PCE inventories.
- Cleanup actions (`unpair`, `delete`) are destructive against the PCE and
  disabled by default — enable `ENABLE_CLEANUP` deliberately and review
  workloads before clicking.
- "Unpair" is a mode change (`agent.config.mode: idle`), not a call to the
  PCE's unpair endpoint — the VEN and its pairing remain in the PCE.
- The offline check relies solely on the workload's `online` flag from the
  PCE; `OFFLINE_HOURS` does not currently gate an independent duration
  calculation.
- The dashboard's by-reason chart buckets by first word only and will merge
  distinct heartbeat/traffic reasons under `no` — use the per-workload table
  for the specific reason.
- Traffic checking queries up to 50,000 flows per cycle; very high-traffic
  PCEs with long lookback windows may see slower poll cycles or truncated
  flow sets.
- Workload deletion and unpair actions are irreversible from this plugin's
  perspective — there is no undo.
