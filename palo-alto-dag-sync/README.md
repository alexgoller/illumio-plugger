# palo-alto-dag-sync

Sync Illumio PCE workload labels into Palo Alto Networks **Dynamic Address
Groups (DAGs)** by registering IP-to-tag mappings via the PAN-OS User-ID
XML API — so PAN-OS/Panorama firewall policy stays current as Illumio
labels change, with no manual address-group maintenance.

> **Note on maturity**: this plugin ships as `production` in the registry,
> but the integration logic has not yet been validated end-to-end against
> a live PAN-OS firewall or Panorama instance. Run it in **dry-run mode**
> first (see below) and validate tag output before pointing it at a real
> firewall.

- [What it does](#what-it-does)
- [Why it matters](#why-it-matters)
- [Prerequisites & setup](#prerequisites--setup)
- [Configuration](#configuration)
- [How it works / data flow](#how-it-works--data-flow)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Notes & limitations](#notes--limitations)

## What it does

On a fixed interval (and on demand), `palo-alto-dag-sync`:

1. Fetches all **labels** from the PCE and caches them by HREF.
2. Fetches all **workloads** from the PCE (up to 10,000 per cycle) and
   keeps only the ones currently **online**.
3. Resolves each workload's labels and builds one or more **PAN-OS tags**
   from a configurable subset of label keys (`role`, `app`, `env`, `loc`
   by default) using a configurable naming template.
4. Collects every non-loopback, non-link-local IP address on each
   workload's interfaces and maps it to its tag(s).
5. Registers the IP-to-tag mappings on PAN-OS via the **User-ID XML API**
   (`type=user-id`), batched in chunks of 500 entries per request.
6. Exposes the result — workloads synced, IPs registered, unique tags,
   sync history, PAN-OS connection status — on a built-in dashboard.

DAGs configured on the firewall/Panorama to match these tags then
automatically include the tagged IPs as members, so firewall rules that
reference the DAG stay in sync with Illumio's label-based grouping
without any manual address-object editing.

## Why it matters

Illumio labels already express what a workload *is* (its role, app, env,
location). Palo Alto DAGs let a firewall rule reference "all workloads
tagged `illumio-env-prod`" instead of a static IP list. This plugin
closes the loop: as workloads are labeled, relabeled, or come online in
Illumio, the corresponding PAN-OS tags update automatically, so
perimeter/segmentation policy on the Palo Alto side tracks Illumio's
label-based inventory instead of drifting out of date.

## Prerequisites & setup

### PAN-OS side

1. **Generate a PAN-OS API key** (once, from an account with User-ID and
   XML API access):
   ```
   curl -k "https://<firewall-or-panorama>/api/?type=keygen&user=<user>&password=<password>"
   ```
   The response contains a `<key>...</key>` element — that string is
   `PALO_API_KEY`.
2. **Permissions**: the account used to generate the key needs access to
   the **User-ID XML API** (`type=user-id`, used to register/unregister
   IP-to-tag mappings) and to the `op` command `<show><system><info>`
   (used for the plugin's health check). On Panorama, the key must be
   valid for whichever firewall(s)/vsys the DAGs live on.
3. **Create Dynamic Address Groups** on the firewall/Panorama that match
   the tags this plugin will register — e.g. a DAG with match criteria
   `'illumio-env-prod'` picks up every IP the plugin tags with
   `illumio-env-prod`. DAG membership updates automatically as tag
   registrations change; no commit is required for membership changes
   (though the DAG object itself, and any rules referencing it, must
   exist and be committed once).
4. Point the plugin at the firewall/Panorama with `PALO_HOST` (hostname
   or IP, no scheme) and the key from step 1 with `PALO_API_KEY`.

### Illumio side

No special PCE-side setup is required beyond normal API credentials
(`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`, `PCE_API_SECRET`),
which plugger injects into the container automatically. Make sure the
label keys you want reflected as PAN-OS tags (`role`, `app`, `env`,
`loc` by default) are actually populated on the workloads you want
synced — a workload with no value for any configured `SYNC_LABELS` key
produces no tags and is skipped.

**Without `PALO_HOST` set, the plugin runs in dry-run mode**: it still
polls the PCE and builds the IP-to-tag map, and shows the result on the
dashboard, but never calls the PAN-OS API. Use this to validate the tag
mapping before enabling the live integration.

## Configuration

All variables are optional; none are marked `required` in the plugin
manifest, but the sync is a no-op against PAN-OS until `PALO_HOST` and
`PALO_API_KEY` are both set.

| Variable | Default | Description |
|---|---|---|
| `PALO_HOST` | _(empty)_ | PAN-OS firewall or Panorama hostname/IP. Empty = dry-run mode (no PAN-OS calls). |
| `PALO_API_KEY` | _(empty)_ | PAN-OS API key (secret — masked in the dashboard and never logged). |
| `PALO_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification when calling the PAN-OS API. |
| `SYNC_INTERVAL` | `3600` | Seconds between automatic sync cycles. |
| `TAG_PREFIX` | `illumio` | Prefix substituted into `TAG_FORMAT` as `{prefix}`. |
| `TAG_FORMAT` | `{prefix}-{key}-{value}` | Template used to build each PAN-OS tag name from `{prefix}`, `{key}` (label key), and `{value}` (label value). |
| `SYNC_LABELS` | `role,app,env,loc` | Comma-separated Illumio label keys to turn into tags. A workload contributes one tag per key that has a value. |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification when calling the PCE API. |

PCE connection credentials (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`,
`PCE_API_KEY`, `PCE_API_SECRET`) are not plugin-specific config — they
are injected automatically by plugger for every plugin, per the
standard PCE connection pattern.

Generated tags are sanitized for PAN-OS compatibility: spaces and
slashes are replaced with hyphens, and the result is truncated to 127
characters (PAN-OS's tag name limit).

## How it works / data flow

```
                 GET /labels (cached once, keyed by href)
   PCE  ─────────────────────────────────────────────────►  palo-alto-dag-sync
        GET /workloads?max_results=10000                          │
                                                                    │  keep online only
                                                                    │  resolve labels → tags
                                                                    │  collect IPs (skip 127.*, 169.254.*)
                                                                    ▼
   PAN-OS  ◄──── type=user-id, <uid-message><register>...          │  ip_tag_map: {ip: [tags]}
   firewall/     batched 500 entries/request                       │
   Panorama      (skipped entirely if PALO_HOST is unset — dry-run)│
                                                                    ▼
                                                        Dashboard (stats, charts, tag registry)
```

Each sync cycle:

1. If the label cache is empty, fetch `/labels` from the PCE once and
   cache `href → {key, value}` in memory (not re-fetched every cycle).
2. If `PALO_HOST` is set, health-check PAN-OS with an `op` command
   (`<show><system><info>`) before doing anything else; on failure the
   sync aborts and the dashboard shows the PAN-OS error.
3. Fetch `/workloads` from the PCE (`max_results=10000`).
4. For each **online** workload: resolve its labels via the cache,
   build tags from `SYNC_LABELS`/`TAG_PREFIX`/`TAG_FORMAT`, and — if at
   least one tag was produced — map every non-loopback,
   non-link-local interface IP to that workload's tag list.
5. If not in dry-run, register the resulting `{ip: [tags]}` map via the
   PAN-OS User-ID XML API, in batches of 500 `<entry>` elements per
   request.
6. Record the outcome (workload/IP/tag counts, timestamp, any error) in
   in-memory state, keeping the last 20 sync results for the dashboard's
   history chart.

The poller runs this cycle every `SYNC_INTERVAL` seconds in a background
thread; one sync also always runs immediately at container startup.

Sync state (`sync_state`) is kept **in memory only** — it resets on
container restart. There is no persistent volume for this plugin.

## Usage

### Dashboard

Open the plugin's UI port (proxied by the plugger dashboard) to see:

- **Header status pill** — current PAN-OS connection status
  (`connected`, `dry-run (no PALO_HOST)`, or an error string) and a
  **Sync Now** button.
- **Stat tiles** — workloads synced, IPs registered, unique tags, total
  syncs since startup.
- **Tags by IP Count** — horizontal bar chart of the top tags by number
  of IPs carrying them.
- **Sync History** — line chart of IPs and tags registered over the
  last 20 sync cycles.
- **Tag Registry** — full list of active tags with their IP counts.

The dashboard polls `/api/sync` every 30 seconds for fresh data.

### API endpoints

| Method & path | Purpose |
|---|---|
| `GET /` | Dashboard HTML. |
| `GET /healthz` | Health check used by plugger (`{"status": "healthy"}`). |
| `GET /api/sync` | Current sync state as JSON (same data backing the dashboard). |
| `POST /api/sync/trigger` | Kicks off an out-of-band sync in a background thread immediately; returns `{"triggered": true}` right away (does not wait for the sync to finish). |

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Dashboard shows `dry-run (no PALO_HOST)` forever | `PALO_HOST` is unset — set it (and `PALO_API_KEY`) to enable live registration. |
| `palo_status` shows a PAN-OS error string | `PALO_HOST`/`PALO_API_KEY` wrong, key expired/revoked, or the account lacks User-ID/XML API access — regenerate the key with `type=keygen` and re-check permissions. |
| Sync error mentions PCE / workloads fetch failure | PCE credentials or connectivity issue — verify `PCE_HOST`/`PCE_API_KEY`/`PCE_API_SECRET` are correctly injected and the PCE is reachable from the container. |
| Tags registered but DAG has no members | The DAG's match expression doesn't match the tag string being registered — compare the exact tag name shown in the dashboard's **Tag Registry** against the DAG's match criteria (tags are lowercase-prefixed, e.g. `illumio-env-prod`). |
| A workload never produces a tag | It has no value for any label key listed in `SYNC_LABELS`, or its labels aren't in the cached `/labels` response (restart the container to force a fresh label fetch — the cache is only populated once per process lifetime). |
| No IPs registered for an otherwise-tagged workload | All of the workload's interface IPs are loopback (`127.*`) or link-local (`169.254.*`) — these are filtered out intentionally. |
| Registration slow / times out on large environments | Requests are batched at 500 entries each; a very large `ip_tag_map` still means many sequential API calls — this is inherent to the current implementation (see Limitations). |

## Notes & limitations

- **One-way and additive only**: the plugin registers and can
  unregister IP-to-tag mappings (`panos_unregister_ips` exists in the
  code), but nothing in the current sync loop calls it — stale
  registrations for workloads that go offline or lose a label are not
  automatically cleaned up today. Re-tagging an IP simply adds a new
  registration; removal is a manual/future-work item.
- **Offline workloads are skipped**, not unregistered — an IP that goes
  offline keeps whatever tags were last registered for it until the
  registration is manually cleared on PAN-OS.
- **In-memory state only** — sync history and counters reset on
  container restart; there is no dashboard reload persistence beyond
  what the last 20 syncs recorded.
- **No pagination beyond a single page** — workloads are fetched with
  `max_results=10000` in one request; environments with more workloads
  than that would need pagination added.
- **TLS verification defaults to skipped** (`PALO_TLS_SKIP_VERIFY` and
  `PCE_TLS_SKIP_VERIFY` both default to `true`) — fine for lab/PoC use,
  but set both to `false` with trusted CAs in production.
- **Untested against a live PAN-OS/Panorama instance** — the XML API
  integration follows PAN-OS documentation but has not been validated
  end-to-end against real hardware/VMs. Validate carefully in dry-run
  mode first, and confirm DAG membership updates as expected before
  relying on it for enforcement.
