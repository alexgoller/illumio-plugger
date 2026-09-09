# nozomi-sync

Sync OT/ICS/IoT asset inventory from **Nozomi Networks** into Illumio as
**unmanaged workloads** with labels, so you can write segmentation policy for
the OT/IoT estate using Nozomi's device classification, zones, and Purdue-level
intelligence.

- [What it does](#what-it-does)
- [Why it matters](#why-it-matters)
- [Architecture & data flow](#architecture--data-flow)
- [Deployment modes](#deployment-modes)
- [Getting Nozomi credentials](#getting-nozomi-credentials)
- [Label mapping](#label-mapping)
- [Configuration](#configuration)
- [Tuning the field map](#tuning-the-field-map)
- [First run (recommended)](#first-run-recommended)
- [Idempotency & stale assets](#idempotency--stale-assets)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [Limitations](#limitations)

## What it does

On a schedule (and on demand), `nozomi-sync`:

1. Authenticates to Nozomi (Vantage or Guardian) and **pulls the asset inventory**.
2. Maps each Nozomi asset to an Illumio **unmanaged workload** with **labels**
   derived from the asset's attributes.
3. **Upserts** those workloads into Illumio — creating new ones and updating
   existing ones — keyed by the Nozomi asset ID so re-syncs never duplicate.
4. Reports assets that have disappeared from Nozomi as **stale** (never deletes).

## Why it matters

Nozomi passively discovers OT/ICS/IoT devices that have **no Illumio agent
(VEN)**. Representing them in Illumio as **labeled unmanaged workloads** lets
Illumio's policy model target the OT estate — ringfencing by device type,
segmenting by Purdue level, isolating a zone — using the rich context Nozomi
already produces. Illumio and Nozomi are both widely deployed in critical
infrastructure, so this is a natural, high-value pairing.

## Architecture & data flow

```
                 (Vantage: JWT via /api/v1/keys/sign_in
                  Guardian: session via /api/open/sign_in)
   Nozomi  ────────────────────────────────────────────►  nozomi-sync
   assets    GET /api/v1/assets   (Vantage, paginated)        │
             GET /api/open/query/do?query=assets (Guardian)   │  map + label
                                                              ▼
   Illumio  ◄──── bulk_create / bulk_update unmanaged workloads
   PCE           external_data_set="nozomi", external_data_reference=<asset id>
                 labels: role / loc / env / vendor / criticality
```

## Deployment modes

Set `NOZOMI_MODE` to match your deployment:

### `vantage` (cloud) — default
- Auth: **API key name + token** exchanged for a **JWT** at
  `POST /api/v1/keys/sign_in` (JWT valid ~30 min; the plugin re-authenticates
  automatically on expiry).
- Assets: `GET /api/v1/assets`, paginated (`page[size]`, `page[number]`).
- `NOZOMI_HOST` = `https://<tenant>.vantage.nozominetworks.io`.

### `guardian` (on-prem Guardian / CMC)
- Auth: **username + password** at `POST /api/open/sign_in` (session cookie +
  CSRF token).
- Assets: Nozomi Query Language via `GET /api/open/query/do?query=assets`.
- `NOZOMI_HOST` = `https://<guardian-host>`.

## Getting Nozomi credentials

**Vantage:** Administration → API keys → create a key; copy the **Key Name**
and **Key Token** into `NOZOMI_KEY_NAME` / `NOZOMI_KEY_TOKEN`. See
[Vantage API keys](https://help.vantage.nozominetworks.io/docs/api-key-config).

**Guardian:** create (or reuse) a user with read access to the asset inventory
and set `NOZOMI_USERNAME` / `NOZOMI_PASSWORD`. Queries use the same NQL you can
try in the Guardian **Query** view (`assets | select ...`).

## Label mapping

Defaults (each Illumio label pulls from the first matching Nozomi field):

| Illumio label | Nozomi source (candidate fields) |
|---------------|----------------------------------|
| `role` | `type`, `product_name`, `device_type` |
| `loc` | `zone`, `site`, `zone_name` |
| `env` | `level` (Purdue), `purdue_level` |
| `vendor` (custom dimension) | `vendor`, `mac_vendor`, `manufacturer` |
| `criticality` (custom dimension) | `criticality`, `risk`, `importance` |

Missing label **values** — and the custom `vendor` / `criticality`
**dimensions** — are created on demand when `CREATE_LABELS=true`.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NOZOMI_MODE` | `vantage` | `vantage` or `guardian` |
| `NOZOMI_HOST` | _(required)_ | Base URL of the Nozomi endpoint |
| `NOZOMI_KEY_NAME` / `NOZOMI_KEY_TOKEN` | — | Vantage API key (vantage mode) |
| `NOZOMI_USERNAME` / `NOZOMI_PASSWORD` | — | Guardian credentials (guardian mode) |
| `SYNC_INTERVAL` | `3600` | Seconds between syncs |
| `CREATE_LABELS` | `true` | Create missing label values + custom dimensions |
| `LABEL_MAP` | _(none)_ | JSON overriding the field→label map |
| `PAGE_SIZE` | `500` | Vantage page size |
| `DRY_RUN` | `false` | Compute the sync without writing to Illumio |
| `DEBUG` | `false` | Dump a raw asset + computed mapping in the dashboard |
| `NOZOMI_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for Nozomi |

PCE credentials are injected by plugger.

## Tuning the field map

Nozomi asset JSON keys differ between Vantage and Guardian and across versions,
so each label pulls from a **list of candidate field names**. If a label isn't
populating:

1. Set `DEBUG=true` and run a sync (dashboard → **Sync now**).
2. Inspect the **raw asset** and **computed mapping** in the dashboard's debug panel.
3. Set `LABEL_MAP` to the exact keys your Nozomi returns, e.g.:

```json
{"role": ["type"], "loc": ["zone"], "env": ["level"],
 "vendor": ["vendor"], "criticality": ["risk"]}
```

## First run (recommended)

1. `DRY_RUN=true`, `DEBUG=true` → verify counts + field mapping look right.
2. Turn off `DRY_RUN` → workloads + labels are created in Illumio.
3. Review the new unmanaged workloads and labels, then build policy against them.

## Idempotency & stale assets

Every synced workload carries `external_data_set="nozomi"` and
`external_data_reference=<nozomi asset id>`. Re-syncs match on that reference,
so assets are **updated in place**, never duplicated. Assets that disappear from
Nozomi are reported as **stale** in the dashboard and **never auto-deleted** —
review and remove them in Illumio if desired.

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `Vantage sign_in -> HTTP 401` | Wrong `NOZOMI_KEY_NAME`/`TOKEN`, or key lacks asset read |
| `Guardian sign_in -> HTTP 401/403` | Wrong username/password, or user lacks inventory read; some Guardian versions require a CSRF token (handled automatically) |
| 0 assets fetched | Wrong `NOZOMI_MODE` or `NOZOMI_HOST`; check the endpoint is reachable from the container |
| Labels empty | Field names differ — use `DEBUG` + `LABEL_MAP` (see above) |
| Custom `vendor`/`criticality` missing | PCE lacks `label_dimensions` support or permission; core `role`/`loc`/`env` still apply |

## Security notes

- Store `NOZOMI_KEY_TOKEN` / `NOZOMI_PASSWORD` as plugger **secrets** (they are
  masked and never logged).
- `NOZOMI_TLS_SKIP_VERIFY` defaults to `true` for lab use; set it to `false`
  with a trusted CA in production.
- The plugin only **reads** from Nozomi and only **creates/updates** unmanaged
  workloads + labels in Illumio — it never deletes.

## Limitations (v0.1.0, preview)

- **Untested against a live Nozomi Vantage/Guardian** — the field map is
  intentionally defensive and overridable; validate with `DRY_RUN` + `DEBUG`.
- Guardian NQL fetch returns the query's default result set; very large
  inventories may need NQL paging (future enhancement).
- One-way (Nozomi → Illumio). Vulnerabilities/alerts are out of scope here
  (candidate follow-ups, mirroring the Dragos plugin family).
