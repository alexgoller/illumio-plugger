# dragos-sync

Sync OT/ICS asset inventory from the **Dragos Platform** into Illumio as
**unmanaged workloads** with labels, so you can write segmentation policy for
the OT estate using Dragos's device-type / zone / Purdue intelligence.

## How it works

- Pulls assets from the Dragos **SiteStore API** — `GET /api/{version}/assets`,
  HTTP **Basic** auth with an API ID/Secret (scope `asset:read`).
- Upserts each asset as an Illumio **unmanaged workload**, made idempotent with
  `external_data_set: "dragos"` + `external_data_reference: <asset id>` — re-syncs
  **update** rather than duplicate.
- Maps Dragos attributes to Illumio labels (defaults):

  | Dragos attribute | Illumio label |
  |------------------|---------------|
  | device type / role | `role` |
  | zone / site | `loc` |
  | Purdue level | `env` |
  | vendor / manufacturer | `vendor` (custom dimension) |
  | criticality | `criticality` (custom dimension) |

- Missing label values (and the custom `vendor`/`criticality` dimensions) are
  created on demand when `CREATE_LABELS=true`.
- Assets removed from Dragos are handled per `STALE_ACTION` — **report**
  (default, flag only), **label** (`lifecycle=stale`), or **delete**.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DRAGOS_HOST` | _(required)_ | SiteStore base URL, e.g. `https://dragos.example.com` |
| `DRAGOS_API_VERSION` | `v2` | API version segment (`v2`/`v3`/`v4`) |
| `DRAGOS_API_ID` / `DRAGOS_API_SECRET` | _(required)_ | API key (Admin → Users → Add New API Key; `asset:read`) |
| `SYNC_INTERVAL` | `3600` | Seconds between syncs |
| `CREATE_LABELS` | `true` | Create missing label values + custom dimensions |
| `LABEL_MAP` | _(none)_ | JSON overriding the field→label map |
| `DRY_RUN` | `false` | Compute the sync without writing to Illumio |
| `STALE_ACTION` | `report` | What to do when an asset leaves the leading system: `report` (flag only), `label` (mark `lifecycle=stale`), or `delete` (remove the unmanaged workload) |
| `DEBUG` | `false` | Dump a raw asset + computed mapping to tune the field map |

Illumio PCE credentials are injected by plugger.

## Tuning the field map

Dragos asset JSON keys vary by SiteStore version, so each label pulls from a
list of candidate field names. If a label isn't populating, enable `DEBUG`,
run a sync, and inspect the raw asset + computed mapping in the dashboard, then
set `LABEL_MAP` to the right keys, e.g.:

```json
{"role": ["device_type"], "loc": ["zone_name"], "env": ["purdue_level"],
 "vendor": ["vendor"], "criticality": ["criticality"]}
```

## Notes (v0.1.0, preview)

- Untested against a live Dragos SiteStore; the field map is intentionally
  defensive and overridable.
- Custom dimensions require a PCE that supports `label_dimensions`; if creation
  fails, those labels are skipped and the core `role`/`loc`/`env` labels still apply.
- One-way (Dragos → Illumio). Cross-PCE / write-back are out of scope.
