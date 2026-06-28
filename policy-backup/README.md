# policy-backup

Snapshot Illumio PCE policy and workload inventory to versioned JSON backups,
diff changes over time, and restore to **draft** policy with a guarded preview.

## What it captures

Each backup is a timestamped directory under `/data/backups/<ts>/` with one
JSON file per object type plus a `manifest.json`:

- `labels.json`, `label_groups.json`, `services.json`, `ip_lists.json`
- `rule_sets.json`, `enforcement_boundaries.json`, `pairing_profiles.json`
- `workloads.json` — inventory snapshot (reference only, never restored)

## Features

- **Scheduled + on-demand backup** — daily by default (`BACKUP_INTERVAL`),
  or "Back up now" in the dashboard. Old backups pruned to `RETENTION_COUNT`.
- **Optional git push** — set `GIT_REMOTE` (and `GIT_TOKEN`) to commit and push
  each backup to a repo for offsite history.
- **Diff** — compare any two backups, or a backup against current **live**
  policy: added / removed / changed objects per type.
- **Guarded restore** — preview the change set, confirm explicitly, then write
  to **draft** policy only (creates missing, updates changed, in dependency
  order). It **never deletes and never provisions** — you review and provision
  in the PCE console.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKUP_INTERVAL` | `86400` | Seconds between scheduled backups |
| `RETENTION_COUNT` | `30` | Backups to keep |
| `GIT_REMOTE` | _(none)_ | Optional git remote to push backups to |
| `GIT_BRANCH` | `main` | Branch to push to |
| `GIT_TOKEN` | _(none)_ | Token for HTTPS git push (secret) |
| `REPORT_ON_CHANGE` | `false` | Publish a report when a scheduled backup detects changes |

PCE credentials are injected by plugger.

## Notes / limits (v0.1.0, preview)

- Restore is best-effort and draft-only. Objects whose referenced dependencies
  were also deleted may fail to recreate (reported per-object); restore the
  dependencies first or recreate manually.
- Very large workload inventories may exceed the single-request fetch; async
  export is a future enhancement.
