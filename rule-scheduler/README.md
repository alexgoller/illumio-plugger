# rule-scheduler

Time-based enable/disable scheduling for Illumio PCE rulesets (and individual
rules) — business hours access, maintenance windows, weekend lockdowns —
applied automatically and provisioned per-ruleset with a full change history.

- [What it does](#what-it-does)
- [Why it matters](#why-it-matters)
- [Prerequisites & setup](#prerequisites--setup)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Notes & limitations](#notes--limitations)

## What it does

On a configurable interval, `rule-scheduler`:

1. Loads a set of user-defined **schedules** — each with a day-of-week /
   time-of-day window, one or more target ruleset (or rule) HREFs, and an
   action to take inside vs. outside the window.
2. Evaluates every **enabled** schedule against the current time.
3. For any target whose current `enabled` state doesn't match what the
   schedule calls for, flips it via the PCE API (`PUT .../{href}` with
   `{"enabled": true|false}`) and **provisions just that ruleset** to active
   policy — not a full org-wide provision.
4. Records every change (target, action, schedule, provisioning result,
   timestamp) in a rolling history, visible in the dashboard.

## Why it matters

Segmentation rules that should only be live during certain hours — vendor
maintenance windows, batch-job access, temporary weekend cutover rules — are
easy to turn on and forget to turn off. `rule-scheduler` automates the
enable/disable transitions on a schedule so access windows are enforced
consistently, and keeps an audit trail of exactly which schedule changed
which ruleset and when.

## Prerequisites & setup

- PCE API credentials are injected automatically by plugger
  (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`, `PCE_API_SECRET`).
  The API key needs read/write access to rulesets and rules, plus policy
  provisioning rights.
- A persistent `/data` volume (required — see [Configuration](#configuration))
  for schedule storage.
- Install and open the dashboard:

  ```bash
  plugger install rule-scheduler
  ```

  Then browse to the plugin's dashboard port (8080) and add a schedule.
  Targets are picked from a **live list of draft rulesets** fetched from your
  PCE — no manual HREF lookup needed for ruleset-level schedules.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECK_INTERVAL` | `120` | Seconds between schedule evaluation cycles |
| `TZ` | `UTC` | Timezone used for day/time-of-day comparisons (IANA name, e.g. `America/New_York`, `Europe/Berlin`) |
| `PCE_TLS_SKIP_VERIFY` | `true` | Declared in the plugin manifest, but **not currently read by the code** — see [Notes & limitations](#notes--limitations) |

PCE credentials (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`,
`PCE_API_SECRET`) are injected by plugger and are not configured here.

**Volume**

| Path | Required | Description |
|------|----------|-------------|
| `/data` | yes | Persists schedule configuration (`schedules.json`, or an optional `schedules.yaml` you seed yourself) across restarts |

## How it works

### Schedule object

Each schedule is a JSON object with these fields:

| Field | Description |
|-------|-------------|
| `name` | Schedule name (shown in the dashboard and history) |
| `description` | Free-text note |
| `targets` | List of ruleset (or rule) HREFs this schedule controls |
| `target_type` | `ruleset` or `rule` |
| `days` | List of `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun` |
| `start_time` / `end_time` | Window bounds, `HH:MM` 24-hour format |
| `action_in_window` | `enable` or `disable` — applied while inside the window |
| `action_outside` | `enable`, `disable`, or empty string — applied while outside the window; empty means **no action is taken outside the window**, so targets are not reverted automatically |
| `comment` | Written into the target ruleset's `description` when a change is applied (ruleset targets only) |
| `enabled` | Whether the schedule is active; disabled schedules are skipped entirely and never touch their targets |

Three example schedules ship as built-in templates when no configuration
exists yet — **Business Hours Access** (Mon–Fri 09:00–17:00), **Maintenance
Window** (Sat 02:00–06:00), and **Weekend Lockdown** (Sat–Sun, all day). All
three start with `enabled: false` and empty `targets`, so nothing runs until
you edit them.

### Storage & load order

`load_schedules()` checks, in order, the first source that exists:

1. `SCHEDULES_YAML` (default `/data/schedules.yaml`) — a YAML file with a
   top-level `schedules:` list, or a bare YAML list
2. `SCHEDULES_FILE` (default `/data/schedules.json`) — a JSON array
3. `SCHEDULES` — a JSON array as a single env var string
4. The three built-in disabled templates above

Dashboard edits (add/update/toggle/delete) are always saved to the JSON path
(`SCHEDULES_FILE`, default `/data/schedules.json`) via `save_schedules()`.
Because the YAML path is checked first on every load, **if a
`schedules.yaml` file is present it will always win**, even after you've
edited schedules through the dashboard — see
[Troubleshooting](#troubleshooting).

### Evaluation

Every `CHECK_INTERVAL` seconds (and immediately after any dashboard edit),
`run_check()`:

1. Reloads schedules from storage.
2. For each **enabled** schedule, determines whether the current time is
   inside the window (`is_in_window()`): the current weekday must be in
   `days`, and the current `HH:MM` must fall between `start_time` and
   `end_time`. If `start_time > end_time` the window is treated as
   **overnight** (e.g. `22:00`–`06:00` matches from 22:00 through midnight
   and from midnight through 06:00).
3. Applies `action_in_window` or `action_outside` accordingly
   (`apply_schedule()`): for each target HREF, it fetches the object's
   current `enabled` state, and — only if it doesn't already match — sets it
   with `PUT` and **provisions that one ruleset** to active policy
   (`POST /sec_policy` with `change_subset.rule_sets` scoped to just that
   HREF; if the target is a rule HREF, its parent ruleset is provisioned).
4. Updates the in-memory status (`last_check`, `check_count`, per-schedule
   `in_window`/`status`, `pce_status`) and appends any changes to a history
   list capped at the last 100 entries.

Disabled schedules are reported with `status: "disabled"` and are never
evaluated or applied.

### Time zone

`TZ` is read and reported in the dashboard, and comparisons use the
container's local time (`datetime.now()`), which reflects `TZ` on standard
Linux container images. There is no explicit per-schedule timezone override —
all schedules in one plugin instance share the same `TZ`.

## Usage

### Dashboard

The dashboard (port 8080, path `/`) shows:

- **Stats** — total schedules, how many are enabled, how many are currently
  in-window, and total recorded changes.
- **Schedules list** — one card per schedule with status (disabled / in
  window / outside), days, time window, in/outside actions, target count,
  and **Edit / Enable-Disable / Delete** controls.
- **Add/Edit form** — name, target type, a live checkbox list of draft
  rulesets fetched from the PCE, comment, day picker, start/end time, and
  in-window/outside-window actions.
- **Change history** — the last 100 applied changes, newest first, with
  target name, action, and which schedule triggered it.
- A live clock and the configured `TZ`.

Toggling a schedule **off**, or **deleting** one, prompts for what to do
with its current targets: re-enable them, force-disable them, or leave them
as-is. Toggling a schedule **on** triggers an immediate reconciliation
instead of waiting for the next poll.

### API endpoints

| Method | Path | Description |
|--------|------|--------------|
| `GET` | `/healthz` | Health check — `{"status": "healthy"}` |
| `GET` | `/` | Dashboard HTML |
| `GET` | `/api/status` | Full state: `last_check`, `check_count`, `error`, `schedules` (with computed status), `history`, `pce_status`, `timezone` |
| `GET` | `/api/rulesets` | Live list of **draft** rulesets from the PCE (`/sec_policy/draft/rule_sets`) — `[{href, name, enabled}]`, used to populate the target picker |
| `POST` | `/api/schedules` | Add a new schedule (JSON body = schedule object). Triggers an immediate background reconciliation |
| `PUT` | `/api/schedules/{index}` | Replace the schedule at `index`. If the body omits `enabled`, the existing value is preserved. Triggers an immediate reconciliation |
| `POST` | `/api/schedules/{index}/toggle` | Flip `enabled` for the schedule at `index`. Optional body `{"restore_action": "enable"\|"disable"}` — only used when disabling, to push targets to that state; omit it (or `"leave"`) to leave targets untouched |
| `DELETE` | `/api/schedules/{index}?restore=enable\|leave` | Remove the schedule at `index`. `restore=enable` re-enables its targets first; default (`leave`, or omitted) leaves targets in their current state |

Schedules are addressed by **array index**, not a stable ID — see
[Notes & limitations](#notes--limitations).

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| "Target Rulesets" picker is empty | The PCE API key lacks read access to `/sec_policy/draft/rule_sets`, or the PCE is unreachable — check `/api/status`'s `error`/`pce_status` fields and container logs |
| A dashboard edit seems to "revert" after a while | A `schedules.yaml` file exists under `/data` and is taking priority over your JSON-saved edits on every reload — remove the YAML file, or manage schedules exclusively via one source (dashboard/JSON, or YAML) |
| Targets never revert when leaving the window | `action_outside` is set to empty ("No action") for that schedule — pick `enable` or `disable` explicitly if you want the opposite state enforced outside the window |
| Nothing changes even though the window looks right | Check `TZ` — comparisons use the container's local time, so a mismatched timezone will shift when windows actually open/close |
| Can't schedule an individual rule from the dashboard | The UI's target picker only lists rulesets; for `target_type: "rule"`, create/edit the schedule via `POST`/`PUT /api/schedules` directly with the rule's HREF in `targets` |
| Change applied but not visible in the PCE console under Active policy | The scheduler provisions only the affected ruleset's **draft** to active — confirm the ruleset shows the expected `enabled` state in Draft policy, and that provisioning succeeded (`success: true` in the history entry) |

## Notes & limitations

- **`PCE_TLS_SKIP_VERIFY` is not wired up** — the PCE client currently calls
  `pce.set_tls_settings(verify=False)` unconditionally, so TLS certificate
  verification is always disabled regardless of this variable's value.
- **No stable schedule IDs** — the API and dashboard both reference schedules
  by their position in the list. There's no locking around the
  load-modify-save cycle for schedule storage, so concurrent edits from
  multiple dashboard sessions could race.
- **YAML/JSON priority** — if both `schedules.yaml` and `schedules.json`
  exist under `/data`, YAML always wins on load (see Troubleshooting above).
- **Rule-level targeting is API-only** — the dashboard's target picker only
  surfaces rulesets; individual-rule schedules must be created or edited
  through the API.
- **History is capped** at the last 100 recorded changes.
- The dashboard footer's displayed check interval is a fixed label in the
  page's JavaScript and does not reflect a custom `CHECK_INTERVAL` value —
  it's cosmetic only; the poller itself does honor `CHECK_INTERVAL`.
