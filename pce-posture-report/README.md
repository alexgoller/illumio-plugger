# pce-posture-report

Scheduled security posture scoring for an Illumio PCE — a single cron run that
collects workloads, labels, and policy objects, computes a 0-100 posture
score, and drops a self-contained HTML report plus the raw JSON into `/data`.

- [What it does](#what-it-does)
- [Why it matters](#why-it-matters)
- [Prerequisites & setup](#prerequisites--setup)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Notes / limits](#notes--limits)

## What it does

On each cron trigger, `pce-posture-report`:

1. Connects to the PCE and pulls `/workloads` (single page, up to 10,000),
   `/labels`, `/sec_policy/active/rule_sets`, `/sec_policy/draft/rule_sets`,
   `/sec_policy/active/ip_lists`, and `/sec_policy/active/services`.
2. Computes posture metrics from that snapshot:
   - **Enforcement coverage** — workload counts per `enforcement_mode`
     (`full`, `selective`, `visibility_only`, `idle`).
   - **Managed vs. unmanaged** — a workload counts as managed if it has an
     `agent.href` (i.e. a VEN), unmanaged otherwise.
   - **Online / offline** — from each workload's `online` flag.
   - **OS distribution** — top 10 `os_type` values by workload count.
   - **Label coverage** — how many workloads carry `role`, `app`, `env`,
     `loc`; how many carry all four ("fully labeled"); how many carry none
     ("unlabeled").
   - **Label inventory** — total labels defined in the PCE, grouped by key.
   - **Policy rules scoring** — active vs. draft ruleset/rule counts, IP list
     and service counts, and a `pending_changes` figure (see
     [How it works](#how-it-works) for the exact formula).
   - **Posture score** — a single 0-100 number combining the above (formula
     below).
3. Writes a timestamped **HTML** report (self-contained, inline CSS, no
   external assets or JS) and a timestamped **JSON** report to `/data`, then
   refreshes `posture_latest.html` / `posture_latest.json` symlinks.
4. Publishes a short Markdown summary (score, workload/managed counts) to
   plugger's configured output channels (Slack/email/webhook), tagged
   `posture`, `compliance`, `score`.
5. Exits. There is no dashboard, no HTTP server, and no long-running process
   — the container starts, runs once, and stops until the next cron trigger.

## Why it matters

Enforcement mode, label coverage, and policy maturity all drift over time as
workloads are added, decommissioned, or relabeled. A recurring, point-in-time
snapshot turns "are we actually enforcing policy on most of the estate?" into
a number you can trend over weeks instead of a question someone has to
answer by clicking through the PCE console. Because the report is a plain
HTML file, it's easy to archive, diff by date, or forward as-is without
needing PCE access.

## Prerequisites & setup

- A reachable PCE with API credentials (PCE_HOST/PORT/ORG_ID/API_KEY/SECRET
  are injected automatically by plugger — no plugin-specific setup needed).
- The API credential needs read access to workloads, labels, rulesets, IP
  lists, and services (a read-only or global-org-owner role is sufficient).
- A `/data` volume for the plugin to write reports into (plugger creates this
  automatically under `{dataDir}/volumes/pce-posture-report/`).

Install like any other plugin:

```bash
plugger install pce-posture-report
```

No further configuration is required to get a working report — the default
cron schedule and default TLS setting are enough for most environments.

## Configuration

Every environment variable declared in `plugin.yaml` / `.plugger/metadata.yaml`:

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `PCE_TLS_SKIP_VERIFY` | `true` | bool | Skip TLS certificate verification |

**Note:** this variable is declared in the plugin manifest but is **not
currently read by `main.py`** — `get_pce()` calls
`pce.set_tls_settings(verify=False)` unconditionally, so TLS verification is
always skipped regardless of this setting. Setting it to `false` has no
effect on the current code.

PCE connection credentials (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`,
`PCE_API_KEY`, `PCE_API_SECRET`) are injected by plugger automatically and
are not part of this plugin's own configuration.

Resource limits (from `plugin.yaml`): `memoryLimit: 256m`, `cpuLimit: 0.5`.
There is no `health` block in the manifest — as a cron job with no
persistent process, there's nothing for plugger to health-check between
runs.

## How it works

**Schedule.** `pce-posture-report` runs in **cron mode**, not daemon mode:

```yaml
schedule:
  mode: cron
  cron: "0 */6 * * *"   # every 6 hours
```

Plugger starts a fresh container at each cron tick, `main.py` runs end to
end, and the container exits. There is no polling loop, no `POLL_INTERVAL`,
and no port to reach the plugin between runs.

**Posture score formula.** Out of a possible 100 points, computed only when
`total_workloads > 0` (otherwise the score is `0`):

| Component | Points | Formula |
|---|---|---|
| Enforcement coverage | up to 25 | `25 * (full + selective) / total_workloads` |
| Label coverage | up to 25 | `25 * fully_labeled / total_workloads` |
| Active policy | up to 25 | `0` if no active rules; otherwise `10 + min(15, rules_active)` — i.e. 11 points for a single active rule, rising to 25 once there are 15 or more |
| Managed workloads | up to 25 | `25 * managed / total_workloads` |

Each component is capped at 25 and truncated to an integer before summing,
so the total score is always a whole number between 0 and 100.

**Pending changes.** `pending_changes` is simply
`len(rulesets_draft) - len(rulesets_active)` — a raw count delta between the
draft and active ruleset lists, not a semantic diff of what actually
changed. It can be negative (e.g. after rulesets are deprovisioned) and
should be read as a rough signal, not an audit trail.

**Output artifacts.** Each run writes four files to `/data` (UTC timestamp,
`YYYYMMDD_HHMMSS`):

```
/data/posture_20260115_060000.json
/data/posture_20260115_060000.html
/data/posture_latest.json  -> posture_20260115_060000.json
/data/posture_latest.html  -> posture_20260115_060000.html
```

The `_latest` symlinks are removed and recreated on every run so they always
point at the most recent report. Older timestamped files are **not**
cleaned up automatically — see [Notes / limits](#notes--limits).

**Report publishing.** After writing the files, the plugin posts a short
summary via `plugger_report.publish_report()` to whatever output channels
plugger has configured (Slack, email, webhook), with `severity` set to
`info` (score ≥ 75), `warning` (score ≥ 50), or `critical` (below 50). This
call is a silent no-op if plugger hasn't injected `PLUGGER_URL` (e.g. when
running the container standalone outside plugger). See
[Notes / limits](#notes--limits) for a caveat about what's actually in that
summary today.

## Usage

The plugin needs no interaction after install — it runs on its own cron
schedule. To read a report:

```bash
# Latest HTML report (self-contained, open directly in a browser)
open {dataDir}/volumes/pce-posture-report/posture_latest.html

# Latest JSON (for scripting / trending over time)
cat {dataDir}/volumes/pce-posture-report/posture_latest.json | jq .score
```

To change how often it runs, edit the `cron` expression in `plugin.yaml`
(standard 5-field cron syntax) and reinstall/restart the plugin.

To trigger an ad-hoc run outside the schedule, run the image directly with
PCE credentials in the environment:

```bash
docker run --rm \
  -e PCE_HOST=poc3.illum.io -e PCE_PORT=8443 -e PCE_ORG_ID=1 \
  -e PCE_API_KEY=... -e PCE_API_SECRET=... \
  -v $(pwd)/data:/data \
  pce-posture-report:latest
```

(This bypasses plugger, so `PLUGGER_URL` won't be set and the output-channel
publish step will silently no-op — you'll still get the HTML/JSON files.)

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| No files in `/data` after install | Cron hasn't fired yet — default is every 6 hours; check plugger's scheduler/container logs for the plugin |
| `KeyError` / crash reading `PCE_HOST` etc. | PCE credentials weren't injected — verify the plugin was installed through plugger, not run standalone without env vars |
| Empty or all-zero report (`total_workloads: 0`) | API credential lacks read access to `/workloads`, or the org genuinely has no workloads; check credential scope/role |
| Score always `0` | Confirm `total_workloads > 0` — the scoring formula short-circuits to 0 when there are no workloads |
| More than 10,000 workloads in the org | `/workloads` is fetched as a single page (`max_results=10000`) with no pagination loop — counts will silently be truncated to the first page returned |
| Slack/email summary shows 0 for enforcement/labels/active rules even though the HTML report looks correct | Known key-mismatch in the summary body construction (see [Notes / limits](#notes--limits)) — the score and workload/managed counts in the summary are accurate; the rest of the one-line breakdown isn't. Read the HTML/JSON report in `/data` for correct figures |
| `PCE_TLS_SKIP_VERIFY=false` doesn't enforce TLS verification | The variable isn't wired up in current code — TLS verification is always skipped (see [Configuration](#configuration)) |

## Notes / limits

- **Single-page workload fetch.** `/workloads` is queried once with
  `max_results=10000` and no pagination — PCEs with more than 10,000
  workloads will get an incomplete/truncated count in every metric derived
  from the workload list.
- **`PCE_TLS_SKIP_VERIFY` is not actually consulted.** `get_pce()` hardcodes
  `verify=False`. The env var exists in the manifest but changing it has no
  effect on the running code today.
- **The published Slack/email/webhook summary has a key mismatch.** `main()`
  builds the outbound report body from `report.get("enforcement", {})`,
  `report.get("labels", {}).get("fully_labeled", 0)`, and
  `report.get("policy", {}).get("active_rules", 0)` — but the actual `report`
  dict returned by `analyze()` nests enforcement mode counts and
  `fully_labeled` under `report["workloads"]`, and names the active-rule
  count `rules_active` (not `active_rules`) under `report["policy"]`. As a
  result, every published summary shows `0 full, 0 selective, 0 visibility,
  0 idle`, `0 fully labeled`, and `0` active rules, regardless of the real
  numbers. Only the posture score and the workload/managed totals in that
  summary are correct. The HTML and JSON files written to `/data` are
  unaffected and contain the accurate figures.
- **`pending_changes` is a count delta, not a diff.** See
  [How it works](#how-it-works) — it can go negative and doesn't identify
  *which* rulesets changed.
- **No report retention/cleanup.** Timestamped HTML/JSON files accumulate in
  `/data` indefinitely; only the `_latest` symlinks are ever removed and
  replaced. Prune old reports manually if disk usage matters.
- **No dashboard.** Unlike daemon-mode plugins with a `type: ui` port, this
  plugin has no `ports` entry in `.plugger/metadata.yaml` and nothing to
  proxy through the plugger dashboard — the HTML report is a static file you
  open directly, not a live view.
- **Read-only.** The plugin never writes to the PCE — it only reads
  workloads, labels, and policy objects to build the report.
