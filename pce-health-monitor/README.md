# PCE Health Monitor

A lightweight, auto-refreshing dashboard that continuously checks whether your Illumio PCE is reachable and authenticating correctly, with a JSON API for wiring into external monitoring.

- [What it does](#what-it-does)
- [Why it matters](#why-it-matters)
- [Prerequisites & setup](#prerequisites--setup)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Notes / limits](#notes--limits)

## What it does

On a fixed interval (and once immediately at startup), `pce-health-monitor`:

1. Sends authenticated HTTPS requests to three PCE API endpoints:
   - `GET /api/v2/health`
   - `GET /api/v2/node_available`
   - `GET /api/v2/orgs/{org_id}/workloads?max_results=1`
2. Records, per endpoint, whether it responded at all and what HTTP status it returned.
3. Rolls the three results up into a single overall status — `healthy`, `degraded`, `unreachable`, or `error` — and publishes it on a web dashboard and a JSON API.

It does **not** check host-level metrics like CPU, memory, or disk — despite the name, this is an **API reachability and auth health** monitor, not an OS resource monitor. (See [Notes / limits](#notes--limits).)

## Why it matters

The PCE is the control plane every VEN, plugin, and integration depends on. If it becomes unreachable or an API key expires/rotates badly, everything downstream degrades silently until someone notices missed policy pushes or stale data. This plugin gives a always-on, at-a-glance signal — plus a JSON endpoint other tooling (uptime checkers, status pages, alerting pipelines) can poll — so PCE connectivity problems surface immediately instead of being discovered indirectly.

## Prerequisites & setup

- A reachable Illumio PCE and valid API credentials, provided the normal way — plugger injects `PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`, and `PCE_API_SECRET` automatically at container start. No plugin-specific credential configuration is needed.
- The API key needs at least read access to workloads — the third check lists one workload (`max_results=1`) to confirm the key can actually query PCE data, not just reach the health endpoint.
- Install like any other plugin:

  ```bash
  plugger install pce-health-monitor
  ```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `120` | Seconds between health checks |
| `PCE_TLS_SKIP_VERIFY` | `false` | Skip TLS certificate verification for PCE requests |

These are the only two configuration values declared in `plugin.yaml` / `.plugger/metadata.yaml`. Everything else needed to reach the PCE (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`, `PCE_API_SECRET`) is injected automatically by plugger.

Note: `PCE_TLS_SKIP_VERIFY` defaults to `false` here (verification **on** by default), which is the opposite default from some other plugins in this repo — set it to `true` only if your PCE uses a certificate the container doesn't trust.

The container also reads `HTTP_PORT` (default `8080`) to pick the port it listens on, but this is not exposed as a declared config option in the manifest — it's fixed to `8080` in practice via the `ports` entry in `.plugger/metadata.yaml`.

## How it works

Each check cycle (`check_pce_health()` in `main.py`) hits all three endpoints listed above using preemptive HTTP Basic Auth (`PCE_API_KEY`:`PCE_API_SECRET`, base64-encoded) with a 10-second timeout per request. For each endpoint:

- A response in the 2xx–3xx range marks that endpoint `ok`, and marks the overall check `reachable` **and** `authenticated`.
- An HTTP error response other than `401` (e.g. `403`, `404`) still marks the check `reachable` and `authenticated` — the PCE answered and accepted the credentials, it just didn't return success for that specific call.
- An HTTP `401` marks the check `reachable` but leaves `authenticated` unset for that endpoint.
- A connection failure (timeout, DNS error, TLS error, refused connection) leaves both flags unset for that endpoint.

These flags accumulate across all three endpoints (once `reachable` or `authenticated` is set `true` by any endpoint, it stays `true`). The overall status is then:

| Status | Condition |
|--------|-----------|
| `healthy` | At least one endpoint was reachable and authenticated |
| `degraded` | At least one endpoint was reachable, but none authenticated (e.g. all returned 401) |
| `unreachable` | No endpoint could be reached at all |
| `error` | An unexpected exception occurred in the check itself (bug/crash, not a normal HTTP failure) — surfaces in logs |
| `unknown` | Initial state before the first check has completed |

The first check runs synchronously at startup (before the HTTP server starts accepting the dashboard), then a background thread repeats the check every `POLL_INTERVAL` seconds.

**Important nuance:** the container's own `/healthz` endpoint (used by plugger's `health.endpoint` restart check) always returns `{"status": "healthy"}` as long as the Python process is alive — it does not reflect PCE reachability. A `degraded` or `unreachable` PCE status will **not** trigger a plugger auto-restart; you have to look at the dashboard or `/api/health` to see PCE-level problems.

## Usage

The dashboard is served on port `8080` (proxied through the plugger dashboard as configured in `.plugger/metadata.yaml`):

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | HTML dashboard — overall status badge, PCE host/port/org, last check time, per-endpoint breakdown with HTTP status and response detail. Auto-refreshes every 15 seconds (fixed, not configurable). |
| GET | `/api/health` | Full health state as JSON — status, `last_check`, `last_error`, `pce_host`, `pce_port`, `org_id`, `check_count`, and the raw per-endpoint `response` detail. Useful for wiring into external monitoring/alerting. |
| GET | `/healthz` | Plugger's own container liveness check — always `{"status": "healthy"}` if the process is running (see caveat above). |

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Status stuck on `unknown` | No check has completed yet — check container logs for startup errors |
| Status `unreachable` | PCE host/port not reachable from the container network, or `PCE_HOST`/`PCE_PORT` are wrong — verify network path and DNS from inside the container |
| Status `degraded` | All endpoints reachable but returning `401` — API key/secret is wrong, disabled, or expired; rotate credentials in plugger and it will pick them up automatically |
| Status `error` in the dashboard | Check container logs — this means the check itself raised an exception (not a normal HTTP failure) |
| TLS handshake failures | If the PCE uses a certificate not trusted by the container, set `PCE_TLS_SKIP_VERIFY=true` (or fix the trust chain instead, which is safer) |
| Dashboard shows old data | The page auto-refreshes every 15s; `check_count` in the JSON API confirms whether new checks are actually running |

## Notes / limits

- This plugin only measures **API reachability and authentication**, not PCE host resources (CPU, memory, disk) — despite similar naming to host-monitoring tools, there is no OS-level metric collection here.
- Checks are read-only: `GET /api/v2/health`, `GET /api/v2/node_available`, and a 1-result workload list. No data is written to the PCE.
- `/healthz` (used for plugger's own restart logic) reflects process liveness only, not PCE health — see [How it works](#how-it-works).
- The 15-second dashboard auto-refresh and the three checked endpoints are hardcoded in `main.py`, not configurable via environment variables.
- Lightweight footprint: 128 MB memory limit, 0.25 CPU limit (per `plugin.yaml`).
