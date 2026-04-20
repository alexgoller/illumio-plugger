# JavaScript Plugin Template

A Node.js plugin template for the Illumio Plugger framework. Zero external dependencies — uses only Node.js built-in modules (`http`, `https`).

## Quick Start

```bash
# Scaffold (or copy this template)
plugger create my-plugin -t javascript

# Edit the plugin logic
cd my-plugin
vim main.js

# Build and install
docker build -t my-plugin:latest .
plugger install plugin.yaml
plugger start my-plugin
```

## Structure

```
my-plugin/
  main.js                   # Plugin code (edit this)
  package.json              # Node.js package metadata
  Dockerfile                # Container image
  plugin.yaml               # Plugger install manifest
  .plugger/metadata.yaml    # In-container metadata (ports, config, volumes)
```

## PCE API Client

The template includes a built-in PCE client using `node:https` — no npm packages needed:

```javascript
// GET workloads
const { status, data } = await pce.get("/workloads", { max_results: 100 });

// GET labels
const labels = await pce.get("/labels");

// POST (create a label)
await pce.post("/labels", { key: "role", value: "web" });

// PUT (update a workload)
await pce.put("/workloads/abc123", { labels: [...] });
```

## Plugin Modes

Edit the `doWork()` function for daemon/cron logic, or `handleEvent()` for event-driven plugins.

- **Daemon** (default): Calls `doWork()` every `POLL_INTERVAL` seconds, runs HTTP server
- **Cron**: Calls `doWork()` once, exits
- **Event**: Reads `PLUGGER_EVENT_PAYLOAD`, calls `handleEvent()`, exits

## Dashboard

Includes a Tailwind CSS dark-theme dashboard served at `/`. Shows poll count, last poll time, and current state. Auto-refreshes every 10 seconds.

## Why Zero Dependencies?

Node.js built-ins cover everything needed for a plugin:
- `https` for PCE API calls (Basic auth, TLS)
- `http` for the dashboard/health server
- `URL`/`URLSearchParams` for query strings
- `Buffer` for Base64 encoding

No `npm install`, no `node_modules`, no supply chain risk. The Docker image stays small and builds fast.
