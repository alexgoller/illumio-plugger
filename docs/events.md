# Event-Driven Architecture

Plugger supports event-driven plugins that spawn ephemeral containers in response to webhooks. This enables reactive automation: when something happens on the PCE (or any external system), a plugin container runs to handle it.

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  PCE Events  │────→│   pce-events     │────→│  Plugger Webhook    │
│  PCE Traffic │     │  (polling +      │     │  /api/events/trigger│
│              │     │   matching)      │     │                     │
└──────────────┘     └──────────────────┘     └──────────┬──────────┘
                                                         │
                     ┌──────────────────┐                │ matches
                     │  Any webhook     │────────────────┤ event_type
                     │  source          │                │
                     └──────────────────┘                ▼
                                              ┌─────────────────────┐
                                              │  Spawn ephemeral    │
                                              │  container with     │
                                              │  PLUGGER_EVENT_     │
                                              │  PAYLOAD injected   │
                                              └─────────────────────┘
```

Plugger is the container orchestrator. It doesn't poll the PCE itself — it receives events via webhook and spawns containers. This means:

- **pce-events** handles PCE API polling, event matching, throttling
- **Plugger** handles container lifecycle, credential injection, cleanup
- **Any webhook source** can trigger event plugins — not just Illumio

## Webhook Endpoint

### `POST /api/events/trigger`

Receives a JSON event and dispatches to matching plugins.

**Request:**

```bash
curl -X POST http://localhost:8800/api/events/trigger \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "workload.create",
    "timestamp": "2026-04-10T12:00:00Z",
    "resource": {
      "href": "/orgs/1/workloads/abc123",
      "hostname": "web-server-01"
    }
  }'
```

**Response:**

```json
{
  "event_type": "workload.create",
  "triggered": ["workload-tagger", "cmdb-sync"],
  "skipped": ["traffic-monitor"],
  "errors": {}
}
```

### `GET /api/events/stats`

Returns per-plugin event statistics.

```json
{
  "plugins": {
    "workload-tagger": {
      "running": 1,
      "triggered": 42,
      "success": 40,
      "failed": 2
    }
  },
  "token": "abc123..."
}
```

## Authentication

The webhook endpoint requires authentication to prevent unauthorized event injection.

### Bearer Token

Set in config:

```yaml
plugger:
  webhookToken: "your-secret-token"
```

Or let plugger auto-generate one at startup (printed to stdout).

**Usage:**

```bash
# Header
curl -H "Authorization: Bearer YOUR_TOKEN" ...

# Query parameter
curl "http://localhost:8800/api/events/trigger?token=YOUR_TOKEN" ...
```

### Security Recommendations

- Always set an explicit `webhookToken` in production
- Use HTTPS (put a reverse proxy like nginx/caddy in front of plugger)
- Restrict network access to the webhook endpoint
- Use Docker network isolation — pce-events and plugger on the same Docker network

## Connecting pce-events

[Pretty Cool Events](https://github.com/alexgoller/illumio-pretty-cool-events) is the recommended event source. It polls the PCE, matches events against watchers, and forwards via webhook.

### Configuration

In the pce-events `config.yaml`, add a webhook watcher:

```yaml
# Forward all events to plugger
watchers:
  ".*":
    - plugin: PCEWebhook
      extra_data:
        url: http://plugger-dashboard:8800/api/events/trigger
        bearer_token: YOUR_PLUGGER_TOKEN

# Or specific event types
watchers:
  "workload\\.create|workload\\.update":
    - plugin: PCEWebhook
      extra_data:
        url: http://plugger-dashboard:8800/api/events/trigger
        bearer_token: YOUR_PLUGGER_TOKEN

  "sec_policy\\.provision":
    - plugin: PCEWebhook
      extra_data:
        url: http://plugger-dashboard:8800/api/events/trigger
        bearer_token: YOUR_PLUGGER_TOKEN
```

### Traffic Events

pce-events can also monitor traffic flows and trigger plugins when traffic patterns match:

```yaml
traffic_watchers:
  - name: blocked-traffic-alert
    src_include: ".*"
    dst_include: ".*"
    service_include: "443"
    policy_decision: blocked
    plugin: PCEWebhook
    extra_data:
      url: http://plugger-dashboard:8800/api/events/trigger
      bearer_token: YOUR_TOKEN
```

## Writing Event Plugins

### Plugin Manifest

```yaml
apiVersion: plugger/v1
name: workload-tagger
version: 1.0.0
image: workload-tagger:latest

schedule:
  mode: event

events:
  types:
    - workload.create
    - workload.update
    - "*"                  # catch all events

resources:
  memoryLimit: 128m
  cpuLimit: "0.25"
```

### Plugin Code

The event payload is in `PLUGGER_EVENT_PAYLOAD`:

**Python:**
```python
import json, os
from illumio import PolicyComputeEngine

event = json.loads(os.environ["PLUGGER_EVENT_PAYLOAD"])
pce = PolicyComputeEngine(url=os.environ["PCE_HOST"], port=os.environ["PCE_PORT"])
pce.set_credentials(username=os.environ["PCE_API_KEY"], password=os.environ["PCE_API_SECRET"])

if event["event_type"] == "workload.create":
    href = event["resource"]["href"]
    # React to the event...

# Exit — container is cleaned up automatically
```

**Shell:**
```bash
#!/bin/sh
EVENT_TYPE=$(echo "$PLUGGER_EVENT_PAYLOAD" | jq -r '.event_type')
RESOURCE=$(echo "$PLUGGER_EVENT_PAYLOAD" | jq -r '.resource.href')

echo "Processing $EVENT_TYPE for $RESOURCE"
# React...
```

### Container Lifecycle

For each matching event:
1. New container created with unique name (`plugger-{name}-evt-{n}`)
2. Started with all PCE env vars + `PLUGGER_EVENT_PAYLOAD`
3. Runs to completion
4. Exit code captured (0 = success, non-zero = logged as error)
5. Container removed

### Concurrency

Max 5 concurrent containers per event plugin. If the limit is reached, incoming events are dropped with an error log. For high-frequency events, consider:

- A daemon plugin that receives events via a queue instead
- Batching events in pce-events before forwarding
- Increasing the concurrency limit (not yet configurable, hardcoded to 5)

## Other Webhook Sources

Plugger's event endpoint works with any system that can POST JSON with an `event_type` field:

```bash
# GitLab webhook
curl -X POST http://plugger:8800/api/events/trigger?token=XXX \
  -d '{"event_type": "push", "project": "my-app", "ref": "main"}'

# Custom monitoring
curl -X POST http://plugger:8800/api/events/trigger?token=XXX \
  -d '{"event_type": "alert.cpu_high", "host": "server-01", "value": 95}'
```

As long as your event plugin's `events.types` includes the `event_type` value, it will be triggered.
