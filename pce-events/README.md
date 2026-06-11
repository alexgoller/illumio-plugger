# PCE Events

Wraps [illumio-pretty-cool-events](https://github.com/alexgoller/illumio-pretty-cool-events) as a plugger plugin.

Real-time PCE event monitoring with 10+ output plugins: Slack, Teams, PagerDuty, Email, SNS, ServiceNow, Jira, Syslog, Webhooks, and more. Events are matched against configurable watcher rules using regex patterns and routed to one or more output plugins.

## Install

```bash
plugger install pce-events
```

## Setup

1. Install the plugin:
   ```bash
   plugger install pce-events
   ```

2. Copy and edit the config:
   ```bash
   cp config.yaml.example ~/.plugger/volumes/pce-events/config/config.yaml
   # Edit with your PCE credentials and output plugin settings
   ```

3. Start the plugin:
   ```bash
   plugger start pce-events
   ```

4. Open the web UI (check the assigned port):
   ```bash
   plugger status pce-events
   ```

## Configuration

This plugin uses a `config.yaml` file (not environment variables) for all settings. The config file is mounted from the host via the `/config` volume.

| Setting | Location | Description |
|---------|----------|-------------|
| `PCE_EVENTS_CONFIG` | env var, default `/config/config.yaml` | Path to the config file inside the container |

### Config File Reference

The `config.yaml` has two sections:

**`config`** -- PCE connection and web UI settings:

| Key | Default | Description |
|-----|---------|-------------|
| `pce` | -- | PCE hostname |
| `pce_port` | `8443` | PCE API port |
| `pce_api_user` | -- | API key ID |
| `pce_api_secret` | -- | API secret |
| `pce_org` | `1` | Organization ID |
| `pce_poll_interval` | `10` | Seconds between event polls |
| `pce_timeout` | `60` | API request timeout |
| `verify_tls` | `false` | Verify TLS certificates |
| `httpd` | `true` | Enable web UI |
| `httpd_listener_port` | `8443` | Web UI port |

**`watchers`** -- Map event type regex patterns to output plugins:

```yaml
watchers:
  "^sec_policy\\.":          # Match security policy events
    - plugin: PCESlack
      extra_data:
        channel: "#policy-changes"
  "^user\\.(login|logout)":  # Match user auth events
    - plugin: PCEMail
      extra_data:
        to_addr: security@example.com
  ".*":                       # Catch-all
    - plugin: PCEStdout
```

## Features

- Real-time PCE event streaming with configurable poll interval
- Regex-based event matching with multiple watchers per pattern
- Web UI for viewing events and managing watchers
- Output plugins: Slack, Teams, PagerDuty, Email, SNS, ServiceNow, Jira, Syslog, Webhooks, Stdout
- Template-based event formatting
- Event filtering by status

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Event viewer and watcher management UI (port 8443) |

## Output Plugins

| Plugin | Description |
|--------|-------------|
| `PCEStdout` | Log events to stdout |
| `PCESlack` | Send to Slack channel via bot token |
| `PCETeams` | Send to Microsoft Teams via webhook |
| `PCEMail` | Send email via SMTP |
| `PCEPagerDuty` | Create PagerDuty incidents |
| `PCEWebhook` | POST to any HTTP endpoint |
| `PCESyslog` | Forward to syslog |
| `PCESNS` | Publish to AWS SNS topic |
| `PCEServiceNow` | Create ServiceNow incidents |
| `PCEJira` | Create Jira tickets |

See `config.yaml.example` for the full configuration reference including all output plugin options.
