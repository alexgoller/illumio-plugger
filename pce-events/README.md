# PCE Events Plugin

Wraps [illumio-pretty-cool-events](https://github.com/alexgoller/illumio-pretty-cool-events) as a plugger plugin.

Real-time PCE event monitoring with 10+ output plugins: Slack, Teams, PagerDuty, Email, SNS, ServiceNow, Jira, Syslog, Webhooks, and more.

## Setup

1. Build the image:
   ```bash
   docker build -t pce-events:latest .
   ```

2. Install the plugin:
   ```bash
   plugger install plugin.yaml
   ```

3. Copy and edit the config:
   ```bash
   cp config.yaml.example ~/.plugger/volumes/pce-events/config/config.yaml
   # Edit with your PCE credentials and output plugin settings
   ```

4. Start the plugin:
   ```bash
   plugger start pce-events
   ```

5. Open the web UI (check the assigned port):
   ```bash
   plugger status pce-events
   ```

## Configuration

The plugin reads its configuration from `/config/config.yaml` inside the container, which is mounted from `~/.plugger/volumes/pce-events/config/` on the host.

See `config.yaml.example` for all available options including Slack, Teams, PagerDuty, and webhook configuration.
