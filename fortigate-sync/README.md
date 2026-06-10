# FortiGate Sync

> Based on [illumio-to-fortigate-sync](https://github.com/ruckle-o/illumio-to-fortigate-sync) by ruckle-o. Extended with daemon mode, dashboard, multi-group support, and REST API address object sync.

Sync Illumio PCE workloads to FortiGate firewalls via two methods:

1. **RSSO** (RADIUS SSO) — inject workload IPs into FortiGate's auth table as dynamic group members. Policies reference the RSSO group — workloads come and go without touching firewall rules.
2. **REST API** — create persistent FortiGate address objects and address groups from Illumio workloads. Survives reboots, visible in FortiGate GUI.

Use RSSO for dynamic environments, REST API for static policy, or both.

## Install

```bash
plugger install fortigate-sync
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `FG_HOST` | _(required)_ | FortiGate hostname or IP |
| `FG_RSSO_PORT` | `1813` | RADIUS accounting port |
| `FG_RSSO_SECRET` | _(required)_ | RSSO shared secret |
| `FG_API_TOKEN` | _(empty)_ | FortiGate REST API token (for address objects) |
| `FG_VDOM` | `root` | FortiGate VDOM |
| `SYNC_MODE` | `rsso` | `rsso`, `objects`, or `both` |
| `SYNC_INTERVAL` | `300` | Seconds between sync cycles |
| `DEFAULT_RSSO_GROUP` | `ILLUMIO_WORKLOADS` | Default RSSO group name |
| `LABEL_GROUPS` | _(empty)_ | JSON: label filter → group mapping |
| `ADDRESS_PREFIX` | `illumio-` | Prefix for REST API address objects |

## Label-to-Group Mapping

Map different Illumio label combinations to different FortiGate groups:

```bash
LABEL_GROUPS='[
  {"labels": {"env": "prod", "role": "web"}, "group": "ILLUMIO_PROD_WEB"},
  {"labels": {"env": "prod", "role": "db"}, "group": "ILLUMIO_PROD_DB"},
  {"labels": {"env": "dev"}, "group": "ILLUMIO_DEV"}
]'
```

Workloads not matching any filter go to `DEFAULT_RSSO_GROUP`.

## Sync Modes

### RSSO (`rsso`)
- Sends RADIUS Accounting-Request packets to FortiGate
- IPs appear in `diagnose firewall auth list` under the RSSO group
- Sessions expire (default 480 min) — plugin re-sends Start packets each cycle
- No FortiGate config changes needed after initial RSSO connector setup

### Address Objects (`objects`)
- Creates FortiGate address objects via REST API (`/api/v2/cmdb/firewall/address`)
- Creates address groups per label group mapping
- Persistent — survives reboots, visible in FortiGate GUI
- Requires FortiGate REST API token with write permissions

### Both (`both`)
- Runs RSSO sync AND creates address objects
- Belt and suspenders approach

## FortiGate Setup

### RSSO Connector (one-time)
1. Security Fabric → External Connectors → Create New → RADIUS Single Sign-On Agent
2. Set shared secret (must match `FG_RSSO_SECRET`)
3. Enable "Send RADIUS Responses"
4. Create a user group: User & Authentication → User Groups → Create New → Fortinet Single Sign-On (FSSO) type
5. Add the RSSO group name (must match `DEFAULT_RSSO_GROUP` or group names in `LABEL_GROUPS`)
6. Reference the group in firewall policies

### REST API Token (optional, for address objects)
1. System → Administrators → Create New → REST API Admin
2. Set trusted hosts, assign admin profile with firewall object write permissions
3. Copy the generated API token → set as `FG_API_TOKEN`

## Features

- Daemon mode with configurable sync interval (vs cron with the original script)
- Multiple RSSO groups from one plugin instance
- REST API address objects and groups (persistent)
- Dashboard with sync status, workload table, group detail
- State tracking with diff-based sync (only send changes)
- Auto-cleanup: removed workloads get RSSO Stop + address object deletion
- Dry-run support via API

## Credits

RSSO sync approach based on [illumio-to-fortigate-sync](https://github.com/ruckle-o/illumio-to-fortigate-sync) by [ruckle-o](https://github.com/ruckle-o).
