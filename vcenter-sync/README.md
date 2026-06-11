# vCenter Sync

> **Status: Untested** — This plugin has not been validated against a live vCenter. Use analytics mode first.

Bi-directional sync between VMware vCenter and Illumio PCE. Import VMs as unmanaged workloads with labels derived from vCenter tags and folder hierarchy. Optionally push Illumio labels back as vCenter tags.

## Install

```bash
plugger install vcenter-sync
```

## Why

VMware is the most common hypervisor in enterprise. Thousands of VMs that may not run VEN agents still need Illumio policy. vCenter already has organizational metadata (tags, folders) that maps naturally to Illumio labels.

## Modes

| Mode | Direction | What It Does |
|------|-----------|-------------|
| `analytics` (default) | Read-only | Discovers VMs, shows tag mapping, previews what would sync |
| `vcenter-to-illumio` | vCenter → PCE | Creates unmanaged workloads + applies labels from tags/folders |
| `illumio-to-vcenter` | PCE → vCenter | Pushes Illumio labels as vCenter tags |
| `bidirectional` | Both | Import + export in one cycle |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VCENTER_HOST` | _(required)_ | vCenter Server hostname or IP |
| `VCENTER_USER` | _(required)_ | Username (e.g., `administrator@vsphere.local`) |
| `VCENTER_PASSWORD` | _(required)_ | Password |
| `VCENTER_SSL_VERIFY` | `false` | Verify vCenter TLS certificate |
| `MODE` | `analytics` | `analytics`, `vcenter-to-illumio`, `illumio-to-vcenter`, `bidirectional` |
| `SYNC_INTERVAL` | `3600` | Seconds between sync cycles |
| `TAG_MAPPING` | _(default)_ | JSON: vCenter tag category → Illumio label key |
| `CREATE_UNMANAGED` | `true` | Create unmanaged workloads for VMs without VEN |
| `FOLDER_TO_LABEL` | `false` | Derive labels from VM folder hierarchy |
| `VM_FILTER` | _(empty)_ | Regex filter on VM names |

## Tag-to-Label Mapping

Default mapping (vCenter tag category → Illumio label key):

| vCenter Tag Category | Illumio Label Key |
|---------------------|-------------------|
| Application | `app` |
| Environment | `env` |
| Role | `role` |
| Location | `loc` |

Override with `TAG_MAPPING` JSON:
```bash
TAG_MAPPING='{"Business Unit": "app", "Tier": "role", "Site": "loc", "Stage": "env"}'
```

## Folder-to-Label Mapping

When `FOLDER_TO_LABEL=true`, derive labels from VM folder path:

```
/Datacenter/vm/Production/WebServers/web01
                ^^^^^^^^^^  ^^^^^^^^^^
                env=prod    role=web
```

First folder level → `env`, second level → `role`. Configurable depth mapping.

## What Gets Created in Illumio

For each vCenter VM without a matching Illumio workload:

```json
{
  "name": "web01",
  "hostname": "web01",
  "interfaces": [{"address": "10.0.1.5", "friendly_name": "eth0"}],
  "description": "Imported from vCenter: vcenter.example.com",
  "labels": [
    {"href": "/orgs/1/labels/app-payments"},
    {"href": "/orgs/1/labels/env-prod"},
    {"href": "/orgs/1/labels/role-web"}
  ]
}
```

## Features

- VM discovery via pyVmomi (all VMs, all datacenters)
- Tag reading via vSphere REST API (categories + tags + associations)
- Configurable tag category → label key mapping
- Folder hierarchy → label derivation
- Match engine: vCenter VMs ↔ Illumio workloads by IP/hostname
- Create unmanaged workloads for unmatched VMs
- Update labels on matched workloads when tags change
- Push Illumio labels back as vCenter tags
- VM name regex filter
- Dashboard with VM inventory, tag mapping, sync results
- Analytics mode for safe preview
