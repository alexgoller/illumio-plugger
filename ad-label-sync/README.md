# AD Label Sync

> **Status: Untested** — This plugin has not been validated against a live Active Directory environment. Please report issues.

Connects to Active Directory via LDAP, discovers computer objects, and
maps AD attributes (OU path, group membership, location, extension
attributes) to Illumio labels. Supports two modes: analytics-only
feasibility analysis and active label sync to the PCE.

## Install

```
plugger install ad-label-sync
```

## Prerequisites

This plugin requires LDAP access to an Active Directory domain controller.

1. Create a service account with read access to computer objects.
2. Set `LDAP_HOST` to your domain controller hostname or IP.
3. Set `LDAP_BIND_DN` and `LDAP_BIND_PASSWORD` for authentication.
4. Set `LDAP_BASE_DN` to the search base (e.g., `DC=corp,DC=example,DC=com`).

For LDAPS (encrypted), set `LDAP_SSL=true` and `LDAP_PORT=636`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `LDAP_HOST` | _(empty)_ | AD domain controller hostname |
| `LDAP_PORT` | `389` | LDAP port (389 for LDAP, 636 for LDAPS) |
| `LDAP_BIND_DN` | _(empty)_ | Bind DN for authentication |
| `LDAP_BIND_PASSWORD` | _(empty)_ | Bind password (secret) |
| `LDAP_BASE_DN` | _(empty)_ | Search base DN |
| `LDAP_FILTER` | `(objectClass=computer)` | LDAP search filter |
| `LDAP_SSL` | `false` | Use LDAPS (TLS) |
| `MODE` | `analytics` | `analytics` = read-only analysis, `sync` = apply labels |
| `SCAN_INTERVAL` | `3600` | Seconds between AD scans |
| `MAPPING_RULES` | _(built-in)_ | Custom mapping rules as JSON array |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for PCE |

### Analytics vs Sync Mode

- **Analytics** (default): Connects to AD, pulls the computer tree, and
  shows what labels would be derived from each computer's attributes.
  Nothing is written to the PCE. Use this to validate mapping rules.
- **Sync**: Applies discovered labels to matching PCE workloads (matched
  by hostname). Only use after verifying analytics results.

### Mapping Rules

Rules map AD attributes to Illumio label keys. Each rule has:
- `source`: AD attribute (`ou_path`, `group`, `location`, `description`, `extensionAttribute1`, etc.)
- `pattern`: Regex to match against the attribute value
- `target`: Illumio label key (`role`, `app`, `env`, `loc`)
- `value`: Label value to assign (`$0` = matched text, `$1` = first capture group)
- `priority`: Higher priority rules override lower ones for the same target

Built-in defaults derive env from OU path (prod/dev/staging), role from
OU or group membership (web/db/processing), loc from the AD location
field, and app from `extensionAttribute1`. Override with `MAPPING_RULES`.

## Features

- Discovers AD computers via LDAP with configurable search filter
- Configurable attribute-to-label mapping with regex and priority
- OU path, group membership, location, and extension attribute support
- Analytics mode for safe, read-only feasibility analysis
- Sync mode to apply labels to PCE workloads matched by hostname
- OU tree visualization and label coverage statistics
- Dashboard with per-computer match detail and suggested labels
