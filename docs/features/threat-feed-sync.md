# Threat Feed Sync

**Status:** Proposed
**Priority:** High — every SOC wants automated threat intel blocking
**Complexity:** Medium
**Dependencies:** PCE IP Lists API, external threat feed APIs

## Problem

Illumio has IP lists for allow/deny but no built-in mechanism to ingest external threat intelligence feeds. The existing `illumiolabs/illumio-ip-threat-list-ingestion` tool is a basic Python script from ~2019 with no UI and limited feed support. Customers need to block known-bad IPs automatically.

## Solution

A plugin that ingests threat intelligence feeds from multiple sources and syncs them to Illumio IP Lists, creating deny rules that block traffic to/from known-bad IPs.

## Supported Feed Sources

### Open/Free Feeds
| Feed | Type | Content | Update Frequency |
|------|------|---------|-----------------|
| **Abuse.ch** | HTTPS/CSV | Botnet C2, malware, ransomware IPs | Hourly |
| **AlienVault OTX** | REST API | Multi-category threat intel | Real-time |
| **Emerging Threats** | HTTPS/CSV | Known compromised IPs | Daily |
| **Spamhaus DROP** | HTTPS/TXT | Hijacked IP ranges | Daily |
| **CINS Score** | HTTPS/TXT | Active threat IPs | Hourly |
| **Tor Exit Nodes** | HTTPS/CSV | Tor exit node IPs | Hourly |
| **Feodo Tracker** | HTTPS/CSV | Banking trojan C2 | Every 5 min |

### Commercial/Enterprise Feeds
| Feed | Type | Auth |
|------|------|------|
| **CrowdStrike TI** | REST API | API key |
| **MISP** | REST API | API key |
| **ThreatConnect** | REST API | API key |
| **Recorded Future** | REST API | API key |

### Standard Formats
| Format | Description |
|--------|-------------|
| **STIX/TAXII 2.1** | Industry standard threat intel exchange |
| **CSV/TXT** | Simple IP-per-line or CSV with columns |
| **JSON** | Custom JSON feeds |

## How It Works

1. **Poll feeds** on configurable schedule (per-feed intervals)
2. **Parse indicators** — extract IP addresses, CIDRs, FQDNs
3. **Categorize** — map to feed categories (C2, ransomware, scanning, botnet, tor)
4. **Create/update Illumio IP Lists** — one IP list per category or per feed
5. **Apply TTL** — auto-expire indicators after configurable duration
6. **Dashboard** — feed health, entry counts, last sync, delta tracking

## IP List Naming Convention

```
threat-feed-{category}          # By category
threat-feed-abusech-botnet      # By feed + category
threat-feed-tor-exit-nodes      # Specific feed
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `FEEDS_CONFIG` | `/data/feeds.yaml` | Feed configuration file path |
| `SYNC_INTERVAL` | `3600` | Default seconds between feed syncs |
| `DEFAULT_TTL` | `86400` | Default indicator TTL in seconds (24h) |
| `MAX_ENTRIES_PER_LIST` | `10000` | Max IPs per Illumio IP List |
| `IP_LIST_PREFIX` | `threat-` | Prefix for created IP Lists |
| `DRY_RUN` | `false` | Preview without creating IP Lists |
| `DEDUP` | `true` | Deduplicate IPs across feeds |

### feeds.yaml

```yaml
feeds:
  - name: abusech-botnet
    url: https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt
    format: txt
    category: botnet-c2
    interval: 3600
    ttl: 86400
    enabled: true

  - name: spamhaus-drop
    url: https://www.spamhaus.org/drop/drop.txt
    format: txt
    category: hijacked
    interval: 86400
    ttl: 604800
    enabled: true

  - name: alienvault-otx
    type: otx
    api_key: "${OTX_API_KEY}"
    pulses:
      - "malware-iocs"
      - "ransomware-c2"
    category: malware
    interval: 3600
    enabled: true

  - name: crowdstrike
    type: crowdstrike
    client_id: "${CS_CLIENT_ID}"
    client_secret: "${CS_CLIENT_SECRET}"
    category: apt
    interval: 1800
    enabled: false

  - name: misp
    type: misp
    url: https://misp.example.com
    api_key: "${MISP_API_KEY}"
    tags: ["tlp:white", "type:ip-dst"]
    category: misp
    interval: 3600
    enabled: false

  - name: custom-csv
    url: https://internal.example.com/blocklist.csv
    format: csv
    ip_column: 0
    skip_header: true
    category: internal
    interval: 3600
    enabled: false

  - name: stix-taxii
    type: taxii
    url: https://taxii.example.com/taxii2/
    collection: "threat-indicators"
    category: stix
    interval: 3600
    enabled: false
```

## Dashboard

- **Feed Status** — per-feed: last sync, entry count, errors, next sync
- **IP List Summary** — per IP list: name, entry count, last updated
- **Recent Changes** — IPs added/removed in last sync
- **Stats** — total unique IPs blocked, feeds active, sync errors
- **Feed Health** — green/yellow/red per feed based on last sync success

## Illumio Integration

### IP List Creation
```python
# Create an IP list for each category
pce.post("/sec_policy/draft/ip_lists", json={
    "name": "threat-botnet-c2",
    "description": "Botnet C2 IPs from Abuse.ch — auto-synced by threat-feed-sync",
    "ip_ranges": [
        {"from_ip": "1.2.3.4", "exclusion": False},
        {"from_ip": "5.6.7.0/24", "exclusion": False},
    ]
})
```

### Deny Rule Suggestion
The plugin can suggest (or auto-create) deny rules:
```
deny_rule: All Workloads → threat-botnet-c2 (IP List)
deny_rule: All Workloads → threat-ransomware (IP List)
```

## TTL / Indicator Expiry

Indicators have a TTL (default 24h). After expiry:
- IP is removed from the Illumio IP List
- Logged in the audit trail
- Can be re-added on next feed sync if still present

This prevents IP lists from growing indefinitely with stale indicators.

## Why This Matters

- **Every SOC wants this** — automated threat intel is table stakes
- **Replaces abandoned tool** — illumiolabs version is unmaintained
- **Multi-feed** — not locked to one vendor
- **Automatic expiry** — IP lists don't grow forever
- **Standard formats** — STIX/TAXII support for enterprise feeds
- **Deny rule integration** — not just IP lists, but actionable policy
