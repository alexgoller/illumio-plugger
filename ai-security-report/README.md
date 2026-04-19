# AI Security Report

Comprehensive AI-powered security posture analysis for Illumio PCE. Collects workloads, traffic, policy, and process data, runs 10 security analysis categories, scores each 0-100, and presents an interactive dashboard with charts, heatmaps, compliance mapping, and PDF export.

## Install

```bash
plugger install ai-security-report
```

## Security Analysis Categories

| Category | Weight | What It Checks |
|----------|--------|----------------|
| Enforcement Coverage | 15% | idle/visibility/selective/full distribution |
| OS Lifecycle Risk | 8% | End-of-life operating systems (20+ patterns) |
| Label Hygiene | 12% | Missing app/env/role/loc labels |
| Environmental Separation | 15% | Prod↔Dev/Test/Staging traffic violations |
| Risky Services | 10% | FTP, Telnet, RDP sprawl, SMB, unencrypted protocols |
| Policy Analysis | 12% | Any↔any rules, broad port ranges, disabled rules |
| Traffic Anomalies | 8% | High-volume blocked traffic, IP-only flows |
| Lateral Movement Surface | 10% | SSH/RDP sprawl, hub workloads |
| Agent Health | 5% | Offline agents, stale heartbeats |
| Compliance Mapping | 5% | NIST CSF, CIS Controls, PCI-DSS alignment |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL` | `86400` | Seconds between scans (minimum 3600) |
| `LOOKBACK_DAYS` | `7` | Days of traffic history to analyze |
| `MAX_TRAFFIC_RESULTS` | `100000` | Maximum traffic flows to query |
| `PROCESS_SAMPLE_SIZE` | `50` | Workloads to sample for process data |
| `REPORT_RETENTION` | `30` | Historical reports to keep |
| `AI_PROVIDER` | _(empty)_ | `anthropic`, `openai`, or `ollama` |
| `AI_API_KEY` | _(empty)_ | API key for the LLM provider |
| `AI_MODEL` | _(auto)_ | Model override |
| `AI_BASE_URL` | _(empty)_ | Custom endpoint for Ollama |

## Features

- Overall security score (0-100) with letter grade (A-F)
- 10 independent analysis categories with weighted scoring
- AI-generated executive summary and per-section narratives (optional)
- AI-prioritized remediation roadmap
- Environment separation heatmap
- Compliance mapping to NIST CSF, CIS Controls, PCI-DSS
- Historical report storage with trend comparison
- Interactive dashboard with Chart.js visualizations
- PDF export via browser print
- Severity filtering and search across all findings
- Works without AI — all data analysis and scoring is built-in

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/healthz` | Health check |
| GET | `/api/report` | Latest report data |
| GET | `/api/report/history` | Historical report list |
| GET | `/api/report/{ts}` | Specific historical report |
| POST | `/api/scan` | Trigger immediate scan |
| GET | `/api/config` | Configuration (no secrets) |
