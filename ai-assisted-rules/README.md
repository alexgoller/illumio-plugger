# ai-assisted-rules

[![Plugin](https://img.shields.io/badge/plugger-ai--assisted--rules-blue)](https://alexgoller.github.io/illumio-plugger/)
[![Version](https://img.shields.io/badge/version-0.2.0-green)]()
[![Mode](https://img.shields.io/badge/mode-daemon-orange)]()

AI-powered policy engine for Illumio PCE. Analyzes blocked traffic, generates tiered rule suggestions, detects infrastructure patterns, models segmentation maturity, simulates breach radius, and provisions rules to PCE draft -- all from a single dashboard.

Works standalone with built-in heuristics. Optionally connects to an LLM (Anthropic Claude, OpenAI GPT, or Ollama) for deeper reasoning about policy decisions.

## Install

```bash
plugger install ai-assisted-rules
```

## Features at a Glance

| Feature | Tab | Description |
|---|---|---|
| **Application Policy** | Application Policy | Per-app view: intra-scope, extra-scope incoming/outgoing, IP traffic. Three security tiers per scope. One-click provision to PCE draft. |
| **Infrastructure Detection** | Infrastructure | Auto-detect high fan-out/fan-in apps (monitoring, DNS, LDAP). Consolidated broad rules instead of per-pair. |
| **Label Gap Detection** | Label Gaps | Find workloads missing role labels. Traffic + hostname heuristic suggestions. Optional AI suggestions. One-click label application. |
| **Blocked Traffic Analysis** | Blocked Traffic | Full table of all blocked/potentially-blocked app\|env pairs with services, connections, host counts. |
| **Deny Layer Catalog** | Deny Layer | Pre-built catalog of lateral movement patterns (SMB, RDP, Telnet, FTP, VNC, WinRM). Traffic evidence for each. |
| **Segmentation Maturity** | Maturity | Six-stage maturity model (Discovery through Hardened) with weighted scoring across discovery, classification, first policy, deny layer, tightening, and coverage. |
| **Breach Radius Simulation** | Breach Radius | Select any app\|env from a live dropdown, simulate compromise. Walk the policy graph outbound to find reachable groups with hop depth and services. |
| **Traffic Classification** | Blocked Traffic | Classify each blocked pair as intra-scope gap, governance (deny working), security concern, change-driven, or noise. |
| **Charts** | Charts | Bar charts of top blocked pairs and blocked services. |
| **Stale Rules** | Stale Rules | Find disabled rulesets, empty rulesets, disabled rules within active rulesets. |

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `POLL_INTERVAL` | No | `3600` | Seconds between analysis runs. |
| `LOOKBACK_HOURS` | No | `24` | Hours of traffic history to analyze. |
| `MAX_RESULTS` | No | `10000` | Maximum flows per Explorer API query. |
| `AI_PROVIDER` | No | _(empty)_ | AI provider: `anthropic`, `openai`, or `ollama`. Leave empty for heuristic-only mode. |
| `AI_API_KEY` | No | _(empty)_ | API key for the AI provider (not needed for Ollama). |
| `AI_MODEL` | No | _(auto)_ | Model name override. Defaults: `claude-sonnet-4-20250514` (Anthropic), `gpt-4o` (OpenAI), `llama3` (Ollama). |
| `AI_BASE_URL` | No | _(empty)_ | Custom API endpoint. Required for Ollama (e.g., `http://localhost:11434`). |
| `MIN_FLOWS` | No | `10` | Minimum blocked flows to consider a pair significant (below this is classified as noise). |
| `PCE_TLS_SKIP_VERIFY` | No | `true` | Skip TLS certificate verification for the PCE. |

PCE connection variables (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`, `PCE_API_SECRET`) are injected automatically by Plugger.

## AI Provider Configuration

AI features are optional. Without an AI provider, the plugin still performs full analysis using built-in heuristics: traffic grouping, rule generation, label gap detection, maturity scoring, and breach radius simulation all work without AI.

### Anthropic (Claude)

```bash
plugger env set ai-assisted-rules AI_PROVIDER=anthropic
plugger env set ai-assisted-rules AI_API_KEY=sk-ant-...
plugger env set ai-assisted-rules AI_MODEL=claude-sonnet-4-20250514   # optional
```

### OpenAI (GPT)

```bash
plugger env set ai-assisted-rules AI_PROVIDER=openai
plugger env set ai-assisted-rules AI_API_KEY=sk-...
plugger env set ai-assisted-rules AI_MODEL=gpt-4o                     # optional
```

### Ollama (Local)

```bash
plugger env set ai-assisted-rules AI_PROVIDER=ollama
plugger env set ai-assisted-rules AI_BASE_URL=http://localhost:11434
plugger env set ai-assisted-rules AI_MODEL=llama3                     # optional
```

When AI is enabled, additional capabilities unlock:
- **AI Analyze** buttons on each application policy card for LLM-powered approve/review/reject recommendations.
- **AI Analyze All** for batch analysis of label gaps.
- Per-rule AI reasoning with confidence scores and suggested modifications.
- Deny pattern risk narratives.
- Breach radius security assessments.
- Maturity coaching with prioritized next steps.

## Dashboard Tabs Explained

### Application Policy

The primary view. Each app|env pair gets a card showing:

- **Intra-Scope**: Blocked traffic within the same app|env. Shows clean services and risky services (flagged with a warning). Displays three security tier summaries:
  - **Ringfencing** (Low): All workloads to all workloads, all clean services. Simple ring-fence around the scope.
  - **App Tiered** (Medium): Role-to-role rules. Respects application architecture (web -> db, processing -> cache). Default for provisioning.
  - **High Security**: Role-to-role, only observed services. Full micro-segmentation.

- **Extra-Scope Incoming**: Other app|env pairs sending traffic into this application.
- **Extra-Scope Outgoing**: This application sending traffic to other app|env pairs.
- **IP Traffic Incoming**: Bare IP sources hitting this application (unlabeled traffic).

Each card has **Provision** buttons (Ringfence / Tiered / High) that create the ruleset as PCE draft policy with a single click.

Risky services (FTP, Telnet, RDP, SMB, VNC, WinRM) are automatically split into a separate "FOR REVIEW" ruleset regardless of which tier you provision.

### Infrastructure

Apps with high fan-out (one app connects to many others) or high fan-in (many apps connect to one) are classified as infrastructure. Instead of generating per-pair rules, the plugin creates consolidated broad rulesets:

- **Outbound infra**: "monitoring -> All on NRPE/SNMP"
- **Inbound infra**: "All -> AD on LDAP/Kerberos"

The threshold is configurable (default: 4+ distinct app|env destinations or sources).

### Label Gaps

Workloads missing role labels cannot use Application Tiered or High Security policies. This tab shows:

- Hostname, current app|env, what label dimensions are missing.
- **Heuristic suggestion**: Based on traffic patterns (what ports the workload serves) and hostname matching. Confidence score and reasoning.
- **AI suggestion**: LLM analysis combining hostname, process data, listening ports, and existing labels.
- **Apply button**: Set the role label directly on the PCE workload.

### Deny Layer

A curated catalog of lateral movement patterns that should typically be blocked cross-scope:

| ID | Pattern | Port | Risk |
|---|---|---|---|
| DENY-001 | Cross-scope SMB | 445/tcp | Critical |
| DENY-002 | Cross-scope RDP | 3389/tcp | High |
| DENY-003 | Cross-scope WinRM | 5985/tcp | High |
| DENY-004 | Cross-scope VNC | 5900/tcp | High |
| DENY-005 | Cross-scope Telnet | 23/tcp | Critical |
| DENY-006 | Cross-scope FTP | 21/tcp | Critical |
| DENY-007 | Cross-scope rsh/rlogin | 514/tcp | Critical |

For each pattern, the plugin reports how many cross-scope flows use that port and which app|env pairs are affected. This provides evidence for deny rule decisions.

### Segmentation Maturity

Six-stage maturity model with weighted scoring:

| Stage | Weight | What It Measures |
|---|---|---|
| Discovery | 10% | Workloads found and traffic analyzed. |
| Classification | 20% | Percentage of workloads with app + env labels. |
| First Policy | 20% | Whether any rules have been suggested/provisioned. |
| Deny Layer | 15% | How many deny catalog patterns are enabled. |
| Tightening | 15% | How many suggested rules have role-level granularity (L2/L3 vs L1). |
| Coverage | 20% | Percentage of workloads in full enforcement mode. |

Overall score maps to a stage:

| Score | Stage |
|---|---|
| 0-19% | Starting |
| 20-39% | Discovering |
| 40-59% | Progressing |
| 60-74% | Protected |
| 75-89% | Enforced |
| 90-100% | Hardened |

### Breach Radius Simulation

Select any app|env from a live dropdown populated from PCE workloads. Click **Simulate** to compute the blast radius:

- The plugin walks the policy graph outbound from the target, following all blocked traffic pairs and suggested rule connections.
- Stops at 5 hops deep.
- Shows each reachable group with hop distance, services, and connection count.
- Color-coded by hop distance: red (1 hop), orange (2), yellow (3), gray (4+).

This answers "if this app|env is compromised, what else can the attacker reach?"

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/report` | Full analysis state: blocked pairs, auto rules, inter rules, infra rules, app policies, label gaps, deny layer, maturity, breach radius, AI analyses. |
| `GET` | `/api/ai/config` | AI provider configuration (no secrets). |
| `GET` | `/api/deny-layer` | Deny layer catalog with traffic evidence. |
| `GET` | `/api/maturity` | Current maturity scores. |
| `GET` | `/api/app-groups` | Sorted list of app\|env tuples from PCE workloads (for breach radius dropdown). |
| `POST` | `/api/ai/analyze` | AI-analyze a rule. Body: `{"index": 0, "scope": "intra"}` or `{"index": 0, "scope": "inter"}`. |
| `POST` | `/api/ai/suggest-label` | AI-suggest a role label. Body: `{"index": 0}`. |
| `POST` | `/api/labels/apply` | Apply a role label to a workload. Body: `{"workload_href": "/orgs/1/workloads/abc", "role": "web"}`. |
| `POST` | `/api/breach-radius` | Simulate breach radius. Body: `{"target": "myapp\|production"}`. |
| `POST` | `/api/provision/{index}/{tier}` | Provision intra-scope rule to PCE draft. Tier: `low`, `medium`, `high`, or `review`. |
| `POST` | `/api/provision/inter/{index}/{tier}` | Provision inter-scope rule. Tier: `level1`, `level2`, `level3`, or `review`. |
| `POST` | `/api/provision/infra/{index}` | Provision infrastructure rule to PCE draft. |
| `GET` | `/healthz` | Health check. |

## One-Click Provisioning to PCE Draft

All suggested rules can be provisioned to the PCE as draft policy directly from the dashboard. The plugin:

1. Builds the complete ruleset JSON (name, description, scopes, rules, ingress services, providers, consumers, resolve_labels_as).
2. POSTs to `/sec_policy/draft/rule_sets` on the PCE.
3. The ruleset appears in the PCE UI under draft policy, ready for review and provisioning.

For intra-scope rules, three tiers are available:
- **Ringfence** (low): `All workloads` -> `All workloads` within scope, clean services.
- **Tiered** (medium): `Role A` -> `Role B` within scope, all observed services per tier.
- **High** (high): `Role A` -> `Role B` within scope, only the specific services observed for that role pair.

For inter-scope (extra-scope) rules, the Illumio extra-scope model is used:
- Ruleset is scoped to the **destination** app|env.
- Consumers use extra-scope label resolution (resolved globally).
- Providers resolve within scope (intra-scope).

Risky services are always split into a separate "FOR REVIEW" ruleset. Cross-environment traffic is always flagged for review.

## Architecture

The plugin consists of three modules:

| File | Purpose |
|---|---|
| `main.py` | Core analysis engine: traffic queries, blocked pair grouping, tiered rule generation, infrastructure detection, inter-scope suggestions, deny layer, maturity model, breach radius, app policy builder, HTTP server, dashboard HTML. |
| `ai_advisor.py` | LLM interface: Anthropic/OpenAI/Ollama clients, prompt templates for rule analysis, label suggestions, deny pattern narratives, breach radius assessments, maturity coaching. |
| `label_advisor.py` | Heuristic label detection: traffic-based role inference (port -> role mapping), hostname pattern matching, gap analysis across all workloads. |

## Resources

- Memory limit: 512 MB
- CPU limit: 0.5 cores
