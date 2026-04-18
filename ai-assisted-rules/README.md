# AI-Assisted Rules

Policy advisor that analyzes blocked traffic patterns and recommends
firewall rules. Works standalone with heuristic analysis, and optionally
uses an LLM (Anthropic Claude, OpenAI GPT, or Ollama) for deeper reasoning
about whether blocked traffic should be allowed.

## Install

```
plugger install ai-assisted-rules
```

## Prerequisites

AI features are optional. Without an AI provider configured, the plugin
still identifies blocked traffic, stale rules, and generates rule
suggestions using built-in heuristics.

To enable AI-powered analysis, configure one of:

**Anthropic (Claude)**
```
AI_PROVIDER=anthropic
AI_API_KEY=sk-ant-...
AI_MODEL=claude-sonnet-4-20250514    # optional, uses default model
```

**OpenAI (GPT)**
```
AI_PROVIDER=openai
AI_API_KEY=sk-...
AI_MODEL=gpt-4o                     # optional
```

**Ollama (local)**
```
AI_PROVIDER=ollama
AI_BASE_URL=http://localhost:11434   # Ollama server URL
AI_MODEL=llama3                      # model name
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL` | `300` | Seconds between analysis runs |
| `LOOKBACK_HOURS` | `24` | Hours of traffic history to analyze |
| `MAX_RESULTS` | `10000` | Maximum flows per query |
| `AI_PROVIDER` | _(empty)_ | AI provider: `anthropic`, `openai`, or `ollama` |
| `AI_API_KEY` | _(empty)_ | API key for the AI provider (not needed for Ollama) |
| `AI_MODEL` | _(empty)_ | Model name override |
| `AI_BASE_URL` | _(empty)_ | Custom API endpoint (required for Ollama) |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS certificate verification |

## Features

- Identifies blocked and potentially blocked traffic patterns
- Groups traffic by app|env label pairs for segmentation analysis
- Detects stale active rules with no matching traffic
- Generates PCE-ready rule JSON for intra-app and inter-app flows
- Consolidated infrastructure ruleset suggestions (DNS, NTP, LDAP, monitoring)
- Per-app policy view with incoming/outgoing flow breakdown
- Label gap detection for workloads missing labels
- Optional LLM analysis with Illumio best-practice context
- Uses `illumio` Python SDK for PCE connectivity
