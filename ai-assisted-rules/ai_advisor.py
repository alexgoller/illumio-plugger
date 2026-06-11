"""
AI Advisor — LLM-powered policy analysis for Illumio PCE.

Supports Anthropic (Claude), OpenAI (GPT), and Ollama-compatible APIs.
Analyzes blocked traffic patterns and recommends whether to create rules.
"""

import json
import logging
import os

log = logging.getLogger("ai_advisor")

ILLUMIO_BEST_PRACTICES = """You are an Illumio PCE security policy advisor. You analyze blocked network traffic patterns and recommend whether firewall rules should be created.

## Illumio Policy Best Practices

1. **ZERO TRUST**: Default deny. Only allow traffic that is explicitly needed for application function.
2. **MICRO-SEGMENTATION**: Segment by application (app label), environment (env label), and role (role label). Each application in each environment should have its own policy scope.
3. **LEAST PRIVILEGE**: Allow only the minimum ports and protocols needed. Never use "all services" rules.
4. **INTRA-SCOPE RULES**: Traffic within the same app|env is common and usually expected (app servers talking to their own databases, caches, queues). These are generally safe to allow but should be scoped to specific services.
5. **INTER-SCOPE RULES**: Traffic between different applications or environments needs careful review. Prod-to-dev traffic, or unexpected app-to-app traffic may indicate misconfigurations or security issues.
6. **SERVICE SPECIFICITY**: Prefer named services over raw port/protocol numbers. Group related ports into service definitions.
7. **COMMON SAFE PATTERNS**:
   - App servers → Database (5432/tcp PostgreSQL, 3306/tcp MySQL, 1433/tcp MSSQL, 1521/tcp Oracle): standard application architecture
   - Web → App (8080/tcp, 8443/tcp, 443/tcp): standard web tier to app tier
   - Monitoring agents (5666/tcp NRPE, 161/udp SNMP, 9090/tcp Prometheus): standard ops infrastructure
   - DNS (53/tcp+udp): essential infrastructure
   - NTP (123/udp): time synchronization
   - LDAP/AD (389/tcp, 636/tcp): authentication
8. **COMMON RISK PATTERNS**:
   - FTP (20-21/tcp): insecure file transfer, recommend SFTP (22/tcp) instead
   - Telnet (23/tcp): insecure remote access, recommend SSH (22/tcp) instead
   - Broad port ranges (e.g., 1024-65535): too permissive, defeats micro-segmentation
   - Any ↔ Any rules: should never exist in a micro-segmented environment
   - RDP (3389/tcp) from broad sources: potential lateral movement vector
   - SMB (445/tcp) between environments: potential ransomware spread vector
9. **ENFORCEMENT PROGRESSION**: New rules should be tested in visibility_only mode first, then selective, then full enforcement. Never go straight to full enforcement.
10. **RULE NAMING**: Use descriptive names that indicate source, destination, and purpose.

## Your Role
When presented with blocked traffic data, evaluate whether creating a rule is appropriate. Consider:
- Is this traffic expected for the application architecture?
- Does allowing this traffic increase the attack surface significantly?
- Are the services standard and well-known, or unusual?
- Is this intra-scope (same app|env) or inter-scope (different app or env)?
- How many connections are being blocked? (High volume suggests legitimate traffic)
- How many unique hosts are involved? (Many hosts suggests systematic, not anomalous)

Always respond in the exact JSON format requested. Be concise but specific in your reasoning."""


ANALYSIS_PROMPT = """Analyze this blocked traffic pattern and recommend whether a firewall rule should be created.

## Blocked Traffic Details

- **Source**: {src_group} (app|env label group)
- **Destination**: {dst_group} (app|env label group)
- **Type**: {traffic_type}
- **Total blocked connections**: {total_connections:,}
- **Unique hosts involved**: {host_count}
- **Time period**: Last {lookback_hours} hours

### Services (port/protocol) with connection counts:
{services_detail}

### Proposed rule:
{rule_summary}

## Instructions
Respond with ONLY a JSON object (no markdown, no code fences):
{{
    "recommendation": "approve" or "review" or "reject",
    "risk_level": "low" or "medium" or "high",
    "reasoning": "2-3 sentence explanation of your assessment",
    "suggested_modifications": "Specific suggestions to make the rule better, or empty string if the rule is fine as-is",
    "confidence": 0.0 to 1.0
}}"""


DENY_PATTERN_PROMPT = """Analyze this deny layer pattern and provide a risk narrative.

## Deny Pattern
- **Name**: {name}
- **Port**: {port}/{proto}
- **Description**: {description}
- **Risk level**: {risk}
- **Safe to block**: {safe_to_block}

## Traffic Evidence
- **Cross-scope flows detected**: {cross_scope_flows}
- **Total connections**: {total_connections}
- **Affected pairs**: {affected_pairs}

## Instructions
Respond with ONLY a JSON object:
{{
    "narrative": "2-4 sentence risk narrative explaining why this pattern matters and what the traffic evidence means",
    "urgency": "immediate" or "soon" or "planned",
    "recommendation": "A specific recommendation for this environment based on the evidence"
}}"""


TIGHTENING_PROMPT = """Analyze this rule for potential tightening from all-services to specific services.

## Current Rule
- **Scope**: {app_env}
- **Rule type**: {rule_type}
- **Current policy**: Allow ALL services between workloads in scope

## Observed Traffic (last {days_observed} days)
{observed_services}

## Instructions
Based on the observed services, recommend whether this rule should be tightened to only allow observed services.
Respond with ONLY a JSON object:
{{
    "recommendation": "tighten" or "keep" or "monitor",
    "confidence": 0.0 to 1.0,
    "reasoning": "2-3 sentence explanation",
    "suggested_services": ["list of services to allow if tightening"]
}}"""


CLASSIFY_FLOW_PROMPT = """Classify this blocked traffic flow.

## Blocked Flow Details
- **Source**: {src_group}
- **Destination**: {dst_group}
- **Services**: {services}
- **Connections**: {total_connections}
- **Host count**: {host_count}

## Instructions
Classify this blocked traffic into one of these categories:
- security_concern: Cross-environment or suspicious traffic that should remain blocked
- change_driven: Legitimate traffic that needs a new rule (application change, new deployment)
- governance: Expected block from deny rules (lateral movement prevention working as intended)
- noise: Low-volume, transient, or scanner traffic that can be ignored

Respond with ONLY a JSON object:
{{
    "classification": "security_concern" or "change_driven" or "governance" or "noise",
    "confidence": 0.0 to 1.0,
    "reasoning": "1-2 sentence explanation"
}}"""


BREACH_RADIUS_PROMPT = """Analyze this breach radius simulation result and provide a security narrative.

## Breach Radius Simulation
- **Target (compromised)**: {target}
- **Total reachable groups**: {total_reachable}
- **Maximum hop depth**: {max_depth}

## Reachable Groups
{reachable_detail}

## Instructions
Write a security narrative about what this breach radius means. Consider:
- Is the blast radius too large? What would a reasonable target be?
- Which reachable groups are most concerning?
- What actions could reduce the radius?

Respond with ONLY a JSON object:
{{
    "severity": "critical" or "high" or "medium" or "low",
    "narrative": "3-5 sentence security assessment",
    "top_risks": ["list of the 2-3 most concerning reachable groups and why"],
    "reduction_actions": ["2-3 specific actions to reduce breach radius"]
}}"""


MATURITY_COACH_PROMPT = """Coach the security team on improving their segmentation maturity.

## Current Maturity Scores
- **Overall**: {overall}% ({stage})
- **Discovery**: {discovery}% (workloads found and traffic analyzed)
- **Classification**: {classification}% (labels assigned)
- **First Policy**: {first_policy}% (rules provisioned)
- **Deny Layer**: {deny_layer}% (lateral movement blocked)
- **Tightening**: {tightening}% (rules specificity, L1→L2→L3)
- **Coverage**: {coverage}% (enforcement mode progression)

## Instructions
Provide specific, actionable coaching for the next steps. Focus on the weakest areas first.

Respond with ONLY a JSON object:
{{
    "priority_area": "the single most impactful area to improve",
    "next_steps": ["3-5 specific, actionable steps ordered by priority"],
    "quick_wins": ["1-2 things that can be done today"],
    "target_stage": "the next maturity stage to aim for",
    "estimated_effort": "low" or "medium" or "high"
}}"""


class AIAdvisor:
    """Unified LLM interface supporting Anthropic, OpenAI, and Ollama."""

    def __init__(self):
        self.provider = os.environ.get("AI_PROVIDER", "").lower()
        self.api_key = os.environ.get("AI_API_KEY", "")
        self.model = os.environ.get("AI_MODEL", "")
        self.base_url = os.environ.get("AI_BASE_URL", "")

        if not self.model:
            if self.provider == "anthropic":
                self.model = "claude-sonnet-4-20250514"
            elif self.provider == "openai":
                self.model = "gpt-4o"
            elif self.provider == "ollama":
                self.model = "llama3"

        self.enabled = bool(self.provider and (self.api_key or self.provider == "ollama"))

        if self.enabled:
            log.info("AI Advisor enabled: provider=%s, model=%s", self.provider, self.model)
        else:
            log.info("AI Advisor disabled (no AI_PROVIDER configured)")

    def is_enabled(self):
        return self.enabled

    def get_config(self):
        """Return safe config info (no secrets)."""
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url or "(default)",
        }

    def analyze(self, auto_rule, lookback_hours=24):
        """Analyze a blocked traffic pattern and return AI recommendation."""
        if not self.enabled:
            return {"error": "AI not configured. Set AI_PROVIDER and AI_API_KEY."}

        # Build services detail
        services_lines = []
        for svc in auto_rule.get("services", []):
            name = svc.get("name", "")
            port = svc.get("port", "?")
            proto = svc.get("proto", "?")
            conns = svc.get("connections", 0)
            label = f"{name} ({port}/{proto})" if name else f"{port}/{proto}"
            services_lines.append(f"  - {label}: {conns:,} connections")

        src = auto_rule.get("app_env", "unknown")
        dst = auto_rule.get("app_env", "unknown")
        traffic_type = "Intra-scope (same app|env)" if src == dst else "Inter-scope (different app or env)"

        svc_names = []
        for s in auto_rule.get("services", []):
            name = s.get("name")
            if name:
                svc_names.append(name)
            else:
                svc_names.append(str(s.get("port", "?")) + "/" + str(s.get("proto", "?")))
        rule_summary = f"Allow all workloads in {src} to communicate on: {', '.join(svc_names)}"

        prompt = ANALYSIS_PROMPT.format(
            src_group=src,
            dst_group=dst,
            traffic_type=traffic_type,
            total_connections=auto_rule.get("total_connections", 0),
            host_count=auto_rule.get("host_count", 0),
            lookback_hours=lookback_hours,
            services_detail="\n".join(services_lines) or "  (none)",
            rule_summary=rule_summary,
        )

        try:
            response_text = self._call_llm(prompt)
            return self._parse_response(response_text)
        except Exception as e:
            log.error("AI analysis failed: %s", e)
            return {"error": str(e)}

    def _call_llm(self, user_prompt):
        """Call the configured LLM provider."""
        if self.provider == "anthropic":
            return self._call_anthropic(user_prompt)
        elif self.provider == "openai":
            return self._call_openai(user_prompt)
        elif self.provider == "ollama":
            return self._call_ollama(user_prompt)
        else:
            raise ValueError(f"Unknown AI provider: {self.provider}")

    def _call_anthropic(self, user_prompt):
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        response = client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=ILLUMIO_BEST_PRACTICES,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text

    def _call_openai(self, user_prompt):
        from openai import OpenAI
        kwargs = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        client = OpenAI(**kwargs)
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=1024,
            messages=[
                {"role": "system", "content": ILLUMIO_BEST_PRACTICES},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content

    def _call_ollama(self, user_prompt):
        import urllib.request
        base = self.base_url or "http://localhost:11434"
        url = f"{base}/api/chat"
        data = json.dumps({
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": ILLUMIO_BEST_PRACTICES},
                {"role": "user", "content": user_prompt},
            ],
        }).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=120)
        result = json.loads(resp.read().decode())
        return result.get("message", {}).get("content", "")

    def suggest_label(self, workload_data):
        """Use AI to suggest a role label based on hostname, traffic, and process data."""
        if not self.enabled:
            return {"error": "AI not configured"}

        hostname = workload_data.get("hostname", "")
        ip = workload_data.get("ip", "")
        app = workload_data.get("app", "")
        env = workload_data.get("env", "")
        existing_labels = workload_data.get("labels", {})
        existing_suggestion = workload_data.get("suggestion", {})
        processes = workload_data.get("processes", [])
        listening_ports = workload_data.get("listening_ports", [])

        prompt = f"""Suggest a role label for this Illumio workload that is missing one.

## Workload Details
- **Hostname**: {hostname}
- **IP**: {ip}
- **Application**: {app}
- **Environment**: {env}
- **Existing labels**: {json.dumps(existing_labels)}

## Traffic/Process Signals
- **Listening ports**: {', '.join(str(p) for p in listening_ports) or 'unknown'}
- **Running processes**: {', '.join(processes[:10]) or 'unknown'}
{f'- **Heuristic suggestion**: {existing_suggestion.get("role", "")} (confidence: {existing_suggestion.get("confidence", 0):.0%}, source: {existing_suggestion.get("source", "")})' if existing_suggestion else ''}

## Available role labels in this PCE
Common roles: web, db, processing, loadbalancer, gateway, cache, jumpbox, monitoring, syslog, dns, dc, mailserver, filer, time, worker

## Instructions
Based on the hostname, traffic patterns, processes, and application context, suggest the most appropriate role label.

Respond with ONLY a JSON object:
{{
    "role": "the suggested role label",
    "confidence": 0.0 to 1.0,
    "reasoning": "brief explanation of why this role fits"
}}"""

        try:
            response_text = self._call_llm(prompt)
            result = self._parse_response(response_text)
            result["ai_suggested"] = True
            return result
        except Exception as e:
            log.error("AI label suggestion failed: %s", e)
            return {"error": str(e)}

    def analyze_deny_pattern(self, pattern, traffic_evidence):
        """AI narrative for a deny layer pattern."""
        if not self.enabled:
            return {"error": "AI not configured"}

        affected_str = ", ".join(
            f"{p['src']} -> {p['dst']} ({p['connections']} conns)"
            for p in traffic_evidence.get("affected_pairs", [])[:5]
        ) or "none"

        prompt = DENY_PATTERN_PROMPT.format(
            name=pattern.get("name", ""),
            port=pattern.get("port", "?"),
            proto=pattern.get("proto", "?"),
            description=pattern.get("description", ""),
            risk=pattern.get("risk", "unknown"),
            safe_to_block=pattern.get("safe_to_block", ""),
            cross_scope_flows=traffic_evidence.get("cross_scope_flows", 0),
            total_connections=traffic_evidence.get("total_connections", 0),
            affected_pairs=affected_str,
        )

        try:
            response_text = self._call_llm(prompt)
            return self._parse_response(response_text)
        except Exception as e:
            log.error("AI deny pattern analysis failed: %s", e)
            return {"error": str(e)}

    def recommend_tightening(self, rule, observed_services, days_observed):
        """AI recommendation for L1 to L2 tightening."""
        if not self.enabled:
            return {"error": "AI not configured"}

        svc_lines = []
        for svc in observed_services:
            name = svc.get("name", "")
            port = svc.get("port", "?")
            proto = svc.get("proto", "?")
            conns = svc.get("connections", 0)
            label = f"{name} ({port}/{proto})" if name else f"{port}/{proto}"
            svc_lines.append(f"  - {label}: {conns:,} connections")

        prompt = TIGHTENING_PROMPT.format(
            app_env=rule.get("app_env", "unknown"),
            rule_type=rule.get("description", "intra-scope"),
            days_observed=days_observed,
            observed_services="\n".join(svc_lines) or "  (none observed)",
        )

        try:
            response_text = self._call_llm(prompt)
            return self._parse_response(response_text)
        except Exception as e:
            log.error("AI tightening recommendation failed: %s", e)
            return {"error": str(e)}

    def classify_blocked_flow(self, flow_data):
        """AI classification of a blocked traffic flow."""
        if not self.enabled:
            return {"error": "AI not configured"}

        services_str = ", ".join(
            s[0] if isinstance(s, (list, tuple)) else str(s)
            for s in flow_data.get("services", [])[:10]
        )

        prompt = CLASSIFY_FLOW_PROMPT.format(
            src_group=flow_data.get("src_group", "unknown"),
            dst_group=flow_data.get("dst_group", "unknown"),
            services=services_str or "unknown",
            total_connections=flow_data.get("total_connections", 0),
            host_count=flow_data.get("host_count", 0),
        )

        try:
            response_text = self._call_llm(prompt)
            return self._parse_response(response_text)
        except Exception as e:
            log.error("AI flow classification failed: %s", e)
            return {"error": str(e)}

    def narrate_breach_radius(self, breach_data):
        """AI narrative for breach radius simulation."""
        if not self.enabled:
            return {"error": "AI not configured"}

        reachable = breach_data.get("reachable", {})
        detail_lines = []
        for group, info in sorted(reachable.items(), key=lambda x: x[1]["hop"]):
            svcs = ", ".join(info.get("services", [])[:3]) or "various"
            detail_lines.append(
                f"  - Hop {info['hop']}: {group} via {svcs} ({info.get('connections', 0):,} connections)"
            )

        prompt = BREACH_RADIUS_PROMPT.format(
            target=breach_data.get("target", "unknown"),
            total_reachable=breach_data.get("total_reachable", 0),
            max_depth=breach_data.get("max_depth", 0),
            reachable_detail="\n".join(detail_lines[:15]) or "  (none reachable)",
        )

        try:
            response_text = self._call_llm(prompt)
            return self._parse_response(response_text)
        except Exception as e:
            log.error("AI breach radius narrative failed: %s", e)
            return {"error": str(e)}

    def coach_maturity(self, maturity_data):
        """AI coaching for maturity improvement."""
        if not self.enabled:
            return {"error": "AI not configured"}

        scores = maturity_data.get("scores", {})
        prompt = MATURITY_COACH_PROMPT.format(
            overall=maturity_data.get("overall", 0),
            stage=maturity_data.get("stage", "Unknown"),
            discovery=scores.get("discovery", 0),
            classification=scores.get("classification", 0),
            first_policy=scores.get("first_policy", 0),
            deny_layer=scores.get("deny_layer", 0),
            tightening=scores.get("tightening", 0),
            coverage=scores.get("coverage", 0),
        )

        try:
            response_text = self._call_llm(prompt)
            return self._parse_response(response_text)
        except Exception as e:
            log.error("AI maturity coaching failed: %s", e)
            return {"error": str(e)}

    def _parse_response(self, text):
        """Parse the LLM response JSON, handling markdown fences."""
        text = text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines).strip()

        try:
            result = json.loads(text)
            # Validate required fields
            for field in ["recommendation", "risk_level", "reasoning"]:
                if field not in result:
                    result[field] = "unknown"
            if "confidence" not in result:
                result["confidence"] = 0.5
            if "suggested_modifications" not in result:
                result["suggested_modifications"] = ""
            result["ai_suggested"] = True
            return result
        except json.JSONDecodeError:
            # If JSON parsing fails, extract what we can
            return {
                "recommendation": "review",
                "risk_level": "medium",
                "reasoning": text[:500],
                "suggested_modifications": "",
                "confidence": 0.3,
                "ai_suggested": True,
                "parse_warning": "Could not parse structured response",
            }
