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
