"""
AI Advisor — LLM-powered security posture analysis for Illumio PCE.

Supports Anthropic (Claude), OpenAI (GPT), and Ollama-compatible APIs.
Generates per-section narratives and executive summaries for security reports.
"""

import json
import logging
import os

log = logging.getLogger("ai_advisor")

SECURITY_REPORT_SYSTEM_PROMPT = """You are an Illumio PCE security posture analyst. You analyze security data from an Illumio Policy Compute Engine and write clear, actionable security report narratives.

## Context
- Illumio PCE manages micro-segmentation policy for workloads (servers, VMs, containers)
- Workloads have labels (app, env, role, loc) that define their identity and drive policy
- Policy is enforced through rulesets scoped by labels — rules define allowed communication
- Enforcement modes progress: idle (no enforcement) → visibility_only (monitor only) → selective (partial) → full (complete enforcement)
- Traffic flows show allowed, blocked, and potentially_blocked communications between workloads
- Zero Trust principle: default deny, only allow explicitly needed traffic

## Security Analysis Categories
1. Enforcement Coverage — how many workloads have active enforcement
2. OS Lifecycle Risk — end-of-life operating systems that no longer receive security patches
3. Label Hygiene — completeness of workload labeling (app, env, role, loc)
4. Environmental Separation — traffic boundary violations between prod/dev/test/staging
5. Risky Services — insecure protocols (FTP, Telnet, RDP sprawl, SMB cross-env)
6. Policy Analysis — overly permissive rules, disabled rules, empty rulesets
7. Traffic Anomalies — unusual blocked traffic patterns, IP-only flows
8. Lateral Movement Surface — SSH/RDP sprawl, east-west communication breadth
9. Agent Health — offline agents, stale heartbeats, version sprawl
10. Compliance Mapping — NIST CSF, CIS Controls, PCI-DSS alignment

## Your Role
When given structured findings for a security analysis section, write:
1. A concise narrative paragraph (3-5 sentences) summarizing key findings in business terms
2. Risk rationale explaining why these findings matter
3. The most impactful remediation actions (top 3)

Always be specific with numbers. Reference actual workload counts, percentages, and specific risky items found. Write for a CISO-level audience — clear, direct, no jargon without explanation.

Respond in the exact JSON format requested."""


SECTION_PROMPT = """Analyze the following {section_title} findings and provide a narrative summary.

## Findings Summary
{findings_json}

## Key Metrics
{metrics_json}

## Category Score: {score}/100 (Grade: {grade})

Respond with ONLY a JSON object (no markdown, no code fences):
{{
    "narrative": "3-5 sentence executive-level narrative of these findings",
    "risk_rationale": "Why these findings matter from a security perspective",
    "top_recommendations": ["recommendation 1", "recommendation 2", "recommendation 3"]
}}"""


EXECUTIVE_PROMPT = """Generate an executive summary for this Illumio security posture report.

## Overall Score: {overall_score}/100 (Grade: {overall_grade})

## Category Scores
{categories_json}

## Finding Severity Totals
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}
- Info: {info_count}

## Top Critical/High Findings
{top_findings}

## Data Summary
{data_summary}

Respond with ONLY a JSON object (no markdown, no code fences):
{{
    "executive_narrative": "4-6 sentence executive summary suitable for a board presentation. Be specific with numbers.",
    "top_3_risks": ["most critical risk 1", "risk 2", "risk 3"],
    "top_3_wins": ["positive finding 1", "positive 2", "positive 3"],
    "recommended_focus_areas": ["focus area 1", "focus area 2", "focus area 3"]
}}"""


REMEDIATION_PROMPT = """Generate a prioritized remediation roadmap based on these security findings.

## Overall Score: {overall_score}/100

## All Findings by Category
{all_findings_json}

Respond with ONLY a JSON array (no markdown, no code fences). Each item:
{{
    "priority": 1,
    "action": "Specific, actionable remediation step",
    "impact": "high" or "medium" or "low",
    "effort": "low" or "medium" or "high",
    "category": "category_id",
    "rationale": "Why this should be prioritized"
}}

Return the top 10 most impactful actions, ordered by priority (highest impact + lowest effort first)."""


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

    def analyze_section(self, section_id, section_title, findings_summary, metrics, score, grade):
        """Generate AI narrative for a report section."""
        if not self.enabled:
            return None

        prompt = SECTION_PROMPT.format(
            section_title=section_title,
            findings_json=json.dumps(findings_summary, indent=2),
            metrics_json=json.dumps(metrics, indent=2),
            score=score,
            grade=grade,
        )

        try:
            response_text = self._call_llm(prompt)
            return self._parse_response(response_text)
        except Exception as e:
            log.error("AI section analysis failed for %s: %s", section_id, e)
            return None

    def generate_executive_summary(self, overall_score, overall_grade, categories,
                                   severity_totals, top_findings, data_summary):
        """Generate the executive summary for the full report."""
        if not self.enabled:
            return None

        categories_lines = []
        for cat_id, cat_data in categories.items():
            categories_lines.append(f"- {cat_data['title']}: {cat_data['score']}/100 ({cat_data['grade']})")

        top_findings_lines = []
        for f in top_findings[:10]:
            top_findings_lines.append(f"- [{f['severity'].upper()}] {f['title']}")

        prompt = EXECUTIVE_PROMPT.format(
            overall_score=overall_score,
            overall_grade=overall_grade,
            categories_json="\n".join(categories_lines),
            critical_count=severity_totals.get("critical", 0),
            high_count=severity_totals.get("high", 0),
            medium_count=severity_totals.get("medium", 0),
            low_count=severity_totals.get("low", 0),
            info_count=severity_totals.get("info", 0),
            top_findings="\n".join(top_findings_lines) or "No critical/high findings.",
            data_summary=json.dumps(data_summary, indent=2),
        )

        try:
            response_text = self._call_llm(prompt)
            return self._parse_response(response_text)
        except Exception as e:
            log.error("AI executive summary failed: %s", e)
            return None

    def generate_remediation_roadmap(self, overall_score, all_findings_by_category):
        """Generate AI-prioritized remediation roadmap."""
        if not self.enabled:
            return None

        condensed = {}
        for cat_id, findings in all_findings_by_category.items():
            condensed[cat_id] = [
                {"title": f["title"], "severity": f["severity"], "affected_count": f.get("affected_count", 0)}
                for f in findings[:5]
            ]

        prompt = REMEDIATION_PROMPT.format(
            overall_score=overall_score,
            all_findings_json=json.dumps(condensed, indent=2),
        )

        try:
            response_text = self._call_llm(prompt)
            result = self._parse_response(response_text)
            if isinstance(result, list):
                return result
            if isinstance(result, dict) and "error" not in result:
                return [result]
            return None
        except Exception as e:
            log.error("AI remediation roadmap failed: %s", e)
            return None

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
            max_tokens=2048,
            system=SECURITY_REPORT_SYSTEM_PROMPT,
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
            max_tokens=2048,
            messages=[
                {"role": "system", "content": SECURITY_REPORT_SYSTEM_PROMPT},
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
                {"role": "system", "content": SECURITY_REPORT_SYSTEM_PROMPT},
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
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines).strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "narrative": text[:500],
                "risk_rationale": "",
                "top_recommendations": [],
                "parse_warning": "Could not parse structured response",
            }
