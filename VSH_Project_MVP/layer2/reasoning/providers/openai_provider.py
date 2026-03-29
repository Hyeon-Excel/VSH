from __future__ import annotations

import os
import time
from typing import Any

from .base import ReasoningProvider

try:
    import openai
except ImportError as e:
    raise ImportError("OpenAI package required for OpenAIReasoningProvider: pip install openai") from e


class OpenAIReasoningProvider(ReasoningProvider):
    name = "openai"
    model_name = "gpt-4.1"

    def __init__(self, model: str | None = None, rate_limit_per_min: int = 60):
        self.model = model or os.environ.get("OPENAI_MODEL", "gpt-4.1-mini")
        self.rate_limit_per_min = rate_limit_per_min
        self._last_called = 0.0

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError("OPENAI_API_KEY is required for OpenAIReasoningProvider")
        openai.api_key = api_key

    def _throttle(self):
        interval = 60.0 / self.rate_limit_per_min
        now = time.time()
        elapsed = now - self._last_called
        if elapsed < interval:
            time.sleep(interval - elapsed)

    def reason(self, vuln_record: dict, context: dict) -> dict:
        self._throttle()
        prompt = self._build_prompt(vuln_record, context)

        resp = openai.ChatCompletion.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a secure code analyst."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=450,
            temperature=0.2,
        )

        self._last_called = time.time()

        text = resp.choices[0].message.content.strip()
        return self._parse_text_output(text, vuln_record)

    def _build_prompt(self, vuln_record: dict, context: dict) -> str:
        return (
            f"Vulnerability detection record:\n"
            f"- vuln_id: {vuln_record.get('vuln_id')}\n"
            f"- cwe_id: {vuln_record.get('cwe_id')}\n"
            f"- file: {vuln_record.get('file_path')}\n"
            f"- line: {vuln_record.get('line_number')}\n"
            f"- snippet: {vuln_record.get('evidence')}\n"
            f"- reachability_status: {vuln_record.get('reachability_status')}\n"
            f"- reachability_confidence: {vuln_record.get('reachability_confidence')}\n"
            f"Context (surrounding lines):\n{context.get('context')}\n"
            "Based on this, generate a JSON object exactly with keys:\n"
            "is_vulnerable (true/false), confidence (0-1), reasoning, attack_scenario, fix_suggestion, severity_override (LOW/MEDIUM/HIGH/CRITICAL)."
        )

    def _parse_text_output(self, text: str, vuln_record: dict) -> dict:
        try:
            import json

            data = json.loads(text)
            return {
                "linked_vuln_id": vuln_record.get("vuln_id"),
                "verdict": "likely_vulnerable" if data.get("is_vulnerable") else "not_vulnerable",
                "confidence": float(data.get("confidence", 0.5)),
                "reasoning": data.get("reasoning", ""),
                "secure_fix_guidance": data.get("fix_suggestion", vuln_record.get("fix_suggestion", "")),
                "evidence_lines": [context.get("target_line", vuln_record.get("line_number", 1))],
                "provider_name": self.name,
                "model_name": self.model,
                "attack_scenario": data.get("attack_scenario", ""),
                "severity_override": data.get("severity_override", "MEDIUM"),
            }
        except Exception:
            return {
                "linked_vuln_id": vuln_record.get("vuln_id"),
                "verdict": "needs_review",
                "confidence": 0.5,
                "reasoning": "OpenAI response parse failed. Fallback to review.",
                "secure_fix_guidance": vuln_record.get("fix_suggestion", ""),
                "evidence_lines": [vuln_record.get("line_number", 1)],
                "provider_name": self.name,
                "model_name": self.model,
                "attack_scenario": "",
                "severity_override": "MEDIUM",
            }
