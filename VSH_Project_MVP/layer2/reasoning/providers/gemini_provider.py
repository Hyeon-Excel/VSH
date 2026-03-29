from __future__ import annotations

import os
import time
from typing import Any

from .base import ReasoningProvider

try:
    from google.genai import Client
    from google.genai import types
except ImportError:
    Client = None
    types = None


class GeminiReasoningProvider(ReasoningProvider):
    name = "gemini"
    model_name = "gemini-pro"

    def __init__(self, model: str | None = None, rate_limit_per_min: int = 60):
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-pro")
        self.rate_limit_per_min = rate_limit_per_min
        self._last_called = 0.0

        if Client is None or types is None:
            raise ImportError("google-genai package required for GeminiReasoningProvider: pip install google-genai")

        api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise EnvironmentError("GOOGLE_API_KEY (or GEMINI_API_KEY) is required for GeminiReasoningProvider")
        self.client = Client(api_key=api_key)

    def _throttle(self):
        interval = 60.0 / self.rate_limit_per_min
        now = time.time()
        elapsed = now - self._last_called
        if elapsed < interval:
            time.sleep(interval - elapsed)

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
            "Based on this, return strict JSON with keys:"
            "is_vulnerable, confidence, reasoning, attack_scenario, fix_suggestion, severity_override."
        )

    def _parse_response(self, text: str, vuln_record: dict, context: dict) -> dict:
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
                "reasoning": "Gemini response could not be parsed; review required.",
                "secure_fix_guidance": vuln_record.get("fix_suggestion", ""),
                "evidence_lines": [context.get("target_line", vuln_record.get("line_number", 1))],
                "provider_name": self.name,
                "model_name": self.model,
                "attack_scenario": "",
                "severity_override": "MEDIUM",
            }

    def reason(self, vuln_record: dict, context: dict) -> dict:
        self._throttle()
        prompt = self._build_prompt(vuln_record, context)
        request = types.GenerateTextRequest(
            model=self.model,
            prompt=prompt,
            max_output_tokens=500,
            temperature=0.2,
        )
        resp = self.client.generate_text(request)
        self._last_called = time.time()
        text = resp.text or ""
        return self._parse_response(text, vuln_record, context)
