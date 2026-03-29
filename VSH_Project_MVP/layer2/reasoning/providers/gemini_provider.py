from __future__ import annotations

from .base import ReasoningProvider


class GeminiReasoningProvider(ReasoningProvider):
    name = "gemini"
    model_name = "gemini-opt-in"

    def reason(self, vuln_record: dict, context: dict) -> dict:
        # Opt-in placeholder. Real API call intentionally separated from default flow.
        return {
            "linked_vuln_id": vuln_record.get("vuln_id"),
            "verdict": "needs_review",
            "reasoning": "Gemini provider is an opt-in extension point and is not enabled by default.",
            "confidence": 0.4,
            "secure_fix_guidance": vuln_record.get("fix_suggestion", ""),
            "evidence_lines": [context.get("target_line", 1)],
            "provider_name": self.name,
            "model_name": self.model_name,
        }
