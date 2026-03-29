from __future__ import annotations

from .base import ReasoningProvider


class MockReasoningProvider(ReasoningProvider):
    name = "mock"
    model_name = "heuristic-mock-v1"

    def reason(self, vuln_record: dict, context: dict) -> dict:
        cwe = vuln_record.get("cwe_id")
        snippet = (context.get("snippet") or "").lower()
        verdict = "suspicious"
        confidence = 0.65
        if cwe in {"CWE-89", "CWE-78", "CWE-95", "CWE-502"} and any(x in snippet for x in ["eval", "execute", "os.system", "pickle.loads", "subprocess"]):
            verdict = "likely_vulnerable"
            confidence = 0.85
        elif cwe == "CWE-1104":
            verdict = "needs_review"
            confidence = 0.55
        elif cwe == "CWE-829":
            verdict = "suspicious"
            confidence = 0.7
        return {
            "linked_vuln_id": vuln_record.get("vuln_id"),
            "verdict": verdict,
            "reasoning": "Mock provider analyzed finding-driven context window and imports.",
            "confidence": confidence,
            "secure_fix_guidance": vuln_record.get("fix_suggestion", "apply secure coding fix"),
            "evidence_lines": [context.get("target_line", vuln_record.get("line_number", 1))],
            "provider_name": self.name,
            "model_name": self.model_name,
        }
