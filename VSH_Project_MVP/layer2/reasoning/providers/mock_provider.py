from __future__ import annotations

from .base import ReasoningProvider


class MockReasoningProvider(ReasoningProvider):
    name = "mock"
    model_name = "heuristic-mock-v1"

    def reason(self, vuln_record: dict, context: dict) -> dict:
        cwe = vuln_record.get("cwe_id")
        snippet = (context.get("snippet") or "").lower()
        is_vulnerable = False
        verdict = "needs_review"
        confidence = 0.45
        severity_override = "MEDIUM"

        if cwe in {"CWE-89", "CWE-78", "CWE-95", "CWE-502"} and any(x in snippet for x in ["eval", "execute", "os.system", "pickle.loads", "subprocess"]):
            is_vulnerable = True
            verdict = "likely_vulnerable"
            confidence = 0.85
            severity_override = "HIGH"
        elif cwe == "CWE-1104":
            verdict = "needs_review"
            confidence = 0.6
            severity_override = "MEDIUM"
        elif cwe == "CWE-829":
            verdict = "suspicious"
            confidence = 0.65
            severity_override = "HIGH"

        attack_scenario = "Known pattern from open-source static rule" if is_vulnerable else "Potential but requires manual review"
        return {
            "linked_vuln_id": vuln_record.get("vuln_id"),
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": f"{attack_scenario}; context indicates snippet: {snippet[:120]}",
            "secure_fix_guidance": vuln_record.get("fix_suggestion", "적절한 입력 검증 및 안전한 API 사용으로 수정"),
            "evidence_lines": [context.get("target_line", vuln_record.get("line_number", 1))],
            "provider_name": self.name,
            "model_name": self.model_name,
            "attack_scenario": attack_scenario,
            "severity_override": severity_override,
        }
