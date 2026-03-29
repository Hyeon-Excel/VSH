from __future__ import annotations

from dataclasses import dataclass, asdict

VERDICTS = {"likely_vulnerable", "suspicious", "not_vulnerable", "needs_review"}


@dataclass
class L2ReasoningResult:
    linked_vuln_id: str
    verdict: str
    confidence: float
    reasoning: str
    attack_scenario: str
    secure_fix_guidance: str
    severity_override: str
    evidence_lines: list[int]
    provider_name: str
    model_name: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def validate_reasoning_result(payload: dict) -> L2ReasoningResult:
    verdict = payload.get("verdict", "needs_review")
    if verdict not in VERDICTS:
        verdict = "needs_review"
    confidence = float(payload.get("confidence", 0.5) or 0.5)
    confidence = max(0.0, min(1.0, confidence))
    evidence = payload.get("evidence_lines") or []
    if not isinstance(evidence, list):
        evidence = []

    severity_override = payload.get("severity_override", "MEDIUM")
    if severity_override not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        severity_override = "MEDIUM"

    return L2ReasoningResult(
        linked_vuln_id=str(payload.get("linked_vuln_id", "")),
        verdict=verdict,
        confidence=confidence,
        reasoning=str(payload.get("reasoning", "")),
        attack_scenario=str(payload.get("attack_scenario", "")),
        secure_fix_guidance=str(payload.get("secure_fix_guidance", "")),
        severity_override=severity_override,
        evidence_lines=[int(x) for x in evidence if isinstance(x, int) or str(x).isdigit()],
        provider_name=str(payload.get("provider_name", "mock")),
        model_name=payload.get("model_name"),
    )
