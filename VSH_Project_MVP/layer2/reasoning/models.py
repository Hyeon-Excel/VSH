from __future__ import annotations

from dataclasses import dataclass, asdict

VERDICTS = {"likely_vulnerable", "suspicious", "not_vulnerable", "needs_review"}


@dataclass
class L2ReasoningResult:
    linked_vuln_id: str
    verdict: str
    reasoning: str
    confidence: float
    secure_fix_guidance: str
    evidence_lines: list[int]
    provider_name: str
    model_name: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def validate_reasoning_result(payload: dict) -> L2ReasoningResult:
    verdict = payload.get("verdict", "needs_review")
    if verdict not in VERDICTS:
        verdict = "needs_review"
    confidence = float(payload.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))
    evidence = payload.get("evidence_lines") or []
    if not isinstance(evidence, list):
        evidence = []
    return L2ReasoningResult(
        linked_vuln_id=str(payload.get("linked_vuln_id", "")),
        verdict=verdict,
        reasoning=str(payload.get("reasoning", "")),
        confidence=confidence,
        secure_fix_guidance=str(payload.get("secure_fix_guidance", "")),
        evidence_lines=[int(x) for x in evidence if isinstance(x, int) or str(x).isdigit()],
        provider_name=str(payload.get("provider_name", "mock")),
        model_name=payload.get("model_name"),
    )
