from __future__ import annotations

from typing import Dict, Tuple


# hyeonexcel 수정: L2가 생성한 수정 제안에 신뢰도 근거를 일관되게 붙이기 위해
# analyzer와 pipeline이 공통으로 사용하는 confidence 계산 규칙을 분리한다.
def build_decision_metadata(
    cwe_id: str | None,
    context: Dict,
    decision_status: str | None = None,
    confidence_score: int | None = None,
    confidence_reason: str | None = None,
) -> Tuple[str, int, str]:
    normalized_status = decision_status or "confirmed"

    if confidence_score is None or (
        confidence_score <= 0 and normalized_status != "analysis_failed"
    ):
        confidence_score = compute_confidence_score(cwe_id, context)

    if not confidence_reason:
        confidence_reason = build_confidence_reason(cwe_id, context, confidence_score)

    return normalized_status, confidence_score, confidence_reason


def compute_confidence_score(cwe_id: str | None, context: Dict) -> int:
    score = 60 if cwe_id != "CWE-829" else 68

    evidence_refs = context.get("evidence_refs") or []
    if evidence_refs:
        score += 8

    if context.get("evidence_summary"):
        score += 6

    retrieval_backend = context.get("retrieval_backend")
    if retrieval_backend == "hybrid":
        score += 12
    elif retrieval_backend == "chroma_only":
        score += 10
    elif retrieval_backend == "static_only":
        score += 4

    chroma_hits = int(context.get("chroma_hits", 0) or 0)
    if chroma_hits > 0:
        score += min(10, chroma_hits * 2)

    if context.get("registry_status") == "FOUND":
        score += 8
    elif context.get("registry_status") == "ERROR":
        score -= 5

    if context.get("osv_status") == "FOUND":
        score += 10
    elif context.get("osv_status") == "ERROR":
        score -= 5

    if context.get("verification_summary"):
        score += 4

    return max(0, min(score, 95))


def build_confidence_reason(cwe_id: str | None, context: Dict, confidence_score: int) -> str:
    reasons = []

    retrieval_backend = context.get("retrieval_backend")
    if retrieval_backend == "hybrid":
        reasons.append("정적 근거와 RAG 근거가 함께 확인되었습니다")
    elif retrieval_backend == "chroma_only":
        reasons.append("RAG 근거가 직접 연결되었습니다")
    elif retrieval_backend == "static_only":
        reasons.append("정적 지식 기반 근거가 확인되었습니다")

    chroma_hits = int(context.get("chroma_hits", 0) or 0)
    if chroma_hits > 0:
        reasons.append(f"Chroma 검색 결과 {chroma_hits}건이 매칭되었습니다")

    if context.get("registry_status") == "FOUND":
        reasons.append("registry 검증에서 선언 정보가 확인되었습니다")

    if context.get("osv_status") == "FOUND":
        reasons.append("OSV 검증에서 취약 advisory가 확인되었습니다")

    if not reasons and cwe_id == "CWE-829":
        reasons.append("취약 의존성 선언이 직접 탐지되었습니다")
    elif not reasons:
        reasons.append("탐지 규칙과 코드 근거가 일치했습니다")

    reasons.append(f"최종 신뢰도 점수는 {confidence_score}점입니다")
    return " / ".join(reasons)
