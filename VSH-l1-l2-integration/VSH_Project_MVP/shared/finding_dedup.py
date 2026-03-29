from __future__ import annotations

from typing import Iterable

from models.vulnerability import Vulnerability


_SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

_REACHABILITY_RANK = {
    "reachable": 3,
    "unreachable": 2,
    "unknown": 1,
    None: 0,
}


def deduplicate_findings(findings: Iterable[Vulnerability]) -> list[Vulnerability]:
    """
    파이프라인 전반에서 사용하는 공통 취약점 중복 제거 함수.

    기준 키는 현재 issue_id 생성 규칙과 동일한
    `file_path + cwe_id + line_number` 조합을 사용한다.
    중복이 발견되면 첫 finding을 기준으로 유지하되,
    severity / rule_id / references / reachability_status / metadata는 가능한 범위에서 병합한다.
    """

    unique: dict[tuple[str | None, str, int], Vulnerability] = {}

    for finding in findings:
        key = (
            finding.file_path,
            finding.cwe_id,
            finding.line_number,
        )
        existing = unique.get(key)
        if existing is None:
            unique[key] = finding
            continue

        unique[key] = _merge_findings(existing, finding)

    return list(unique.values())


def _merge_findings(base: Vulnerability, incoming: Vulnerability) -> Vulnerability:
    references = list(base.references)
    seen_refs = set(references)
    for ref in incoming.references:
        if ref not in seen_refs:
            references.append(ref)
            seen_refs.add(ref)

    merged_metadata = dict(base.metadata)
    for key, value in incoming.metadata.items():
        if key not in merged_metadata:
            merged_metadata[key] = value

    return base.model_copy(
        update={
            "rule_id": base.rule_id or incoming.rule_id,
            "severity": _higher_severity(base.severity, incoming.severity),
            "code_snippet": _prefer_snippet(base.code_snippet, incoming.code_snippet),
            "reachability_status": _higher_reachability(base.reachability_status, incoming.reachability_status),
            "references": references,
            "metadata": merged_metadata,
        }
    )


def _higher_severity(left: str, right: str) -> str:
    return left if _SEVERITY_RANK.get(left, 0) >= _SEVERITY_RANK.get(right, 0) else right


def _higher_reachability(left: str | None, right: str | None) -> str | None:
    return left if _REACHABILITY_RANK.get(left, 0) >= _REACHABILITY_RANK.get(right, 0) else right


def _prefer_snippet(left: str, right: str) -> str:
    if not left:
        return right
    if not right:
        return left
    return left if len(left) >= len(right) else right
