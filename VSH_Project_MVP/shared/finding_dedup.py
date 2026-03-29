from __future__ import annotations

from typing import Iterable

from models.vulnerability import Vulnerability

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_REACHABILITY_RANK = {"reachable": 3, "unreachable": 2, "unknown": 1, None: 0}


def _dedup_key(finding: Vulnerability) -> tuple:
    evidence = (finding.code_snippet or "").strip()
    span_start = finding.line_number
    span_end = finding.metadata.get("end_line_number", finding.line_number)
    # core dedup grouping: same file, CWE, line-span => merge duplicates
    # metadata and evidence는 병합 시력으로 유지하며 false-merge는 _merge_findings에서 조정
    return (
        finding.file_path,
        finding.cwe_id,
        span_start,
        span_end,
    )


def deduplicate_findings(findings: Iterable[Vulnerability]) -> list[Vulnerability]:
    unique: dict[tuple, Vulnerability] = {}
    for finding in findings:
        key = _dedup_key(finding)
        existing = unique.get(key)
        unique[key] = finding if existing is None else _merge_findings(existing, finding)
    return list(unique.values())


def _merge_findings(base: Vulnerability, incoming: Vulnerability) -> Vulnerability:
    refs = list(dict.fromkeys([*base.references, *incoming.references]))
    meta = dict(base.metadata)
    for k, v in incoming.metadata.items():
        meta.setdefault(k, v)
    return base.model_copy(update={
        "rule_id": base.rule_id or incoming.rule_id,
        "severity": base.severity if _SEVERITY_RANK.get(base.severity, 0) >= _SEVERITY_RANK.get(incoming.severity, 0) else incoming.severity,
        "code_snippet": base.code_snippet if len(base.code_snippet or "") >= len(incoming.code_snippet or "") else incoming.code_snippet,
        "reachability_status": base.reachability_status if _REACHABILITY_RANK.get(base.reachability_status, 0) >= _REACHABILITY_RANK.get(incoming.reachability_status, 0) else incoming.reachability_status,
        "references": refs,
        "metadata": meta,
    })
