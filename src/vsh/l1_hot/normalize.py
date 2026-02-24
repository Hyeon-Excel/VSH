"""Normalize raw scanner outputs into Finding models."""

from __future__ import annotations

import hashlib
from typing import Any

from vsh.common.models import Category, Finding, Location, ReachabilityHint, Severity


def _as_severity(value: str | None) -> Severity:
    if value in {item.value for item in Severity}:
        return Severity(value)  # type: ignore[arg-type]
    return Severity.MEDIUM


def _as_category(value: str | None) -> Category:
    if value in {item.value for item in Category}:
        return Category(value)  # type: ignore[arg-type]
    return Category.CODE


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _infer_reachability(rule_id: str, message: str) -> ReachabilityHint:
    context = f"{rule_id} {message}".lower()
    if any(token in context for token in ("sqli", "xss", "injection", "innerhtml")):
        return ReachabilityHint.YES
    return ReachabilityHint.UNKNOWN


def _derive_confidence(severity: Severity, reachability_hint: ReachabilityHint) -> float:
    if severity in {Severity.CRITICAL, Severity.HIGH} and reachability_hint == ReachabilityHint.YES:
        return 0.9
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return 0.8
    if severity == Severity.MEDIUM:
        return 0.7
    return 0.6


def _finding_id(rule_id: str, file_path: str, line: int, col: int) -> str:
    raw = f"{rule_id}:{file_path}:{line}:{col}"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"l1-{digest}"


def _normalize_rule_id(raw: str) -> str:
    if "vsh." in raw:
        return raw[raw.index("vsh.") :]
    return raw


def semgrep_json_to_findings(semgrep_json: dict[str, Any], file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    results = semgrep_json.get("results", [])

    for result in results:
        meta = result.get("extra", {}).get("metadata", {})
        start = result.get("start", {})
        end = result.get("end", {})
        start_line = int(start.get("line", 1))
        start_col = int(start.get("col", 1))
        end_line = int(end.get("line", start_line))
        end_col = int(end.get("col", start_col))
        rule_id = _normalize_rule_id(str(result.get("check_id", "unknown.rule")))
        message = str(result.get("extra", {}).get("message", "Potential issue found."))
        severity = _as_severity(meta.get("severity"))
        category = _as_category(meta.get("category"))
        reachability_hint = _infer_reachability(rule_id, message)
        confidence = _derive_confidence(severity, reachability_hint)

        location = Location(
            file_path=file_path,
            start_line=start_line,
            start_col=start_col,
            end_line=end_line,
            end_col=end_col,
        )
        findings.append(
            Finding(
                id=_finding_id(rule_id, file_path, start_line, start_col),
                rule_id=rule_id,
                severity=severity,
                category=category,
                location=location,
                cwe=_as_str_list(meta.get("cwe")),
                owasp=_as_str_list(meta.get("owasp")),
                kisa_key=meta.get("kisa_key"),
                fsec_key=meta.get("fsec_key"),
                message=message,
                reachability_hint=reachability_hint,
                confidence=confidence,
            )
        )

    return findings
