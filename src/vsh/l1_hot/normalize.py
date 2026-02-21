"""Normalize raw scanner outputs into Finding models."""

from __future__ import annotations

from typing import Any

from vsh.common.models import Category, Finding, Location, ReachabilityHint, Severity


def _as_severity(value: str | None) -> Severity:
    if value in {item.value for item in Severity}:
        return Severity(value)  # type: ignore[arg-type]
    return Severity.MEDIUM


def semgrep_json_to_findings(semgrep_json: dict[str, Any], file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    results = semgrep_json.get("results", [])

    for index, result in enumerate(results, start=1):
        meta = result.get("extra", {}).get("metadata", {})
        start = result.get("start", {})
        end = result.get("end", {})
        location = Location(
            file_path=result.get("path", file_path),
            start_line=start.get("line", 1),
            start_col=start.get("col", 1),
            end_line=end.get("line", start.get("line", 1)),
            end_col=end.get("col", start.get("col", 1)),
        )
        findings.append(
            Finding(
                id=f"l1-{index}",
                rule_id=result.get("check_id", "unknown.rule"),
                severity=_as_severity(meta.get("severity")),
                category=Category.CODE,
                location=location,
                cwe=meta.get("cwe", []),
                owasp=meta.get("owasp", []),
                kisa_key=meta.get("kisa_key"),
                fsec_key=meta.get("fsec_key"),
                message=result.get("extra", {}).get("message", "Potential issue found."),
                reachability_hint=ReachabilityHint.UNKNOWN,
                confidence=0.7,
            )
        )

    return findings
