"""Build L1 annotation patches."""

from __future__ import annotations

from difflib import unified_diff

from vsh.common.models import Finding


def build_annotation_patch(code: str, findings: list[Finding], file_path: str) -> str:
    """Return unified diff text for inline annotations."""
    if not findings:
        return ""

    source_lines = code.splitlines()
    annotated_lines = list(source_lines)
    comment_prefix = _comment_prefix(file_path)

    line_to_findings: dict[int, list[Finding]] = {}
    for finding in findings:
        line_to_findings.setdefault(finding.location.start_line, []).append(finding)

    for line_no in sorted(line_to_findings.keys(), reverse=True):
        insertion_index = max(0, min(line_no, len(annotated_lines)))
        block: list[str] = []
        for finding in sorted(line_to_findings[line_no], key=lambda item: item.rule_id):
            block.extend(_build_comment_block(comment_prefix, finding))
        annotated_lines[insertion_index:insertion_index] = block

    diff_lines = list(
        unified_diff(
            source_lines,
            annotated_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        )
    )
    if not diff_lines:
        return ""
    return "\n".join(diff_lines) + "\n"


def _comment_prefix(file_path: str) -> str:
    lowered = file_path.lower()
    if lowered.endswith((".js", ".ts", ".c", ".cpp", ".java", ".go", ".rs")):
        return "//"
    return "#"


def _build_comment_block(prefix: str, finding: Finding) -> list[str]:
    cwe = ", ".join(finding.cwe) if finding.cwe else "UNKNOWN"
    kisa = finding.kisa_key or "N/A"
    impact = _impact_text(finding.rule_id)
    guidance = _guidance_text(finding.rule_id)
    return [
        f"{prefix} VSH Alert [{finding.severity.value}] {finding.rule_id}",
        f"{prefix} CWE: {cwe}",
        f"{prefix} KISA: {kisa}",
        f"{prefix} Reachability: {finding.reachability_hint.value}",
        f"{prefix} Impact: {impact}",
        f"{prefix} Recommendation: {guidance}",
    ]


def _impact_text(rule_id: str) -> str:
    lowered = rule_id.lower()
    if "sqli" in lowered or "sql" in lowered:
        return "User-controlled input may alter database queries."
    if "xss" in lowered or "innerhtml" in lowered:
        return "Untrusted input may execute script in the browser."
    if "secret" in lowered:
        return "Embedded credentials may be leaked through source control."
    return "Potentially unsafe behavior detected by static analysis."


def _guidance_text(rule_id: str) -> str:
    lowered = rule_id.lower()
    if "sqli" in lowered or "sql" in lowered:
        return "Use parameterized queries instead of string interpolation."
    if "xss" in lowered or "innerhtml" in lowered:
        return "Use safe text rendering APIs or sanitize trusted HTML."
    if "secret" in lowered:
        return "Move secrets to environment variables or a secret manager."
    return "Review data flow and apply secure coding controls."
