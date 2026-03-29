from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class Diagnostic:
    file: str
    line: int
    column: int | None
    severity: str
    source: str
    rule_id: str
    message: str
    suggestion: str
    linked_vuln_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def vuln_to_diagnostic(vuln: dict) -> Diagnostic:
    return Diagnostic(
        file=vuln.get("file_path", "<unknown>"),
        line=int(vuln.get("line_number", 1)),
        column=int(vuln.get("column_number", 1)) if vuln.get("column_number") is not None else None,
        severity=vuln.get("severity", "LOW"),
        source=vuln.get("source", "L1"),
        rule_id=vuln.get("rule_id", "unknown"),
        message=f"{vuln.get('cwe_id', 'CWE-UNKNOWN')} detected ({vuln.get('vuln_type', 'GENERIC')})",
        suggestion=vuln.get("fix_suggestion", ""),
        linked_vuln_id=vuln.get("vuln_id"),
    )


def build_inline_preview(diagnostics: list[dict]) -> str:
    lines = []
    for d in diagnostics:
        lines.append(f"{d['file']}:{d['line']} [{d['severity']}] {d['rule_id']} - {d['message']} -> {d['suggestion']}")
    return "\n".join(lines)


def build_markdown_preview(diagnostics: list[dict]) -> str:
    md = ["# Diagnostics Preview", ""]
    for d in diagnostics:
        md.append(f"- `{d['file']}:{d['line']}` **{d['severity']}** `{d['rule_id']}`: {d['message']}  ")
        md.append(f"  - suggestion: {d['suggestion']}")
    return "\n".join(md)
