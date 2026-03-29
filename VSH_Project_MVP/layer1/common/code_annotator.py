from __future__ import annotations

from pathlib import Path

from models.vulnerability import Vulnerability


def _get_comment_marker(file_path: str) -> str:
    return "//" if file_path.lower().endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")) else "#"


def _build_annotation(vuln: Vulnerability, marker: str) -> str:
    lines = [
        f"{marker} ⚠️ [VSH-L1] 취약점 탐지",
        f"{marker} Severity: {vuln.severity}",
        f"{marker} CWE: {vuln.cwe_id}",
        f"{marker} Rule: {vuln.rule_id or 'unknown'}",
    ]
    if vuln.reachability_status:
        lines.append(f"{marker} Reachability: {vuln.reachability_status}")
    if vuln.references:
        lines.append(f"{marker} Ref: {', '.join(vuln.references[:2])}")
    return "\n".join(lines)


def annotate_files(findings: list[Vulnerability]) -> dict[str, str]:
    annotated: dict[str, str] = {}
    by_file: dict[str, list[Vulnerability]] = {}
    for f in findings:
        if f.file_path and not f.file_path.startswith("<"):
            by_file.setdefault(f.file_path, []).append(f)

    for file_path, group in by_file.items():
        path = Path(file_path)
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=True)
        marker = _get_comment_marker(file_path)
        seen = set()
        for f in sorted(group, key=lambda x: (x.line_number, x.cwe_id, x.rule_id or ""), reverse=True):
            key = (f.line_number, f.cwe_id, f.rule_id)
            if key in seen or f.line_number < 1 or f.line_number > len(lines):
                continue
            seen.add(key)
            annotation = _build_annotation(f, marker)
            idx = f.line_number - 1
            target_line = lines[idx]
            indent = target_line[: len(target_line) - len(target_line.lstrip())]
            lines.insert(idx, "\n".join(indent + l for l in annotation.split("\n")) + "\n")
        annotated[file_path] = "".join(lines)
    return annotated
