from __future__ import annotations

from pathlib import Path

from models.vulnerability import Vulnerability


def _get_comment_marker(file_path: str) -> str:
    lower_path = file_path.lower()
    if lower_path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
        return "//"
    return "#"


def _build_annotation(vuln: Vulnerability, comment_marker: str) -> str:
    lines = [
        f"{comment_marker} ⚠️ [VSH-L1] 취약점 탐지",
        f"{comment_marker} Severity: {vuln.severity}",
        f"{comment_marker} CWE: {vuln.cwe_id}",
    ]

    if vuln.reachability_status:
        lines.append(f"{comment_marker} Reachability: {vuln.reachability_status}")

    if vuln.references:
        lines.append(f"{comment_marker} Reference: {vuln.references[0]}")

    if vuln.metadata.get("title"):
        lines.append(f"{comment_marker} Risk: {vuln.metadata['title']}")

    return "\n".join(lines)


def _check_existing_annotation(line_num: int, content: str) -> bool:
    lines = content.splitlines()
    start = max(0, line_num - 10)
    end = min(len(lines), line_num)
    for idx in range(start, end):
        if "[VSH-L1]" in lines[idx]:
            return True
    return False


def annotate_files(findings: list[Vulnerability]) -> dict[str, str]:
    annotated: dict[str, str] = {}
    findings_by_file: dict[str, list[Vulnerability]] = {}

    for finding in findings:
        if not finding.file_path or finding.file_path.startswith("<"):
            continue
        findings_by_file.setdefault(finding.file_path, []).append(finding)

    for file_path, grouped_findings in findings_by_file.items():
        path = Path(file_path)
        if not path.exists():
            continue

        content = path.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=True)
        sorted_findings = sorted(grouped_findings, key=lambda item: item.line_number, reverse=True)

        for finding in sorted_findings:
            if finding.line_number < 1 or finding.line_number > len(lines):
                continue
            if _check_existing_annotation(finding.line_number, content):
                continue

            marker = _get_comment_marker(file_path)
            annotation = _build_annotation(finding, marker)
            insert_position = finding.line_number - 1
            target_line = lines[insert_position]
            indent = len(target_line) - len(target_line.lstrip())
            indent_str = target_line[:indent] if indent > 0 else ""
            indented_annotation = "\n".join(indent_str + line for line in annotation.split("\n")) + "\n"
            lines.insert(insert_position, indented_annotation)

        annotated[file_path] = "".join(lines)

    return annotated
