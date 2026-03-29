from __future__ import annotations

from pathlib import Path

from models.common_schema import VulnRecord


def extract_finding_context(vuln: VulnRecord, around: int = 6, max_chars: int = 4000) -> dict:
    path = Path(vuln.file_path)
    if not path.exists() or not path.is_file():
        return {"target_line": vuln.line_number, "snippet": vuln.evidence, "imports": [], "context": vuln.evidence}

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    ln = max(1, min(vuln.line_number, len(lines)))
    start, end = max(1, ln - around), min(len(lines), ln + around)
    window = lines[start - 1 : end]
    imports = [l.strip() for l in lines[: min(200, len(lines))] if l.strip().startswith(("import ", "from ")) or "require(" in l or "import " in l]
    context = "\n".join(f"{i}:{lines[i-1]}" for i in range(start, end + 1))
    if len(context) > max_chars:
        context = context[:max_chars]
    return {"target_line": ln, "snippet": lines[ln - 1], "imports": imports[:25], "context": context}
