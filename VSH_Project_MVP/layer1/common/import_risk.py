import re
import sys
from pathlib import Path

from models.vulnerability import Vulnerability

PY_IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([a-zA-Z0-9_\.]+)", re.MULTILINE)
JS_IMPORT_RE = re.compile(r"(?:import\s+.*?from\s+|require\()\s*[\"']([@a-zA-Z0-9_\-/]+)[\"']")

TOP_PYPI_PACKAGES = {
    "requests",
    "numpy",
    "pandas",
    "django",
    "flask",
    "pytest",
    "pydantic",
    "fastapi",
    "httpx",
    "sqlalchemy",
    "scipy",
    "matplotlib",
    "tensorflow",
    "torch",
    "pillow",
    "beautifulsoup4",
    "celery",
    "redis",
    "boto3",
    "psycopg2",
}

TOP_NPM_PACKAGES = {
    "react",
    "express",
    "typescript",
    "lodash",
    "axios",
    "webpack",
    "vite",
    "eslint",
    "prettier",
    "jest",
    "next",
    "vue",
    "rxjs",
    "uuid",
    "mongodb",
    "dotenv",
}

PY_STDLIB = set(getattr(sys, "stdlib_module_names", ()))


def guess_language(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    if suffix in {".js", ".jsx", ".mjs"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    return "python"


def _normalize_name(name: str) -> str:
    table = str.maketrans(
        {
            "0": "o",
            "1": "l",
            "3": "e",
            "5": "s",
            "7": "t",
            "$": "s",
            "@": "a",
            "µ": "u",
            "ı": "i",
            "ο": "o",
            "а": "a",
            "е": "e",
            "р": "p",
            "с": "c",
        }
    )
    return name.lower().translate(table).replace("-", "").replace("_", "")


def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if not s2:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _similarity_ratio(s1: str, s2: str) -> float:
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    return 1.0 - (_levenshtein_distance(s1, s2) / max_len)


def _extract_import_lines(file_path: str, language: str) -> list[tuple[str, int, str]]:
    text = Path(file_path).read_text(encoding="utf-8")
    lines = text.splitlines()
    imports: list[tuple[str, int, str]] = []

    if language == "python":
        for idx, line in enumerate(lines, start=1):
            match = PY_IMPORT_RE.search(line)
            if not match:
                continue
            module = match.group(1).split(".")[0]
            if not module or module.startswith("_"):
                continue
            if module in PY_STDLIB:
                continue
            imports.append((module, idx, line.strip()))
        return imports

    for idx, line in enumerate(lines, start=1):
        match = JS_IMPORT_RE.search(line)
        if not match:
            continue
        module = match.group(1)
        if module.startswith("."):
            continue
        if "/" in module and not module.startswith("@"):
            module = module.split("/")[0]
        imports.append((module, idx, line.strip()))
    return imports


def detect_typosquatting_findings(file_path: str) -> list[Vulnerability]:
    language = guess_language(file_path)
    ecosystem = "PyPI" if language == "python" else "npm"
    top_packages = TOP_PYPI_PACKAGES if ecosystem == "PyPI" else TOP_NPM_PACKAGES
    findings: list[Vulnerability] = []

    for package_name, line_number, code_snippet in _extract_import_lines(file_path, language):
        normalized = _normalize_name(package_name)
        best_match = None
        best_score = 0.0

        for candidate in top_packages:
            candidate_normalized = _normalize_name(candidate)
            if normalized == candidate_normalized:
                best_match = None
                best_score = 0.0
                break
            if abs(len(normalized) - len(candidate_normalized)) > 4:
                continue
            score = _similarity_ratio(normalized, candidate_normalized)
            if score > best_score:
                best_score = score
                best_match = candidate

        if best_match and best_score >= 0.75:
            severity = "HIGH" if best_score >= 0.90 else "MEDIUM"
            findings.append(
                Vulnerability(
                    file_path=file_path,
                    rule_id="VSH-IMPORT-TYPOSQUATTING-001",
                    cwe_id="CWE-1104",
                    severity=severity,
                    line_number=line_number,
                    code_snippet=code_snippet,
                    references=["OWASP A08:2021"],
                    metadata={
                        "engine": "typosquatting",
                        "package": package_name,
                        "similar_to": best_match,
                        "similarity_score": round(best_score, 2),
                        "ecosystem": ecosystem,
                    },
                )
            )

    return findings
