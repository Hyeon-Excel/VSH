from __future__ import annotations

import re
from pathlib import Path

try:
    from config import VULNERABLE_PACKAGES
except ImportError:
    VULNERABLE_PACKAGES = {}

ADVISORY_PATTERNS = {
    "requests": [r"requests\.(get|post|request)", r"Session\("],
    "pyyaml": [r"yaml\.load\("],
    "django": [r"django\.", r"from django"],
    "flask": [r"from flask", r"flask\."],
}

PY_IMPORT = re.compile(r"^\s*(?:import\s+([a-zA-Z0-9_\.]+)|from\s+([a-zA-Z0-9_\.]+)\s+import\s+(.+))", re.MULTILINE)
JS_IMPORT = re.compile(r"import\s+.*?from\s+['\"]([^'\"]+)['\"]|require\(['\"]([^'\"]+)['\"]\)")


def _iter_code_files(root: Path):
    for f in root.rglob("*"):
        if f.is_file() and f.suffix.lower() in {".py", ".js", ".ts", ".jsx", ".tsx"}:
            yield f


def build_package_usage_index(project_root: str) -> dict:
    root = Path(project_root)
    index: dict[str, dict] = {}
    for pkg, info in VULNERABLE_PACKAGES.items():
        index[pkg] = {
            "package": pkg,
            "advisory_id": info.get("cve"),
            "advisory_source": "mock-offline-dataset",
            "imports": [],
            "api_references": [],
            "usage_status": "package_present",
            "affected_api_patterns": ADVISORY_PATTERNS.get(pkg, []),
            "exploitability_hint": "heuristic",
        }

    for file in _iter_code_files(root):
        text = file.read_text(encoding="utf-8", errors="ignore")
        for pkg in index:
            imported = False
            if file.suffix.lower() == ".py":
                for m in PY_IMPORT.finditer(text):
                    mod = (m.group(1) or m.group(2) or "").split(".")[0]
                    if mod == pkg:
                        imported = True
                        index[pkg]["imports"].append({"file": str(file), "line": text[: m.start()].count("\n") + 1})
            else:
                for m in JS_IMPORT.finditer(text):
                    mod = (m.group(1) or m.group(2) or "").split("/")[0]
                    if mod == pkg:
                        imported = True
                        index[pkg]["imports"].append({"file": str(file), "line": text[: m.start()].count("\n") + 1})
            if imported:
                index[pkg]["usage_status"] = "package_imported"

            for pattern in index[pkg]["affected_api_patterns"]:
                for match in re.finditer(pattern, text):
                    index[pkg]["api_references"].append({"file": str(file), "line": text[: match.start()].count("\n") + 1, "pattern": pattern})

            if index[pkg]["api_references"]:
                index[pkg]["usage_status"] = "vulnerable_api_referenced"
            elif imported and index[pkg]["imports"]:
                index[pkg]["usage_status"] = "package_imported"

    for pkg, payload in index.items():
        if payload["usage_status"] == "package_imported" and payload["affected_api_patterns"]:
            payload["usage_status"] = "needs_manual_review"
        if payload["usage_status"] == "vulnerable_api_referenced":
            payload["exploitability_hint"] = "high"

    return index
