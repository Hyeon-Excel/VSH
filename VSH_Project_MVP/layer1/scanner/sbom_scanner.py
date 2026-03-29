from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List

from packaging.version import parse as parse_version

from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from shared.contracts import BaseScanner
from shared.logging_utils import get_logger

try:
    from config import VULNERABLE_PACKAGES
except ImportError:
    VULNERABLE_PACKAGES = {}

LOGGER = get_logger(__name__)
MANIFEST_FILES = [
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
]
REQ_RE = re.compile(r"^([a-zA-Z0-9_\-.@/]+)(?:[=!<>~]+([0-9a-zA-Z\-.+]+))?")


class SBOMScanner(BaseScanner):
    """스캔 대상 path를 기준으로 project root의 dependency manifest를 수집한다."""

    def scan(self, file_path: str) -> ScanResult:
        target = Path(file_path)
        root = self._guess_project_root(target)
        findings: List[Vulnerability] = []

        for manifest in self._collect_manifests(root):
            for line_no, package_name, package_version, raw_line in self._extract_packages(manifest):
                vuln_info = VULNERABLE_PACKAGES.get(package_name.lower())
                if not vuln_info:
                    continue
                vulnerable_below = vuln_info.get("vulnerable_below")
                is_vulnerable = not package_version or (vulnerable_below and parse_version(package_version) < parse_version(vulnerable_below))
                if not is_vulnerable:
                    continue
                findings.append(Vulnerability(
                    file_path=str(manifest),
                    rule_id="VSH-SBOM-001",
                    cwe_id="CWE-829",
                    severity="HIGH",
                    line_number=line_no,
                    code_snippet=raw_line,
                    metadata={
                        "ecosystem": self._infer_ecosystem(manifest.name),
                        "package": package_name,
                        "version": package_version,
                        "sbom_source": manifest.name,
                    },
                ))

        return ScanResult(file_path=str(root), language="multi", findings=findings)

    def supported_languages(self) -> List[str]:
        return ["python", "javascript", "typescript", "multi"]

    def _guess_project_root(self, target: Path) -> Path:
        path = target if target.is_dir() else target.parent
        for current in [path, *path.parents]:
            if any((current / manifest).exists() for manifest in MANIFEST_FILES):
                return current
        return path

    def _collect_manifests(self, root: Path) -> Iterable[Path]:
        for file_name in MANIFEST_FILES:
            manifest = root / file_name
            if manifest.exists() and manifest.is_file():
                yield manifest

    def _extract_packages(self, manifest: Path) -> Iterable[tuple[int, str, str | None, str]]:
        text = manifest.read_text(encoding="utf-8", errors="ignore")
        if manifest.name == "package.json":
            try:
                import json
                data = json.loads(text)
                for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
                    deps = data.get(section, {}) or {}
                    for pkg, ver in deps.items():
                        yielding_line = f"{pkg}@{ver} ({section})"
                        yield 0, pkg, str(ver), yielding_line
                return
            except Exception:
                pass

        if manifest.name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
            for idx, line in enumerate(text.splitlines(), start=1):
                # simple lock file parsing fallback
                if "@" in line and line.strip().startswith("\""):
                    parts = line.strip().strip('"').split("@", 1)
                    if len(parts) == 2:
                        pkg = parts[0]
                        version = parts[1].split(":")[0].strip()
                        if pkg and version:
                            yield idx, pkg, version, line.strip()
                if "version" in line and ":" in line and "\"" in line:
                    m = re.search(r"[\"']([0-9a-zA-Z_\-.]+)[\"']", line)
                    if m:
                        version = m.group(1)
                        # package name may be implied by prior key, ignore for now
            # continue with requirement-file fallback

        for idx, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip().strip(',')
            if not stripped or stripped.startswith("#"):
                continue
            m = REQ_RE.match(stripped.strip('"'))
            if not m:
                continue
            yield idx, m.group(1), m.group(2), stripped

    @staticmethod
    def _infer_ecosystem(manifest_name: str) -> str:
        return "npm" if "package" in manifest_name else "PyPI"
