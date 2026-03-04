from __future__ import annotations

from modules.scanner.base_scanner import BaseScanner
from vsh.core.config import VSHConfig
from vsh.core.models import Finding, ScanResult
from vsh.core.utils import guess_language
from vsh.engines.osv_engine import scan_deps_with_osv
from vsh.engines.reachability_engine import annotate_reachability
from vsh.engines.registry_engine import find_hallucinated_packages
from vsh.engines.sbom_engine import generate_sbom
from vsh.engines.semgrep_engine import run_semgrep


class VSHL1Scanner(BaseScanner):
    """L1 hot-path scanner that aggregates static security signals.

    Responsibilities are intentionally constrained to detection only:
    - code finding detection (Semgrep/pattern fallback)
    - dependency inventory + OSV matching
    - hallucinated package detection
    - light reachability annotation

    It does NOT print, call LLMs, generate reports, or write output files.
    """

    def __init__(self, cfg: VSHConfig):
        self._cfg = cfg

    def scan(self) -> ScanResult:
        language = self._cfg.language or guess_language(self._cfg.project_root)

        findings = run_semgrep(self._cfg, language)
        findings = annotate_reachability(self._cfg.project_root, language, findings)

        hallucinated_packages = find_hallucinated_packages(self._cfg, language)

        sbom = generate_sbom(self._cfg)
        dep_vulns = scan_deps_with_osv(self._cfg, sbom)

        finding_by_pkg = [
            Finding(
                id="VSH-PKG-HALLUCINATION-001",
                title="Registry-missing dependency import detected",
                severity="MEDIUM",
                cwe="CWE-1104",
                file="<dependency-scan>",
                line=1,
                message=f"Imported package '{pkg}' was not found in registry index.",
                recommendation="Validate package spelling and trust source before installation.",
                meta={"engine": "registry", "package": pkg},
            )
            for pkg in hallucinated_packages
        ]

        all_findings = findings + finding_by_pkg

        return ScanResult(
            project=self._cfg.project_root.name,
            findings=all_findings,
            dep_vulns=dep_vulns,
            hallucinated_packages=hallucinated_packages,
            notes=[f"layer=L1", f"language={language}", f"sbom_source={sbom.get('source')}"]
        )
