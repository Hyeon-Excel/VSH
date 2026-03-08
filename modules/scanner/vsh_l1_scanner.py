from __future__ import annotations

from modules.scanner.base_scanner import BaseScanner
from vsh.core.config import VSHConfig
from vsh.core.models import Finding, ScanResult
from vsh.core.utils import guess_language
from vsh.engines.osv_engine import scan_deps_with_osv
from vsh.engines.reachability_engine import annotate_reachability
from vsh.engines.registry_engine import find_hallucinated_packages, extract_imports
from vsh.engines.sbom_engine import generate_sbom
from vsh.engines.semgrep_engine import run_semgrep
from vsh.engines.typosquatting_engine import detect_typosquatting
from vsh.engines.schema_normalizer import normalize_scan_result, normalize_finding, normalize_dep_vuln, normalize_sbom_packages
from vsh.engines.code_annotator import annotate_files


class VSHL1Scanner(BaseScanner):
    """L1 hot-path scanner that aggregates static security signals.
    
    Extended with:
    - Typosquatting detection (similar packages in registries)
    - Schema normalization (Finding/DependencyVuln -> VulnRecord/PackageRecord)
    - Optional code annotation (scan_only vs scan+annotate modes)

    Responsibilities are intentionally constrained to detection only:
    - code finding detection (Semgrep/pattern fallback)
    - dependency inventory + OSV matching
    - hallucinated package detection
    - typosquatting package detection (NEW)
    - light reachability annotation
    - normalized schema conversion (NEW)
    - optional code annotation (NEW)

    It does NOT print, call LLMs, generate reports, or write output files.
    """

    def __init__(self, cfg: VSHConfig):
        self._cfg = cfg
        self._sbom = None  # Cache SBOM data for normalization

    def scan(self) -> ScanResult:
        """Run L1 scan with all detection engines and return normalized results."""
        language = self._cfg.language or guess_language(self._cfg.project_root)

        # Core detections
        findings = run_semgrep(self._cfg, language)
        findings = annotate_reachability(self._cfg.project_root, language, findings)

        hallucinated_packages = find_hallucinated_packages(self._cfg, language)

        sbom = generate_sbom(self._cfg)
        self._sbom = sbom  # Cache for normalization
        dep_vulns = scan_deps_with_osv(self._cfg, sbom)

        # Process hallucinated packages as findings
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

        # NEW: Typosquatting detection
        imports = extract_imports(self._cfg.project_root, language)
        ecosystem = "npm" if language == "javascript" else "PyPI"
        typosquatting_findings = detect_typosquatting(imports, ecosystem, threshold=0.75)
        all_findings.extend(typosquatting_findings)
        typosquatting_packages = [f.meta.get("package") for f in typosquatting_findings]

        # Construct base ScanResult
        result = ScanResult(
            project=self._cfg.project_root.name,
            findings=all_findings,
            dep_vulns=dep_vulns,
            hallucinated_packages=hallucinated_packages,
            typosquatting_packages=typosquatting_packages,
            notes=[f"layer=L1", f"language={language}", f"sbom_source={sbom.get('source')}"]
        )

        # NEW: Apply schema normalization
        return self._normalize_result(result)

    def _normalize_result(self, result: ScanResult) -> ScanResult:
        """Apply schema normalization to create VulnRecord and PackageRecord."""
        # Normalize findings to VulnRecord
        result.vuln_records = [
            normalize_finding(f, i + 1) 
            for i, f in enumerate(result.findings)
        ]
        
        # Normalize dependency vulnerabilities to PackageRecord
        dep_pkg_count = len(result.dep_vulns)
        result.package_records = [
            normalize_dep_vuln(dv, i + 1) 
            for i, dv in enumerate(result.dep_vulns)
        ]
        
        # Normalize SBOM packages to PackageRecord
        if self._sbom:
            sbom_packages = normalize_sbom_packages(self._sbom, dep_pkg_count + 1)
            result.package_records.extend(sbom_packages)
        
        return result

    def annotate(self, result: ScanResult) -> ScanResult:
        """
        Inject vulnerability annotations into source code files.
        
        Args:
            result: ScanResult (typically from scan())
        
        Returns:
            ScanResult with annotated_files populated
        """
        result.annotated_files = annotate_files(result.vuln_records, self._cfg.project_root)
        return result
