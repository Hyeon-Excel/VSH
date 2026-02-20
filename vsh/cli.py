import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table

from vsh.core.config import VSHConfig
from vsh.core.models import ScanResult
from vsh.core.utils import guess_language
from vsh.engines.semgrep_engine import run_semgrep
from vsh.engines.registry_engine import find_hallucinated_packages
from vsh.engines.sbom_engine import generate_sbom
from vsh.engines.osv_engine import scan_deps_with_osv
from vsh.engines.reachability_engine import annotate_reachability
from vsh.engines.report_engine import calc_score, make_inline_comment, write_markdown_report

console = Console()

def scan(cfg: VSHConfig) -> ScanResult:
    lang = cfg.language or guess_language(cfg.project_root)

    findings = run_semgrep(cfg, lang)
    findings = annotate_reachability(cfg.project_root, lang, findings)

    hallucinated = find_hallucinated_packages(cfg, lang)

    sbom = generate_sbom(cfg)
    dep_vulns = scan_deps_with_osv(cfg, sbom)

    result = ScanResult(
        project=cfg.project_root.name,
        findings=findings,
        dep_vulns=dep_vulns,
        hallucinated_packages=hallucinated,
        notes=[f"language={lang}", f"sbom_source={sbom.get('source')}"]
    )
    result.score = calc_score(result.findings, result.dep_vulns, result.hallucinated_packages)
    return result

def print_summary(result: ScanResult):
    t = Table(title="VSH Scan Summary")
    t.add_column("Type")
    t.add_column("Count")
    t.add_row("Code Findings", str(len(result.findings)))
    t.add_row("Dependency Vulns (OSV)", str(len(result.dep_vulns)))
    t.add_row("Hallucinated Packages", str(len(result.hallucinated_packages)))
    t.add_row("Score", str(result.score))
    console.print(t)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("project", help="Path to target project")
    ap.add_argument("--out", default="vsh_out", help="Output directory")
    ap.add_argument("--lang", default=None, choices=[None,"python","javascript"], help="Force language")
    ap.add_argument("--no-syft", action="store_true", help="Disable syft SBOM")
    args = ap.parse_args()

    project_root = Path(args.project).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    cfg = VSHConfig(
        project_root=project_root,
        out_dir=out_dir,
        language=args.lang,
        use_syft=not args.no_syft
    )

    result = scan(cfg)
    print_summary(result)

    # write report
    report_path = out_dir / "VSH_REPORT.md"
    write_markdown_report(report_path, result)
    console.print(f"[green]Report written:[/green] {report_path}")

    # demo inline comment output (pick top 1-3)
    if result.findings:
        console.print("\n[bold]Inline comment demo:[/bold]")
        for f in result.findings[:3]:
            console.print(make_inline_comment(f))

    if result.hallucinated_packages:
        console.print("\n[bold red]Hallucinated packages:[/bold red]")
        for p in result.hallucinated_packages:
            console.print(f"- {p}")

if __name__ == "__main__":
    main()
