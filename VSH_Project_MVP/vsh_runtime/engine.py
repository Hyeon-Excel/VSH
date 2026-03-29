from __future__ import annotations

import json
from pathlib import Path

from layer1.scanner.vsh_l1_scanner import VSHL1Scanner
from layer1.common import annotate_files
from layer2.reasoning import L2ReasoningPipeline
from models.common_schema import VulnRecord
from models.vulnerability import Vulnerability
from reporting.report_engine import ReportEngine
from vsh_runtime.diagnostics import build_inline_preview, build_markdown_preview, vuln_to_diagnostic
from vsh_runtime.l3_validator import L3Validator
from vsh_runtime.risk import compute_package_risk, compute_vuln_risk
from vsh_runtime.sca_usage import build_package_usage_index


class VshRuntimeEngine:
    def __init__(self):
        self.l1 = VSHL1Scanner()
        self.l2 = L2ReasoningPipeline()
        self.l3 = L3Validator()
        self.report = ReportEngine()

    def analyze_file(self, file_path: str) -> dict:
        return self._analyze_target(file_path)

    def analyze_project(self, project_path: str) -> dict:
        return self._analyze_target(project_path)

    def get_diagnostics(self, target_path: str) -> dict:
        analyzed = self._analyze_target(target_path)
        return {"diagnostics": analyzed["diagnostics"], "target": target_path}

    def _analyze_target(self, target_path: str) -> dict:
        scan_result = self.l1.scan(target_path)
        reasoning = self.l2.run(scan_result.vuln_records)
        reasoning_by_id = {r["linked_vuln_id"]: r for r in reasoning}

        vulns = [v.model_dump() for v in scan_result.vuln_records]
        pkgs = [p.model_dump() for p in scan_result.package_records]
        usage_index = build_package_usage_index(str(Path(target_path) if Path(target_path).is_dir() else Path(target_path).parent))

        for v in vulns:
            r = reasoning_by_id.get(v.get("vuln_id"))
            if r:
                v["reasoning_verdict"] = r["verdict"]
            score, pri = compute_vuln_risk(v, r)
            v["risk_score"] = score
            v["final_priority"] = pri

        for p in pkgs:
            usage = usage_index.get(p["name"].lower(), {})
            p.update({
                "advisory_id": usage.get("advisory_id"),
                "advisory_source": usage.get("advisory_source"),
                "affected_api_patterns": usage.get("affected_api_patterns", []),
                "exploitability_hint": usage.get("exploitability_hint"),
                "usage_status": usage.get("usage_status", p.get("usage_status")),
                "affected_module": usage.get("imports", [{}])[0].get("file") if usage.get("imports") else None,
                "affected_symbol": usage.get("api_references", [{}])[0].get("pattern") if usage.get("api_references") else None,
            })
            score, pri = compute_package_risk(p)
            p["risk_score"] = score
            p["final_priority"] = pri

        reasoning_map = {r["linked_vuln_id"]: r for r in reasoning}
        l3_results = self.l3.validate_many([VulnRecord(**v) for v in vulns], reasoning_map=reasoning_map) if vulns else []

        # annotate vuln_records with L3 cache and inferred final
        for v, l3 in zip(vulns, l3_results):
            v["l3_validated"] = l3.get("validated")
            v["exploit_possible"] = l3.get("exploit_possible")
            v["l3_confidence"] = l3.get("confidence")
            v["l3_attack_scenario"] = l3.get("attack_scenario")
            v["l3_severity_override"] = l3.get("severity_override")

        diagnostics = [vuln_to_diagnostic(v).to_dict() for v in vulns]
        aggregate = self._build_aggregate(vulns, pkgs)

        report_payload = {
            "vuln_records": vulns,
            "package_records": pkgs,
            "l2_reasoning_results": reasoning,
            "l3_validation_results": l3_results,
            "diagnostics": diagnostics,
            "aggregate_summary": aggregate,
        }
        report_payload["previews"] = {
            "inline": build_inline_preview(diagnostics),
            "markdown": build_markdown_preview(diagnostics),
            "diagnostics_json": json.dumps(diagnostics, ensure_ascii=False, indent=2),
        }
        return report_payload

    def _build_aggregate(self, vulns: list[dict], pkgs: list[dict]) -> dict:
        dist = {k: 0 for k in ["P1", "P2", "P3", "P4", "INFO"]}
        for v in vulns:
            dist[v.get("final_priority", "INFO")] += 1
        for p in pkgs:
            dist[p.get("final_priority", "INFO")] += 1
        avg = 0.0
        all_scores = [v.get("risk_score", 0) for v in vulns] + [p.get("risk_score", 0) for p in pkgs]
        if all_scores:
            avg = round(sum(all_scores) / len(all_scores), 2)
        return {
            "final_score": avg,
            "risk_distribution": dist,
            "reachable_issue_count": len([v for v in vulns if v.get("reachability_status") == "reachable"]),
            "high_priority_package_risk_count": len([p for p in pkgs if p.get("final_priority") in {"P1", "P2"}]),
        }

    def write_outputs(self, payload: dict, out_dir: str) -> dict:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        json_path = out / "result.json"
        md_path = out / "result.md"
        diag_path = out / "diagnostics.json"
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        self.report.write_markdown(str(md_path), {"summary": {"file_path": "target", "total_vulns": len(payload["vuln_records"]), "total_packages": len(payload["package_records"]), "severity_distribution": {}}, "reachable_issues": payload["vuln_records"]})
        diag_path.write_text(json.dumps(payload["diagnostics"], ensure_ascii=False, indent=2), encoding="utf-8")
        return {"json": str(json_path), "markdown": str(md_path), "diagnostics": str(diag_path)}
    
    def annotate_file(self, file_path: str, in_place: bool = False) -> dict:
        """Analyze a file and generate annotated source code.
        
        Args:
            file_path: Path to the file to annotate
            in_place: If True, overwrite original file. If False, save to .vsh/annotated/
        
        Returns:
            dict with annotated_files mapping and analysis results
        """
        if not Path(file_path).is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Analyze the file
        analysis = self.analyze_file(file_path)
        
        # Convert vuln_records to Vulnerability objects for annotation
        vulns = []
        for v in analysis.get("vuln_records", []):
            try:
                vuln = Vulnerability(
                    vuln_id=v.get("vuln_id"),
                    file_path=v.get("file_path"),
                    line_number=v.get("line_number", 0),
                    column_number=v.get("column_number", 1),
                    severity=v.get("severity", "UNKNOWN"),
                    cwe_id=v.get("cwe_id", ""),
                    rule_id=v.get("rule_id", ""),
                    evidence=v.get("evidence", ""),
                    reachability_status=v.get("reachability_status"),
                    references=[]
                )
                vulns.append(vuln)
            except Exception as e:
                print(f"Warning: Failed to create Vulnerability object: {e}")
        
        # Generate annotated files
        annotated = annotate_files(vulns)
        
        # Save annotated files
        output_paths = {}
        if annotated:
            if in_place:
                # Overwrite original file
                for file_path_key, content in annotated.items():
                    Path(file_path_key).write_text(content, encoding="utf-8")
                    output_paths[file_path_key] = file_path_key
            else:
                # Save to .vsh/annotated/
                vsh_dir = Path(file_path).parent / ".vsh" / "annotated"
                vsh_dir.mkdir(parents=True, exist_ok=True)
                
                for file_path_key, content in annotated.items():
                    rel_path = Path(file_path_key).name
                    output_file = vsh_dir / rel_path
                    output_file.write_text(content, encoding="utf-8")
                    output_paths[file_path_key] = str(output_file)
        
        return {
            "success": True,
            "file": file_path,
            "analysis": analysis,
            "annotated_files": output_paths,
            "in_place": in_place,
            "total_issues": len(vulns)
        }
    
    def annotate_project(self, project_path: str, in_place: bool = False) -> dict:
        """Analyze a project and generate annotated source files.
        
        Args:
            project_path: Path to the project directory
            in_place: If True, overwrite original files. If False, save to .vsh/annotated/
        
        Returns:
            dict with annotated_files mapping and analysis results
        """
        if not Path(project_path).is_dir():
            raise NotADirectoryError(f"Directory not found: {project_path}")
        
        # Analyze the project
        analysis = self.analyze_project(project_path)
        
        # Convert vuln_records to Vulnerability objects for annotation
        vulns = []
        for v in analysis.get("vuln_records", []):
            try:
                vuln = Vulnerability(
                    vuln_id=v.get("vuln_id"),
                    file_path=v.get("file_path"),
                    line_number=v.get("line_number", 0),
                    column_number=v.get("column_number", 1),
                    severity=v.get("severity", "UNKNOWN"),
                    cwe_id=v.get("cwe_id", ""),
                    rule_id=v.get("rule_id", ""),
                    evidence=v.get("evidence", ""),
                    reachability_status=v.get("reachability_status"),
                    references=[]
                )
                vulns.append(vuln)
            except Exception as e:
                print(f"Warning: Failed to create Vulnerability object: {e}")
        
        # Generate annotated files
        annotated = annotate_files(vulns)
        
        # Save annotated files
        output_paths = {}
        if annotated:
            if in_place:
                # Overwrite original files
                for file_path_key, content in annotated.items():
                    Path(file_path_key).write_text(content, encoding="utf-8")
                    output_paths[file_path_key] = file_path_key
            else:
                # Save to .vsh/annotated/ preserving directory structure
                vsh_dir = Path(project_path) / ".vsh" / "annotated"
                vsh_dir.mkdir(parents=True, exist_ok=True)
                
                for file_path_key, content in annotated.items():
                    original = Path(file_path_key)
                    # Try to preserve relative path structure
                    try:
                        rel_path = original.relative_to(Path(project_path))
                        output_file = vsh_dir / rel_path
                        output_file.parent.mkdir(parents=True, exist_ok=True)
                    except ValueError:
                        # File is outside project path, just use filename
                        output_file = vsh_dir / original.name
                    
                    output_file.write_text(content, encoding="utf-8")
                    output_paths[file_path_key] = str(output_file)
        
        return {
            "success": True,
            "project": project_path,
            "analysis": analysis,
            "annotated_files": output_paths,
            "in_place": in_place,
            "total_issues": len(vulns),
            "files_annotated": len(output_paths)
        }
