from __future__ import annotations

import json
from pathlib import Path

from layer1.scanner.vsh_l1_scanner import VSHL1Scanner
from layer2.reasoning import L2ReasoningPipeline
from reporting.report_engine import ReportEngine
from vsh_runtime.diagnostics import build_inline_preview, build_markdown_preview, vuln_to_diagnostic
from vsh_runtime.risk import compute_package_risk, compute_vuln_risk
from vsh_runtime.sca_usage import build_package_usage_index


class VshRuntimeEngine:
    def __init__(self):
        self.l1 = VSHL1Scanner()
        self.l2 = L2ReasoningPipeline()
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

        diagnostics = [vuln_to_diagnostic(v).to_dict() for v in vulns]
        aggregate = self._build_aggregate(vulns, pkgs)

        report_payload = {
            "vuln_records": vulns,
            "package_records": pkgs,
            "l2_reasoning_results": reasoning,
            "l3_validation_results": [{"status": "queued", "mode": "cold_path"}],
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
