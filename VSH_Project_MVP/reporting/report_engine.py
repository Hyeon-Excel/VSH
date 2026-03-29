from __future__ import annotations

import json
from pathlib import Path


class ReportEngine:
    def write_json(self, path: str, payload: dict) -> None:
        Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def write_markdown(self, path: str, payload: dict) -> None:
        agg = payload.get("aggregate_summary", {})
        lines = [
            "# VSH Integrated Security Report",
            "## High-level summary",
            f"- Final score: **{agg.get('final_score', 0)}**",
            f"- Reachable issue count: **{agg.get('reachable_issue_count', 0)}**",
            f"- High-priority package risk count: **{agg.get('high_priority_package_risk_count', 0)}**",
            "",
            "## Top risks",
        ]
        for item in sorted(payload.get("vuln_records", []), key=lambda x: x.get("risk_score", 0), reverse=True)[:5]:
            lines.append(f"- {item.get('final_priority')} | {item.get('cwe_id')} | {item.get('file_path')}:{item.get('line_number')} | score={item.get('risk_score')}")

        lines.append("\n## Reachable issues")
        for item in payload.get("vuln_records", []):
            if item.get("reachability_status") == "reachable":
                lines.append(f"- {item.get('cwe_id')} @ {item.get('file_path')}:{item.get('line_number')}")

        lines.append("\n## Vulnerable package usage")
        for pkg in payload.get("package_records", []):
            lines.append(f"- {pkg.get('name')} {pkg.get('version')} | usage={pkg.get('usage_status')} | priority={pkg.get('final_priority')}")

        lines.append("\n## L2 reasoning verdict")
        for r in payload.get("l2_reasoning_results", []):
            lines.append(f"- {r.get('linked_vuln_id')}: {r.get('verdict')} ({r.get('confidence')})")

        lines.append("\n## L3 validation status")
        for r in payload.get("l3_validation_results", []):
            lines.append(f"- {r}")

        lines.append("\n## Limitations")
        lines.append("- L1/L2 결과는 정적/휴리스틱 기반이며 runtime proof는 L3에서 다룸.")
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
