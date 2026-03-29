from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from layer2.reasoning.models import L2ReasoningResult
from models.common_schema import VulnRecord

DANGEROUS_PATTERNS = {
    "eval_input": (r"\beval\(.*input\(.*\)", "eval() with user input"),
    "subprocess_shell": (r"subprocess\.(Popen|run|call)\(.*shell\s*=\s*True.*", "subprocess shell=True"),
    "pickle_load": (r"pickle\.loads?\(", "unsafe pickle load"),
    "yaml_load": (r"yaml\.load\(", "unsafe yaml.load"),
}


class L3Validator:
    def __init__(self):
        self.cache: dict[str, dict[str, Any]] = {}

    def validate(self, vuln: VulnRecord, reasoning: L2ReasoningResult | None = None) -> dict[str, Any]:
        if not vuln or not isinstance(vuln, VulnRecord):
            raise L3ValidationError("invalid vuln record object")

        key = f"{vuln.file_path}:{vuln.line_number}:{vuln.cwe_id}"
        if key in self.cache:
            return self.cache[key]

        l2_conf = 0.0
        l2_attack = "unknown"
        l2_severity_override = vuln.severity

        if reasoning:
            if isinstance(reasoning, dict):
                l2_conf = float(reasoning.get("confidence", 0.0))
                l2_attack = reasoning.get("attack_scenario", "unknown")
                l2_severity_override = reasoning.get("severity_override", vuln.severity)
            else:
                l2_conf = getattr(reasoning, "confidence", 0.0) or 0.0
                l2_attack = getattr(reasoning, "attack_scenario", "unknown") or "unknown"
                l2_severity_override = getattr(reasoning, "severity_override", vuln.severity) or vuln.severity

        result = {
            "vulnerability_id": vuln.vuln_id,
            "validated": False,
            "exploit_possible": False,
            "confidence": 0.0,
            "evidence": "",
            "recommended_fix": vuln.fix_suggestion or "Review this code path and harden input handling.",
            "attack_scenario": l2_attack,
            "severity_override": l2_severity_override,
            "details": {
                "source_file": vuln.file_path,
                "source_line": vuln.line_number,
                "vuln_type": vuln.vuln_type,
                "l2_confidence": l2_conf,
            },
        }

        file_path = Path(vuln.file_path)
        if not file_path.exists():
            result.update({"validated": False, "exploit_possible": False, "confidence": 0.0, "evidence": "file not found"})
            self.cache[key] = result
            return result

        code = file_path.read_text(encoding="utf-8", errors="ignore")
        target_line = vuln.line_number
        lines = code.splitlines()
        if 1 <= target_line <= len(lines):
            snippet = lines[target_line - 1]
        else:
            snippet = ""

        conditions = []

        for name, (pattern, description) in DANGEROUS_PATTERNS.items():
            if re.search(pattern, snippet):
                conditions.append(description)

        if not conditions:
            # expand to surrounding context for deeper path analysis
            window = "\n".join(lines[max(0, target_line - 5):min(len(lines), target_line + 4)])
            for name, (pattern, description) in DANGEROUS_PATTERNS.items():
                if re.search(pattern, window):
                    conditions.append(description)

        reachable = True

        if conditions:
            result.update({
                "validated": True,
                "exploit_possible": True,
                "confidence": min(1.0, l2_conf + 0.4),
                "evidence": "; ".join(conditions),
                "recommended_fix": vuln.fix_suggestion or "Avoid unsafe API; validate/escape input or use safer alternatives.",
            })
        else:
            result.update({
                "validated": True,
                "exploit_possible": False,
                "confidence": max(0.2, l2_conf),
                "evidence": "No immediate high-risk pattern found; needs manual verification.",
            })

        result["details"]["reachable"] = reachable

        self.cache[key] = result
        return result

    def validate_many(self, vulns: list[VulnRecord], reasoning_map: dict[str, L2ReasoningResult] | None = None) -> list[dict[str, Any]]:
        reasoning_map = reasoning_map or {}
        results = []

        for vuln in vulns:
            reasoning = reasoning_map.get(vuln.vuln_id)
            results.append(self.validate(vuln, reasoning))

        return results
