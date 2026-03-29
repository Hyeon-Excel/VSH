from __future__ import annotations

SEV = {"CRITICAL": 95, "HIGH": 78, "MEDIUM": 55, "LOW": 30}
VERDICT_BONUS = {"likely_vulnerable": 15, "suspicious": 5, "not_vulnerable": -15, "needs_review": 0, None: 0}
REACH_BONUS = {"reachable": 10, "unknown": 3, "unreachable": -5, None: 0}
PACKAGE_USAGE_BONUS = {
    "vulnerable_api_referenced": 20,
    "reachable_package_risk": 15,
    "package_imported": 7,
    "package_present": 2,
    "needs_manual_review": 5,
    None: 0,
}


def priority_from_score(score: float) -> str:
    if score >= 90:
        return "P1"
    if score >= 75:
        return "P2"
    if score >= 55:
        return "P3"
    if score >= 35:
        return "P4"
    return "INFO"


def compute_vuln_risk(vuln: dict, reasoning: dict | None = None) -> tuple[float, str]:
    score = SEV.get(vuln.get("severity"), 20)
    score += REACH_BONUS.get(vuln.get("reachability_status"), 0)
    verdict = reasoning.get("verdict") if reasoning else vuln.get("reasoning_verdict")
    score += VERDICT_BONUS.get(verdict, 0)
    if reasoning:
        score += int(float(reasoning.get("confidence", 0.5)) * 5)
    score = max(0.0, min(100.0, float(score)))
    return score, priority_from_score(score)


def compute_package_risk(pkg: dict) -> tuple[float, str]:
    base = SEV.get(pkg.get("severity"), 20)
    score = base + PACKAGE_USAGE_BONUS.get(pkg.get("usage_status"), 0)
    score = max(0.0, min(100.0, float(score)))
    return score, priority_from_score(score)
