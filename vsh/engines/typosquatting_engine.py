"""
Typosquatting detection engine.

Detects packages that are not hallucinated (exist in registry) but are
highly similar to well-known packages, suggesting possible typosquatting attacks.
"""

from vsh.core.models import Finding


def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _similarity_ratio(s1: str, s2: str) -> float:
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    distance = _levenshtein_distance(s1, s2)
    return 1.0 - (distance / max_len)


def _normalize_name(name: str) -> str:
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "$": "s", "@": "a"})
    return name.lower().translate(table).replace("-", "").replace("_", "")


def _score_candidate(pkg_norm: str, candidate_norm: str, raw_similarity: float) -> float:
    score = raw_similarity
    if candidate_norm.startswith(pkg_norm) or pkg_norm.startswith(candidate_norm):
        score += 0.05
    if abs(len(pkg_norm) - len(candidate_norm)) <= 1:
        score += 0.05
    return min(score, 1.0)


TOP_PYPI_PACKAGES = {
    "pip", "setuptools", "wheel", "numpy", "pandas", "requests", "django", "flask", "pytest", "scipy", "matplotlib",
    "scikit-learn", "tensorflow", "pytorch", "opencv", "pillow", "beautifulsoup4", "sqlalchemy", "celery", "redis",
    "pymongo", "psycopg2", "mysql", "sqlite3", "boto3", "azure", "google-cloud", "pydantic", "fastapi", "httpx",
}

TOP_NPM_PACKAGES = {
    "react", "angular", "vue", "svelte", "next", "express", "fastify", "webpack", "vite", "babel", "typescript",
    "eslint", "prettier", "jest", "mocha", "vitest", "playwright", "lodash", "rxjs", "axios", "uuid", "mongodb",
    "mysql2", "pg", "sqlite3", "redis", "aws-sdk", "firebase", "prisma", "sequelize", "dotenv", "winston",
}


def detect_typosquatting(imports: set[str], ecosystem: str, threshold: float = 0.75) -> list[Finding]:
    candidates = TOP_PYPI_PACKAGES if ecosystem == "PyPI" else TOP_NPM_PACKAGES
    findings: list[Finding] = []

    for pkg in imports:
        best_match = None
        best_score = 0.0
        pkg_norm = _normalize_name(pkg)

        for candidate in candidates:
            cand_norm = _normalize_name(candidate)
            if pkg_norm == cand_norm:
                continue
            if abs(len(pkg_norm) - len(cand_norm)) > 3:
                continue

            similarity = _similarity_ratio(pkg_norm, cand_norm)
            score = _score_candidate(pkg_norm, cand_norm, similarity)
            if score > best_score:
                best_score = score
                best_match = candidate

        if best_score >= threshold and best_match:
            severity = "CRITICAL" if best_score > 0.9 else "HIGH" if best_score > 0.85 else "MEDIUM"
            findings.append(
                Finding(
                    id=f"VSH-TYPOSQUATTING-{pkg.upper()[:3]}",
                    title=f"Potential typosquatting package detected: '{pkg}' vs '{best_match}'",
                    severity=severity,
                    cwe="CWE-1104",
                    file="<dependency-scan>",
                    line=1,
                    message=(
                        f"Package '{pkg}' is suspiciously similar to well-known package '{best_match}' "
                        f"(risk score: {best_score:.2%}). This may be a typosquatting attack."
                    ),
                    recommendation=f"Verify package name is correct. Did you mean '{best_match}'?",
                    meta={
                        "engine": "typosquatting",
                        "package": pkg,
                        "similar_to": best_match,
                        "similarity_score": best_score,
                        "ecosystem": ecosystem,
                    },
                )
            )

    return findings
