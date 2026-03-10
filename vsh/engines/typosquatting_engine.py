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
    table = str.maketrans({
        "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "$": "s", "@": "a",
        "µ": "u", "ı": "i", "ο": "o", "а": "a", "е": "e", "р": "p", "с": "c",
    })
    return name.lower().translate(table).replace("-", "").replace("_", "")


def _score_candidate(pkg: str, candidate: str, pkg_norm: str, candidate_norm: str, raw_similarity: float, popularity: int) -> float:
    score = raw_similarity

    # prefix/suffix/namespace confusion
    if candidate_norm.startswith(pkg_norm) or pkg_norm.startswith(candidate_norm):
        score += 0.05
    if pkg_norm.endswith(candidate_norm) or candidate_norm.endswith(pkg_norm):
        score += 0.03

    # small length difference likely typo
    if abs(len(pkg_norm) - len(candidate_norm)) <= 1:
        score += 0.05

    # popular target package => more suspicious
    if popularity >= 95:
        score += 0.03

    # package has suspicious addon tokens around popular package
    suspicious_tokens = ("security", "official", "core", "plus", "utils", "sdk")
    if any(token in pkg.lower() for token in suspicious_tokens) and candidate.lower() in pkg.lower():
        score += 0.04

    return min(score, 1.0)


TOP_PYPI_PACKAGES = {
    "requests": 100, "numpy": 100, "pandas": 98, "django": 97, "flask": 96, "pytest": 95,
    "pydantic": 95, "fastapi": 94, "httpx": 92, "sqlalchemy": 92, "scipy": 90,
    "matplotlib": 90, "tensorflow": 88, "torch": 88, "pillow": 86, "beautifulsoup4": 84,
    "celery": 83, "redis": 83, "boto3": 82, "psycopg2": 80,
}

TOP_NPM_PACKAGES = {
    "react": 100, "express": 99, "typescript": 98, "lodash": 97, "axios": 96, "webpack": 95,
    "vite": 95, "eslint": 94, "prettier": 94, "jest": 93, "next": 93,
    "vue": 92, "rxjs": 91, "uuid": 90, "mongodb": 89, "dotenv": 88,
}


def detect_typosquatting(imports: set[str], ecosystem: str, threshold: float = 0.75) -> list[Finding]:
    candidates = TOP_PYPI_PACKAGES if ecosystem == "PyPI" else TOP_NPM_PACKAGES
    findings: list[Finding] = []

    for pkg in imports:
        pkg_norm = _normalize_name(pkg)
        best_match = None
        best_score = 0.0
        ranked: list[tuple[str, float]] = []

        for candidate, popularity in candidates.items():
            candidate_norm = _normalize_name(candidate)
            if pkg_norm == candidate_norm:
                continue
            if abs(len(pkg_norm) - len(candidate_norm)) > 4:
                continue

            similarity = _similarity_ratio(pkg_norm, candidate_norm)
            score = _score_candidate(pkg, candidate, pkg_norm, candidate_norm, similarity, popularity)
            ranked.append((candidate, score))
            if score > best_score:
                best_score = score
                best_match = candidate

        if best_score >= threshold and best_match:
            severity = "CRITICAL" if best_score > 0.92 else "HIGH" if best_score > 0.86 else "MEDIUM"
            top_k = [name for name, _ in sorted(ranked, key=lambda x: x[1], reverse=True)[:3]]
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
                        "top_candidates": top_k,
                        "ecosystem": ecosystem,
                    },
                )
            )

    return findings
