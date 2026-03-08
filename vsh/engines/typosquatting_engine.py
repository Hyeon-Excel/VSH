"""
Typosquatting detection engine.

Detects packages that are not hallucinated (exist in registry) but are
highly similar to well-known packages, suggesting possible typosquatting attacks.
"""

from vsh.core.models import Finding
import requests


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
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
    """Calculate similarity ratio (0.0 to 1.0)."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    distance = _levenshtein_distance(s1, s2)
    return 1.0 - (distance / max_len)


# Top 100 popular PyPI packages
TOP_PYPI_PACKAGES = {
    "pip", "setuptools", "wheel", "numpy", "pandas", "requests", "django",
    "flask", "pytest", "scipy", "matplotlib", "scikit-learn", "tensorflow",
    "pytorch", "opencv", "pillow", "beautifulsoup4", "sqlalchemy", "celery",
    "redis", "pymongo", "psycopg2", "mysql", "sqlite3", "boto3", "azure",
    "google-cloud", "pydantic", "fastapi", "httpx", "aiohttp", "twisted",
    "requests-html", "lxml", "html5lib", "jinja2", "mako", "babel", "click",
    "typer", "rich", "colorama", "tqdm", "loguru", "python-dotenv", "pyyaml",
    "tomli", "toml", "configparser", "argparse", "pathlib", "dataclasses",
    "typing-extensions", "mypy", "pylint", "black", "flake8", "autopep8",
    "sphinx", "mkdocs", "gitpython", "paramiko", "fabric", "ansible",
    "requests", "urllib3", "certifi", "idna", "chardet", "six", "future",
    "typing_extensions", "enum34", "pathlib2", "contextlib2", "functools32",
    "scandir", "fwdpy11", "cython", "numba", "dask", "distributed", "airflow",
    "luigi", "prefect", "hydra", "wandb", "mlflow", "optuna", "xgboost",
    "lightgbm", "catboost", "transformers", "huggingface", "spacy", "nltk",
    "gensim", "word2vec", "fasttext", "gpt", "bert", "clip", "stable_diffusion",
    "pydantic", "dataclasses-json", "marshmallow", "voluptuous", "cerberus"
}

# Top 100 popular npm packages
TOP_NPM_PACKAGES = {
    "react", "angular", "vue", "svelte", "ember", "next", "nuxt", "gatsby",
    "remix", "astro", "express", "fastify", "koa", "hapi", "nestjs", "apollo",
    "graphql", "webpack", "vite", "parcel", "rollup", "esbuild", "babel",
    "typescript", "eslint", "prettier", "jest", "mocha", "vitest", "cypress",
    "playwright", "testing-library", "sinon", "chai", "jasmine", "qunit",
    "lodash", "underscore", "ramda", "rxjs", "async", "p-queue", "p-limit",
    "axios", "node-fetch", "cross-fetch", "whatwg-fetch", "isomorphic-fetch",
    "supertest", "superagent", "request", "got", "ky", "node-http-proxy",
    "uuid", "shortid", "nanoid", "cuid", "ulid", "mongodb", "mysql2",
    "pg", "sqlite3", "redis", "ioredis", "memcached", "elasticsearch",
    "aws-sdk", "azure-sdk", "google-cloud", "firebase", "supabase",
    "prisma", "sequelize", "typeorm", "orms", "mikro-orm", "drizzle",
    "joi", "yup", "zod", "validator", "class-validator", "computed-types",
    "dotenv", "nconf", "config", "rc", "convict", "cosmiconfig",
    "winston", "pino", "bunyan", "debug", "loglevel", "npmlog",
    "moment", "dayjs", "date-fns", "luxon", "chronology", "temporal",
    "classnames", "clsx", "styled-components", "emotion", "sass", "less",
    "postcss", "autoprefixer", "tailwindcss", "bootstrap", "material-ui"
}


def detect_typosquatting(
    imports: set[str],
    ecosystem: str,
    threshold: float = 0.75,
) -> list[Finding]:
    """
    Detect typosquatting packages based on Levenshtein distance.
    
    Args:
        imports: Set of imported package names
        ecosystem: "PyPI" or "npm"
        threshold: Similarity ratio threshold (0.0-1.0); packages above this are flagged
    
    Returns:
        List of Finding objects for suspected typosquatting
    """
    candidates = TOP_PYPI_PACKAGES if ecosystem == "PyPI" else TOP_NPM_PACKAGES
    findings: list[Finding] = []
    
    for pkg in imports:
        best_match = None
        best_similarity = 0.0
        
        for candidate in candidates:
            # Normalize for comparison
            pkg_norm = pkg.lower().replace("-", "").replace("_", "")
            cand_norm = candidate.lower().replace("-", "").replace("_", "")
            
            # Skip if identical (after normalization)
            if pkg_norm == cand_norm:
                continue
            
            # Length difference must be small to be a typo
            if abs(len(pkg_norm) - len(cand_norm)) > 3:
                continue
            
            similarity = _similarity_ratio(pkg_norm, cand_norm)
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = candidate
        
        if best_similarity >= threshold and best_match:
            severity = "CRITICAL" if best_similarity > 0.9 else "HIGH" if best_similarity > 0.85 else "MEDIUM"
            
            findings.append(Finding(
                id=f"VSH-TYPOSQUATTING-{pkg.upper()[:3]}",
                title=f"Potential typosquatting package detected: '{pkg}' vs '{best_match}'",
                severity=severity,
                cwe="CWE-1104",
                file="<dependency-scan>",
                line=1,
                message=f"Package '{pkg}' is suspiciously similar to well-known package '{best_match}' "
                        f"(similarity: {best_similarity:.2%}). This may be a typosquatting attack.",
                recommendation=f"Verify package name is correct. Did you mean '{best_match}'?",
                meta={
                    "engine": "typosquatting",
                    "package": pkg,
                    "similar_to": best_match,
                    "similarity_score": best_similarity,
                    "ecosystem": ecosystem,
                }
            ))
    
    return findings
