"""L1 SBOM 스캐너 — 패키지 CVE 검사 및 환각(Hallucination) 탐지"""
import json
import re
from pathlib import Path
from typing import Optional

import requests as http

from ..models import Finding, Severity

OSV_API = "https://api.osv.dev/v1/query"

# ------------------------------------------------------------------ #
# 알려진 패키지 화이트리스트 (환각 탐지용)
# ------------------------------------------------------------------ #
_KNOWN_PYTHON: set[str] = {
    "requests", "flask", "django", "fastapi", "numpy", "pandas", "scipy",
    "matplotlib", "sqlalchemy", "pydantic", "uvicorn", "gunicorn", "starlette",
    "pytest", "black", "mypy", "ruff", "anthropic", "openai", "langchain",
    "chromadb", "semgrep", "click", "rich", "httpx", "aiohttp", "celery",
    "redis", "pymongo", "psycopg2", "alembic", "pillow", "cryptography",
    "paramiko", "boto3", "mcp", "fastmcp", "packaging", "pyyaml", "toml",
    "python-dotenv", "dotenv", "jinja2", "werkzeug", "itsdangerous",
    "six", "attrs", "typing-extensions", "setuptools", "wheel", "pip",
    "langchain-anthropic", "langchain-core", "langchain-community",
    "tree-sitter", "charset-normalizer", "certifi", "urllib3", "idna",
}

_KNOWN_NPM: set[str] = {
    "react", "vue", "angular", "express", "next", "nuxt", "svelte",
    "lodash", "axios", "moment", "dayjs", "webpack", "vite", "esbuild",
    "typescript", "eslint", "prettier", "jest", "vitest", "tailwindcss",
    "react-dom", "react-router", "redux", "zustand", "mobx",
    "socket.io", "socket.io-client", "mongoose", "sequelize", "prisma",
    "jsonwebtoken", "bcrypt", "passport", "dotenv", "cors", "helmet",
    "zod", "joi", "yup", "formik", "react-query", "swr",
}

_KISA_SUPPLY_CHAIN = "KISA 시큐어코딩 가이드 — 보안기능 8항 (공급망 보안)"


class SBOMScanner:
    """requirements.txt / package.json 기반 패키지 보안 검사"""

    def __init__(self):
        self._session = http.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    # ------------------------------------------------------------------ #
    # 공개 API
    # ------------------------------------------------------------------ #

    def scan_file(self, file_path: str) -> list[Finding]:
        path = Path(file_path)
        if not path.exists():
            return []

        name = path.name.lower()
        if name == "requirements.txt":
            packages = _parse_requirements(path)
            ecosystem = "PyPI"
        elif name == "package.json":
            packages = _parse_package_json(path)
            ecosystem = "npm"
        else:
            return []

        findings: list[Finding] = []
        for pkg_name, pkg_version in packages:
            hallucination_hint = self._check_hallucination(pkg_name, ecosystem)
            if hallucination_hint is not None:
                findings.append(self._hallucination_finding(pkg_name, pkg_version, hallucination_hint))
                continue

            if pkg_version:
                findings.extend(self._check_osv(pkg_name, pkg_version, ecosystem))

        return findings

    # ------------------------------------------------------------------ #
    # 환각 탐지
    # ------------------------------------------------------------------ #

    def _check_hallucination(self, name: str, ecosystem: str) -> Optional[str]:
        """알 수 없는 패키지를 환각으로 의심하면 유사 패키지명을 반환, 아니면 None."""
        known = _KNOWN_PYTHON if ecosystem == "PyPI" else _KNOWN_NPM
        normalized = name.lower().replace("_", "-")

        if normalized in known:
            return None

        similar = _find_similar(normalized, known)
        if similar:
            return similar

        if not self._exists_in_registry(name, ecosystem):
            return f"(레지스트리 미확인 패키지 — 오타 또는 AI 환각 의심)"

        return None

    def _exists_in_registry(self, name: str, ecosystem: str) -> bool:
        try:
            url = (
                f"https://pypi.org/pypi/{name}/json"
                if ecosystem == "PyPI"
                else f"https://registry.npmjs.org/{name}"
            )
            resp = self._session.get(url, timeout=5)
            return resp.status_code == 200
        except Exception:
            return True  # 네트워크 오류 시 오탐 방지

    # ------------------------------------------------------------------ #
    # OSV CVE 조회
    # ------------------------------------------------------------------ #

    def _check_osv(self, name: str, version: str, ecosystem: str) -> list[Finding]:
        try:
            resp = self._session.post(
                OSV_API,
                json={"version": version, "package": {"name": name, "ecosystem": ecosystem}},
                timeout=10,
            )
            if resp.status_code != 200:
                return []
            vulns = resp.json().get("vulns", [])
        except Exception:
            return []

        findings: list[Finding] = []
        for vuln in vulns[:3]:
            vuln_id: str = vuln.get("id", "UNKNOWN")
            summary: str = vuln.get("summary", "알 수 없는 취약점")

            cve: Optional[str] = next(
                (a for a in vuln.get("aliases", []) if a.startswith("CVE-")), None
            )
            cvss = _extract_cvss(vuln)
            sev = _cvss_to_severity(cvss)

            findings.append(Finding(
                rule_id=f"vsh.sbom.{vuln_id.lower()}",
                severity=sev,
                cwe="CWE-1035",
                cvss=cvss,
                message=f"{name} {version}: {summary}",
                line=0,
                cve=cve,
                kisa_reference=_KISA_SUPPLY_CHAIN,
                package_name=name,
                package_version=version,
                fix_suggestion=f"pip install --upgrade {name}  # 최신 패치 버전으로 업그레이드",
                impact=f"{name} 라이브러리 취약점을 통한 보안 위협",
            ))
        return findings

    # ------------------------------------------------------------------ #
    # Finding 생성 헬퍼
    # ------------------------------------------------------------------ #

    @staticmethod
    def _hallucination_finding(name: str, version: Optional[str], hint: str) -> Finding:
        fix = f"# 올바른 패키지명으로 교체하세요\nimport {hint.split()[0]}"
        if version:
            fix += f"\n# pip install {hint.split()[0]}=={version}"
        else:
            fix += f"\n# pip install {hint.split()[0]}"

        return Finding(
            rule_id="vsh.sbom.hallucination",
            severity=Severity.HIGH,
            cwe="CWE-829",
            cvss=8.6,
            message=(
                f"패키지 환각(Hallucination) 감지: '{name}' — "
                f"존재하지 않거나 오타일 가능성 있음. 유사 패키지: '{hint}'"
            ),
            line=0,
            kisa_reference=_KISA_SUPPLY_CHAIN,
            package_name=name,
            package_version=version,
            fix_suggestion=fix,
            impact="악성 패키지 설치 시 원격 코드 실행(RCE) 가능",
            reachable=True,
            is_hallucination=True,
        )


# ------------------------------------------------------------------ #
# 파일 파싱 유틸
# ------------------------------------------------------------------ #

def _parse_requirements(path: Path) -> list[tuple[str, Optional[str]]]:
    result: list[tuple[str, Optional[str]]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+")):
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([><=!~]{1,2}\s*[\d\.]+)?', line)
        if m:
            pkg = m.group(1).lower().replace("_", "-")
            ver_raw = m.group(2)
            ver = re.search(r'[\d\.]+', ver_raw).group() if ver_raw else None
            result.append((pkg, ver))
    return result


def _parse_package_json(path: Path) -> list[tuple[str, Optional[str]]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    result: list[tuple[str, Optional[str]]] = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in data.get(section, {}).items():
            ver = re.sub(r'^[\^~>=<]', '', str(spec)).split()[0]
            result.append((name.lower(), ver or None))
    return result


# ------------------------------------------------------------------ #
# 편집거리 & 유사 패키지 검색
# ------------------------------------------------------------------ #

def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 3:
        return 999
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            dp[j] = prev[j - 1] if a[i - 1] == b[j - 1] else 1 + min(prev[j], dp[j - 1], prev[j - 1])
    return dp[n]


def _find_similar(name: str, known: set[str], threshold: int = 2) -> Optional[str]:
    candidates = [(dist, k) for k in known if 0 < (dist := _edit_distance(name, k)) <= threshold]
    return min(candidates)[1] if candidates else None


# ------------------------------------------------------------------ #
# CVSS 헬퍼
# ------------------------------------------------------------------ #

def _extract_cvss(vuln: dict) -> float:
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS v3 벡터: "CVSS:3.1/AV:N/AC:L/..." — 점수가 없는 경우 기본값
        m = re.search(r'/(\d+\.\d+)$', score_str)
        if m:
            return float(m.group(1))
    return 7.0


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW
