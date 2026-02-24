"""L1 Semgrep 스캐너 — 커스텀 룰 기반 정적 분석"""
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..models import Finding, Severity

# CWE → KISA 시큐어코딩 가이드 매핑
KISA_MAP: dict[str, str] = {
    "CWE-89":  "KISA 시큐어코딩 가이드 — 입력데이터 검증 및 표현 1항 (SQL 삽입)",
    "CWE-79":  "KISA 시큐어코딩 가이드 — 입력데이터 검증 및 표현 3항 (크로스사이트 스크립팅)",
    "CWE-78":  "KISA 시큐어코딩 가이드 — 입력데이터 검증 및 표현 6항 (운영체제 명령어 삽입)",
    "CWE-22":  "KISA 시큐어코딩 가이드 — 입력데이터 검증 및 표현 4항 (경로 조작 및 자원 삽입)",
    "CWE-798": "KISA 시큐어코딩 가이드 — 보안기능 5항 (하드코딩된 암호화 키)",
    "CWE-502": "KISA 시큐어코딩 가이드 — 입력데이터 검증 및 표현 13항 (신뢰할 수 없는 역직렬화)",
    "CWE-829": "KISA 시큐어코딩 가이드 — 보안기능 8항 (공급망 보안)",
    "CWE-312": "KISA 시큐어코딩 가이드 — 보안기능 6항 (민감정보 평문 저장)",
    "CWE-330": "KISA 시큐어코딩 가이드 — 보안기능 3항 (적절하지 않은 난수 생성)",
}

RULES_DIR = Path(__file__).parent.parent.parent.parent / "rules" / "semgrep"

_LANG_SUFFIX: dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "go": ".go",
    "rust": ".rs",
}

_SEMGREP_SEV: dict[str, Severity] = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_DEFAULT_CVSS: dict[Severity, float] = {
    Severity.CRITICAL: 9.8,
    Severity.HIGH: 8.2,
    Severity.MEDIUM: 6.5,
    Severity.LOW: 3.1,
    Severity.INFO: 0.0,
}


class SemgrepScanner:
    """Semgrep CLI를 호출하거나, 미설치 시 내장 패턴으로 폴백합니다."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or RULES_DIR

    # ------------------------------------------------------------------ #
    # 공개 API
    # ------------------------------------------------------------------ #

    def scan(self, code: str, language: str, filename: str = "") -> list[Finding]:
        """코드 문자열을 스캔하여 Finding 목록을 반환합니다."""
        if self._semgrep_available():
            return self._scan_with_semgrep(code, language)
        return self._scan_with_fallback(code, language)

    # ------------------------------------------------------------------ #
    # Semgrep 실행
    # ------------------------------------------------------------------ #

    def _semgrep_available(self) -> bool:
        try:
            r = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _scan_with_semgrep(self, code: str, language: str) -> list[Finding]:
        suffix = _LANG_SUFFIX.get(language, ".txt")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, encoding="utf-8", delete=False
        ) as f:
            f.write(code)
            temp_path = Path(f.name)
        try:
            return self._run_semgrep(temp_path, language)
        finally:
            temp_path.unlink(missing_ok=True)

    def _run_semgrep(self, file_path: Path, language: str) -> list[Finding]:
        lang_rules = self.rules_dir / language
        rules_target = str(lang_rules) if lang_rules.exists() else str(self.rules_dir)

        cmd = ["semgrep", "--config", rules_target, "--json", "--quiet", str(file_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return []

        if result.returncode not in (0, 1):
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})

            cwe = meta.get("cwe", "CWE-000")
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else "CWE-000"
            cwe = cwe.split(":")[0].strip()

            sev = _SEMGREP_SEV.get(extra.get("severity", "INFO").upper(), Severity.MEDIUM)

            findings.append(Finding(
                rule_id=r.get("check_id", "vsh.unknown"),
                severity=sev,
                cwe=cwe,
                cvss=float(meta.get("cvss", _DEFAULT_CVSS[sev])),
                message=extra.get("message", "취약점 감지"),
                line=r.get("start", {}).get("line", 0),
                col=r.get("start", {}).get("col", 0),
                cve=meta.get("cve"),
                code_snippet=extra.get("lines", ""),
                fix_suggestion=meta.get("fix", ""),
                kisa_reference=KISA_MAP.get(cwe, ""),
                impact=meta.get("impact", ""),
            ))
        return findings

    # ------------------------------------------------------------------ #
    # 폴백 패턴 매칭 (Semgrep 미설치 환경)
    # ------------------------------------------------------------------ #

    def _scan_with_fallback(self, code: str, language: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = code.splitlines()
        for pattern in self._fallback_patterns(language):
            for line_num, line in enumerate(lines, start=1):
                if pattern["regex"].search(line):
                    cwe = pattern["cwe"]
                    sev = pattern["severity"]
                    findings.append(Finding(
                        rule_id=pattern["rule_id"],
                        severity=sev,
                        cwe=cwe,
                        cvss=_DEFAULT_CVSS[sev],
                        message=pattern["message"],
                        line=line_num,
                        code_snippet=line.strip(),
                        fix_suggestion=pattern.get("fix", ""),
                        kisa_reference=KISA_MAP.get(cwe, ""),
                        impact=pattern.get("impact", ""),
                    ))
        return findings

    @staticmethod
    def _fallback_patterns(language: str) -> list[dict]:
        if language == "python":
            return [
                {
                    "rule_id": "vsh.python.sqli",
                    "regex": re.compile(
                        # execute(f"...{var}...")  또는  execute("..." % var)
                        r'\.execute\s*\(\s*[f"\']|'
                        r'\.execute\s*\(\s*\w+\s*%|'
                        # f-string에 SELECT/INSERT/UPDATE/DELETE 포함
                        r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{.*\}|'
                        # "SELECT..." % var  또는  "SELECT..." + var
                        r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\'].*(?:%|\+)\s*\w'
                    ),
                    "cwe": "CWE-89",
                    "severity": Severity.CRITICAL,
                    "message": "SQL 쿼리에 외부 입력이 직접 삽입될 수 있습니다 (f-string / % 포맷).",
                    "fix": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))',
                    "impact": "DB 전체 조회 / 삭제 / 변조 가능",
                },
                {
                    "rule_id": "vsh.python.cmdi",
                    "regex": re.compile(
                        r'os\.system\s*\(|'
                        r'subprocess\.(run|call|Popen|check_output)\s*\(.*shell\s*=\s*True'
                    ),
                    "cwe": "CWE-78",
                    "severity": Severity.CRITICAL,
                    "message": "shell=True 와 외부 입력을 함께 사용하면 OS 명령어 삽입이 가능합니다.",
                    "fix": "subprocess.run(['cmd', user_arg], shell=False)",
                    "impact": "원격 코드 실행(RCE) 가능",
                },
                {
                    "rule_id": "vsh.python.hardcoded_secret",
                    "regex": re.compile(
                        r'(?i)(password|secret(?:_key)?|api_key|token|passwd)\s*=\s*["\'][^"\']{6,}["\']'
                    ),
                    "cwe": "CWE-798",
                    "severity": Severity.HIGH,
                    "message": "하드코딩된 시크릿 키가 감지되었습니다.",
                    "fix": "import os\nsecret = os.getenv('SECRET_KEY')",
                    "impact": "소스코드 노출 시 서버 전체 인증 우회 / 세션 위조 가능",
                },
                {
                    "rule_id": "vsh.python.path_traversal",
                    "regex": re.compile(r'open\s*\(\s*\w*[Ii]nput|open\s*\(\s*request\.|open\s*\(\s*f["\']'),
                    "cwe": "CWE-22",
                    "severity": Severity.HIGH,
                    "message": "외부 입력을 파일 경로에 직접 사용하면 경로 조작이 가능합니다.",
                    "fix": (
                        "import os\n"
                        "safe_path = os.path.realpath(user_path)\n"
                        "if not safe_path.startswith(ALLOWED_BASE):\n"
                        "    raise ValueError('경로 이탈 시도')"
                    ),
                    "impact": "서버 파일 시스템 임의 접근 가능",
                },
                {
                    "rule_id": "vsh.python.insecure_deserialize",
                    "regex": re.compile(r'pickle\.loads?\s*\(|yaml\.load\s*\([^)]*Loader'),
                    "cwe": "CWE-502",
                    "severity": Severity.HIGH,
                    "message": "신뢰할 수 없는 데이터에 pickle/yaml.load 사용 시 코드 실행이 가능합니다.",
                    "fix": "yaml.safe_load(data)  # pickle 대신 json.loads() 사용 권장",
                    "impact": "원격 코드 실행(RCE) 가능",
                },
            ]

        if language in ("javascript", "typescript"):
            return [
                {
                    "rule_id": "vsh.js.xss_innerhtml",
                    "regex": re.compile(r'\.innerHTML\s*=|\.outerHTML\s*='),
                    "cwe": "CWE-79",
                    "severity": Severity.HIGH,
                    "message": "innerHTML에 사용자 입력을 삽입하면 XSS 취약점이 발생합니다.",
                    "fix": "element.textContent = userInput;",
                    "impact": "악성 스크립트 실행 / 세션 탈취 / 피싱 페이지 삽입 가능",
                },
                {
                    "rule_id": "vsh.js.xss_document_write",
                    "regex": re.compile(r'document\.write\s*\('),
                    "cwe": "CWE-79",
                    "severity": Severity.HIGH,
                    "message": "document.write()는 XSS에 취약합니다.",
                    "fix": "document.getElementById('output').textContent = userInput;",
                    "impact": "악성 스크립트 실행 가능",
                },
                {
                    "rule_id": "vsh.js.sqli_template",
                    "regex": re.compile(r'`\s*SELECT\s.*\$\{|\bquery\s*[+]=?\s*\w+'),
                    "cwe": "CWE-89",
                    "severity": Severity.CRITICAL,
                    "message": "SQL 쿼리에 외부 입력이 직접 삽입될 수 있습니다 (템플릿 리터럴).",
                    "fix": "db.query('SELECT * FROM users WHERE id = ?', [userId]);",
                    "impact": "DB 전체 조회 / 삭제 / 변조 가능",
                },
                {
                    "rule_id": "vsh.js.hardcoded_secret",
                    "regex": re.compile(
                        r'(?i)(password|secret(?:Key)?|api_?key|token)\s*[:=]\s*["\'][^"\']{6,}["\']'
                    ),
                    "cwe": "CWE-798",
                    "severity": Severity.HIGH,
                    "message": "하드코딩된 시크릿 키가 감지되었습니다.",
                    "fix": "const secret = process.env.SECRET_KEY;",
                    "impact": "소스코드 노출 시 인증 우회 가능",
                },
            ]

        return []
