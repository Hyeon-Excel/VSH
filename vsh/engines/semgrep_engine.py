import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from vsh.core.config import VSHConfig
from vsh.core.models import Finding
from vsh.core.utils import iter_source_files, read_text, run_cmd

RULE_DIR = Path(__file__).resolve().parent.parent / "rules" / "semgrep"


@dataclass(frozen=True)
class _Rule:
    id: str
    title: str
    severity: str
    cwe: str
    cvss: float
    message: str
    recommendation: str
    references: list[str]
    pattern: str
    function_risk: str
    safe_alternatives: str


def _rule_file(language: str) -> Path:
    if language == "javascript":
        return RULE_DIR / "javascript.yml"
    return RULE_DIR / "python.yml"


def _append_finding(findings: list[Finding], seen: set[tuple[str, int, str]], file_path: str, line: int, rule: _Rule) -> None:
    key = (file_path, line, rule.id)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        Finding(
            id=rule.id,
            title=rule.title,
            severity=rule.severity,
            cwe=rule.cwe,
            cvss=rule.cvss,
            file=file_path,
            line=line,
            message=rule.message,
            recommendation=rule.recommendation,
            references=rule.references,
            meta={
                "engine": "pattern",
                "function_risk": rule.function_risk,
                "safe_alternatives": rule.safe_alternatives,
            },
        )
    )


@lru_cache(maxsize=64)
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _scan_with_line_rules(project_root: Path, language: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    py_rules = [
        _Rule("VSH-PY-SQLI-001", "SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.", "CRITICAL", "CWE-89", 9.8,
              "SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.",
              'query = "SELECT * FROM users WHERE id = %s"; cursor.execute(query, (user_input,))',
              ["KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현"], r"cursor\.execute\(\s*f[\"'].*\{.*\}",
              "동적 SQL 문자열 결합은 SQL Injection 위험이 큽니다.", "파라미터 바인딩 쿼리 사용"),
        _Rule("VSH-PY-XXE-001", "XXE 취약점: fromstring() 함수가 외부 엔티티를 처리할 수 있습니다.", "CRITICAL", "CWE-611", 8.2,
              "XXE 취약점: fromstring() 함수가 외부 엔티티를 처리할 수 있습니다.",
              "외부 입력을 신뢰하지 말고, parse() 메소드를 사용하거나 defusedxml 라이브러리를 사용하세요.",
              ["OWASP XXE Prevention Cheat Sheet"], r"\bfromstring\s*\(",
              "xml.etree.ElementTree.fromstring() 함수는 XXE 공격에 취약합니다.",
              "xml.etree.ElementTree.parse() 또는 defusedxml 사용을 고려하세요."),
        _Rule("VSH-PY-EVAL-001", "위험한 eval() 사용: 임의 코드 실행으로 이어질 수 있습니다.", "CRITICAL", "CWE-95", 9.3,
              "위험한 eval() 사용: 임의 코드 실행으로 이어질 수 있습니다.",
              "eval() 대신 ast.literal_eval()을 사용하거나, 입력을 엄격하게 검증하세요.",
              ["OWASP Code Injection Prevention"], r"\beval\s*\(",
              "eval()은 임의 코드 실행 공격에 취약합니다.", "ast.literal_eval() 또는 whitelist 기반 파서 사용"),
        _Rule("VSH-PY-SUBPROCESS-001", "subprocess에서 shell=True 사용: 명령어 주입 위험이 있습니다.", "HIGH", "CWE-78", 8.6,
              "subprocess에서 shell=True 사용: 명령어 주입 위험이 있습니다.",
              "subprocess.run([\"cmd\", \"arg\"], shell=False) 형태를 사용하세요.",
              ["OWASP Command Injection Prevention"], r"subprocess\.(run|Popen)\(.*shell\s*=\s*True",
              "shell=True 옵션은 명령어 주입 공격에 취약합니다.",
              "shell=False로 설정하고 리스트 형태로 명령어 전달"),
        _Rule("VSH-PY-DESERIALIZE-001", "안전하지 않은 역직렬화: pickle.loads()는 임의 코드 실행으로 이어질 수 있습니다.", "CRITICAL", "CWE-502", 9.8,
              "안전하지 않은 역직렬화: pickle.loads()는 임의 코드 실행으로 이어질 수 있습니다.",
              "신뢰할 수 있는 데이터만 역직렬화하고, 가능하면 JSON으로 마이그레이션하세요.",
              ["OWASP Deserialization Cheat Sheet"], r"pickle\.loads\s*\(",
              "pickle.loads()는 역직렬화 공격에 취약합니다.", "json.loads() 또는 안전한 직렬화 라이브러리 사용"),
        _Rule("VSH-PY-OS-SYSTEM-001", "os.system() 사용: 명령어 주입 위험이 있습니다.", "HIGH", "CWE-78", 8.8,
              "os.system() 사용: 명령어 주입 위험이 있습니다.",
              "subprocess.run([...], shell=False)로 변경하세요.",
              ["OWASP Command Injection Prevention"], r"os\.system\s*\(",
              "os.system()은 명령어 주입 공격에 취약합니다.", "subprocess.run([...], shell=False) 사용"),
    ]

    js_rules = [
        _Rule("VSH-JS-XSS-001", "XSS 가능성: 사용자 입력이 innerHTML로 직접 삽입됩니다.", "HIGH", "CWE-79", 8.2,
              "XSS 공격에 취약: 사용자 입력이 innerHTML로 직접 삽입됩니다.",
              'document.getElementById("output").textContent = userInput;',
              ["KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현", "OWASP Top 10 - XSS"],
              r"\.innerHTML\s*=", "innerHTML에 사용자 입력을 할당하면 DOM XSS 공격에 취약합니다.",
              "textContent 또는 기타 안전한 DOM 조작 메서드 사용"),
        _Rule("VSH-JS-EVAL-001", "위험한 eval() 사용: 코드 실행으로 이어질 수 있습니다.", "CRITICAL", "CWE-95", 9.3,
              "위험한 eval() 사용: 코드 실행으로 이어질 수 있습니다.",
              "eval() 대신 JSON.parse() 또는 안전한 대안을 사용하세요.", ["OWASP Code Injection Prevention"],
              r"\beval\s*\(", "eval()은 임의 코드 실행 공격에 취약합니다.",
              "JSON.parse(), Function 생성자 대신 안전한 파서 사용"),
        _Rule("VSH-JS-DOCUMENT-WRITE-001", "XSS 위험: document.write()가 사용자 입력을 직접 출력합니다.", "HIGH", "CWE-79", 7.8,
              "XSS 위험: document.write()가 사용자 입력을 직접 출력합니다.",
              "document.write() 대신 DOM API를 사용하세요.", ["OWASP XSS Prevention Cheat Sheet"],
              r"document\.write\s*\(", "document.write()는 XSS 공격에 취약합니다.",
              "textContent 기반 DOM 조작 사용"),
    ]

    rules = py_rules if language == "python" else js_rules
    for f in iter_source_files(project_root, language):
        file_path = str(f.relative_to(project_root))
        for i, line in enumerate(read_text(f).splitlines(), 1):
            for rule in rules:
                if _compiled(rule.pattern).search(line):
                    _append_finding(findings, seen, file_path, i, rule)

    return findings


def run_semgrep(cfg: VSHConfig, language: str) -> list[Finding]:
    rule = _rule_file(language)
    cmd = [cfg.semgrep_bin, "--quiet", "--json", "--config", str(rule), str(cfg.project_root)]
    rc, out, _ = run_cmd(cmd, cwd=cfg.project_root, timeout=cfg.timeout_sec)

    if rc in (0, 1) and out.strip():
        try:
            data = json.loads(out)
            findings: list[Finding] = []
            for r in data.get("results", []):
                path = r.get("path", "")
                start = r.get("start", {}) or {}
                extra = r.get("extra", {}) or {}
                meta = extra.get("metadata", {}) or {}
                findings.append(
                    Finding(
                        id=str(r.get("check_id", "VSH-SEM")),
                        title=extra.get("message", "Semgrep finding"),
                        severity=str(meta.get("severity", "MEDIUM")).upper(),
                        cwe=meta.get("cwe"),
                        cvss=meta.get("cvss"),
                        cve=meta.get("cve"),
                        file=path,
                        line=int(start.get("line", 1)),
                        column=int(start.get("col", 1)),
                        message=extra.get("message", ""),
                        recommendation=meta.get("fix"),
                        references=list(meta.get("references", [])),
                        meta={"engine": "semgrep"},
                    )
                )
            return findings
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    return _scan_with_line_rules(cfg.project_root, language)
