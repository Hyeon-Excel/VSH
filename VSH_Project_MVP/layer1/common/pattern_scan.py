import re
from dataclasses import dataclass
from pathlib import Path

from models.vulnerability import Vulnerability
from .import_risk import guess_language


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    title: str
    severity: str
    cwe_id: str
    pattern: str
    references: list[str]


PYTHON_RULES = [
    PatternRule("VSH-PY-SQLI-001", "SQL Injection 가능성", "CRITICAL", "CWE-89", r"cursor\.execute\(\s*f[\"'].*\{.*\}", ["KISA 입력데이터 검증 및 표현 1항"]),
    PatternRule("VSH-PY-XXE-001", "XXE 가능성", "CRITICAL", "CWE-611", r"\bfromstring\s*\(", ["OWASP XXE Prevention Cheat Sheet"]),
    PatternRule("VSH-PY-EVAL-001", "eval() 사용", "CRITICAL", "CWE-95", r"\beval\s*\(", ["OWASP Code Injection Prevention"]),
    PatternRule("VSH-PY-SUBPROCESS-001", "subprocess shell=True 사용", "HIGH", "CWE-78", r"subprocess\.(run|Popen)\(.*shell\s*=\s*True", ["OWASP Command Injection Prevention"]),
    PatternRule("VSH-PY-DESERIALIZE-001", "pickle.loads 사용", "CRITICAL", "CWE-502", r"pickle\.loads\s*\(", ["OWASP Deserialization Cheat Sheet"]),
    PatternRule("VSH-PY-OS-SYSTEM-001", "os.system() 사용", "HIGH", "CWE-78", r"os\.system\s*\(", ["OWASP Command Injection Prevention"]),
]

JAVASCRIPT_RULES = [
    PatternRule("VSH-JS-XSS-001", "innerHTML 기반 XSS 가능성", "HIGH", "CWE-79", r"\.innerHTML\s*=", ["KISA 입력데이터 검증 및 표현 3항"]),
    PatternRule("VSH-JS-EVAL-001", "eval() 사용", "CRITICAL", "CWE-95", r"\beval\s*\(", ["OWASP Code Injection Prevention"]),
    PatternRule("VSH-JS-DOCUMENT-WRITE-001", "document.write() 사용", "HIGH", "CWE-79", r"document\.write\s*\(", ["OWASP XSS Prevention Cheat Sheet"]),
]


def scan_file_with_patterns(file_path: str) -> list[Vulnerability]:
    language = guess_language(file_path)
    rules = JAVASCRIPT_RULES if language in {"javascript", "typescript"} else PYTHON_RULES
    content = Path(file_path).read_text(encoding="utf-8")
    findings: list[Vulnerability] = []
    seen: set[tuple[str, int, str]] = set()

    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule in rules:
            if not re.search(rule.pattern, line):
                continue
            key = (rule.rule_id, line_number, line.strip())
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Vulnerability(
                    file_path=file_path,
                    rule_id=rule.rule_id,
                    cwe_id=rule.cwe_id,
                    severity=rule.severity,
                    line_number=line_number,
                    code_snippet=line.strip(),
                    references=list(rule.references),
                    metadata={
                        "engine": "vsh_pattern",
                        "title": rule.title,
                    },
                )
            )

    return findings
