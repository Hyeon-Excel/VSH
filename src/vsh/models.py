"""VSH 공통 데이터 모델"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Ecosystem(str, Enum):
    PYTHON = "PyPI"
    JAVASCRIPT = "npm"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    cwe: str              # e.g. "CWE-89"
    cvss: float
    message: str
    line: int
    col: int = 0
    cve: Optional[str] = None
    code_snippet: str = ""
    fix_suggestion: str = ""
    kisa_reference: str = ""
    reachable: Optional[bool] = None   # None = 미분석, True = 도달 가능, False = 도달 불가
    is_hallucination: bool = False
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    impact: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    annotated_code: str = ""
    language: str = ""
    scanned_lines: int = 0
    error: Optional[str] = None
