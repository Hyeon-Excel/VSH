"""L1 결과 집계기 — Scanner + Reachability + Formatter 조합"""
from ..models import Finding, ScanResult, Severity
from .scanner import SemgrepScanner
from .reachability import ReachabilityAnalyzer
from .formatter import Formatter

_SEV_ORDER: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}


class L1Aggregator:
    """L1 Hot Path 전체 파이프라인을 실행합니다."""

    def __init__(self):
        self._scanner = SemgrepScanner()
        self._reachability = ReachabilityAnalyzer()
        self._formatter = Formatter()

    async def scan(self, code: str, language: str, filename: str = "") -> ScanResult:
        try:
            # 1. Semgrep (또는 폴백 패턴)으로 취약점 탐지
            findings = self._scanner.scan(code=code, language=language, filename=filename)

            # 2. Reachability 분석 — 외부 입력 → 싱크 도달 여부
            findings = self._reachability.analyze(code=code, language=language, findings=findings)

            # 3. 정렬 & 중복 제거
            findings = _dedup(_sort(findings))

            # 4. 코드에 주석 블록 삽입
            annotated = self._formatter.annotate_code(
                code=code, findings=findings, language=language
            )

            return ScanResult(
                findings=findings,
                annotated_code=annotated,
                language=language,
                scanned_lines=len(code.splitlines()),
            )
        except Exception as exc:
            return ScanResult(error=str(exc))


# ------------------------------------------------------------------ #
# 유틸
# ------------------------------------------------------------------ #

def _sort(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.line, _SEV_ORDER.get(f.severity.value, 5)))


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    result: list[Finding] = []
    for f in findings:
        key = (f.line, f.cwe, f.rule_id)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
