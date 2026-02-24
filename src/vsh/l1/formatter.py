"""L1 취약점 주석 포맷터 — 기획서 스타일의 한국어 인라인 주석 생성"""
from ..models import Finding, Severity

_STARS: dict[Severity, str] = {
    Severity.CRITICAL: "★★★★★",
    Severity.HIGH:     "★★★★☆",
    Severity.MEDIUM:   "★★★☆☆",
    Severity.LOW:      "★★☆☆☆",
    Severity.INFO:     "★☆☆☆☆",
}

_PREFIX: dict[str, str] = {
    "python":     "#",
    "javascript": "//",
    "typescript": "//",
    "java":       "//",
    "go":         "//",
    "rust":       "//",
    "c":          "//",
    "cpp":        "//",
}

_CWE_NAMES: dict[str, str] = {
    "CWE-89":   "SQL Injection",
    "CWE-79":   "Cross-Site Scripting",
    "CWE-78":   "OS Command Injection",
    "CWE-22":   "Path Traversal",
    "CWE-798":  "Hardcoded Credentials",
    "CWE-502":  "Insecure Deserialization",
    "CWE-829":  "Supply Chain / Untrusted Module",
    "CWE-312":  "Cleartext Storage of Sensitive Info",
    "CWE-330":  "Insufficient Randomness",
    "CWE-1035": "Known Vulnerable Library",
}


class Formatter:
    # ------------------------------------------------------------------ #
    # 코드 주석 삽입
    # ------------------------------------------------------------------ #

    def annotate_code(self, code: str, findings: list[Finding], language: str) -> str:
        """코드 각 취약 라인 바로 아래에 VSH 주석 블록을 삽입합니다."""
        prefix = _PREFIX.get(language, "#")
        lines = code.splitlines(keepends=True)

        # line_num → findings 매핑 (inline), 0번 라인은 파일 끝
        inline: dict[int, list[Finding]] = {}
        tail: list[Finding] = []
        for f in findings:
            if 1 <= f.line <= len(lines):
                inline.setdefault(f.line, []).append(f)
            else:
                tail.append(f)

        result: list[str] = []
        for i, line in enumerate(lines, start=1):
            result.append(line)
            for f in inline.get(i, []):
                result.append(self._comment_block(f, prefix) + "\n")

        if tail:
            result.append("\n")
            for f in tail:
                result.append(self._comment_block(f, prefix) + "\n")

        return "".join(result)

    # ------------------------------------------------------------------ #
    # SBOM 리포트 (Markdown)
    # ------------------------------------------------------------------ #

    def format_sbom_report(self, findings: list[Finding], source_path: str) -> str:
        tag_map = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH:     "🟠",
            Severity.MEDIUM:   "🟡",
            Severity.LOW:      "🟢",
            Severity.INFO:     "⚪",
        }
        rows = [
            "# 📦 VSH SBOM 보안 진단 결과",
            "",
            f"**분석 파일** : `{source_path}`",
            f"**발견된 문제** : {len(findings)}건",
            "",
            "---",
            "",
        ]
        for f in findings:
            tag = tag_map.get(f.severity, "⚪")
            title = (
                f"패키지 환각 (Hallucination): `{f.package_name}`"
                if f.is_hallucination
                else f"취약 패키지: `{f.package_name}` {f.package_version or ''}"
            )
            rows += [
                f"## {tag} [{f.severity.value}] {title}",
                "",
                f"- **위험도** : {_STARS[f.severity]} CVSS {f.cvss:.1f}",
                f"- **{f.cwe}** : {_CWE_NAMES.get(f.cwe, '알 수 없음')}",
            ]
            if f.cve:
                rows.append(f"- **CVE** : `{f.cve}`")
            rows += [
                f"- **영향** : {f.impact}",
                f"- **KISA** : {f.kisa_reference}",
                "",
                "**권장 조치:**",
                "```",
                f.fix_suggestion,
                "```",
                "",
                "---",
                "",
            ]
        return "\n".join(rows)

    # ------------------------------------------------------------------ #
    # 내부: 주석 블록 생성
    # ------------------------------------------------------------------ #

    def _comment_block(self, f: Finding, p: str) -> str:
        sep = f"{p} {'─' * 49}"
        reach = {
            True:  "✅ 실제 도달 가능 (외부 입력 → 위험 코드 직접 연결 확인됨)",
            False: "⚠️  도달 불가 (코드 흐름상 외부 입력과 분리됨)",
            None:  "🔍 미분석 (L2 Warm Path 에서 정밀 분석 예정)",
        }[f.reachable]

        block = [
            f"{p} ⚠️  [VSH 알림] {_short_rule(f.rule_id)} 취약점 감지",
            sep,
            f"{p} 위험도      : {_STARS[f.severity]} {f.severity.value} | CVSS {f.cvss:.1f}",
            f"{p} 취약점      : {f.cwe} ({_CWE_NAMES.get(f.cwe, '알 수 없음')})",
        ]
        if f.kisa_reference:
            block.append(f"{p} 근거        : {f.kisa_reference}")
        if f.cve:
            block.append(f"{p} CVE         : {f.cve}")
        block.append(f"{p} Reachability: {reach}")

        if f.impact:
            block += [f"{p}", f"{p} 💥 영향 범위: {f.impact}"]

        if f.fix_suggestion:
            block += [f"{p}", f"{p} 🔧 권장 수정 코드:"]
            for line in f.fix_suggestion.splitlines():
                block.append(f"{p} {line}")

        block.append(sep)
        return "\n".join(block)


def _short_rule(rule_id: str) -> str:
    """vsh.python.sqli → SQLi 처럼 짧은 레이블로 변환"""
    part = rule_id.split(".")[-1].replace("_", " ").upper()
    aliases = {
        "SQLI": "SQL Injection",
        "XSS INNERHTML": "XSS",
        "XSS DOCUMENT WRITE": "XSS",
        "CMDI": "Command Injection",
        "HARDCODED SECRET": "Hardcoded Secret",
        "PATH TRAVERSAL": "Path Traversal",
        "INSECURE DESERIALIZE": "Insecure Deserialization",
        "HALLUCINATION": "패키지 환각 (Hallucination)",
    }
    return aliases.get(part, part)
