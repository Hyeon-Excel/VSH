"""VSH FastMCP 서버 — MCP 도구 정의"""
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .l1.aggregator import L1Aggregator
from .l1.sbom import SBOMScanner
from .l1.formatter import Formatter

mcp = FastMCP(
    name="VSH",
    instructions=(
        "VSH(Vibe Security Helper)는 AI 코딩 환경에서 실시간으로 보안 취약점을 탐지합니다.\n"
        "KISA 시큐어코딩 가이드 및 OWASP Top 10 기준으로 취약점을 분류하고, "
        "한국어 인라인 주석으로 결과를 제공합니다.\n"
        "지원 기능: 코드 스캔, 파일 스캔, 패키지 SBOM 검사."
    ),
)

_aggregator = L1Aggregator()
_sbom = SBOMScanner()
_formatter = Formatter()

_LANG_MAP: dict[str, str] = {
    "py":  "python",
    "js":  "javascript",
    "ts":  "typescript",
    "jsx": "javascript",
    "tsx": "typescript",
    "java": "java",
    "go":   "go",
    "rs":   "rust",
    "c":    "c",
    "cpp":  "cpp",
}


# ------------------------------------------------------------------ #
# Tool 1: 코드 스니펫 스캔
# ------------------------------------------------------------------ #

@mcp.tool()
async def scan_code(code: str, language: str, filename: str = "") -> str:
    """
    코드 스니펫에서 보안 취약점을 실시간(L1 Hot Path)으로 스캔합니다.

    Args:
        code:     분석할 소스 코드 문자열
        language: 프로그래밍 언어 (python, javascript, typescript, java, go, rust 등)
        filename: 원본 파일명 (선택적, 컨텍스트 제공용)

    Returns:
        취약점 인라인 주석이 삽입된 코드.
        취약점이 없으면 "✅ 취약점 없음" 메시지 반환.
    """
    result = await _aggregator.scan(code=code, language=language, filename=filename)

    if result.error:
        return f"❌ 스캔 오류: {result.error}"

    if not result.findings:
        return f"✅ 취약점 없음 — {len(code.splitlines())}줄 분석 완료\n\n{code}"

    summary = _build_summary(result.findings)
    return f"{summary}\n\n{result.annotated_code}"


# ------------------------------------------------------------------ #
# Tool 2: 파일 스캔
# ------------------------------------------------------------------ #

@mcp.tool()
async def scan_file(file_path: str) -> str:
    """
    파일에서 보안 취약점을 L1 실시간 스캔합니다.

    Args:
        file_path: 분석할 파일의 절대 또는 상대 경로

    Returns:
        취약점 인라인 주석이 삽입된 코드.
        취약점이 없으면 "✅ 취약점 없음" 메시지 반환.
    """
    path = Path(file_path)
    if not path.exists():
        return f"❌ 파일을 찾을 수 없습니다: {file_path}"

    try:
        code = path.read_text(encoding="utf-8")
    except Exception as e:
        return f"❌ 파일 읽기 실패: {e}"

    language = _LANG_MAP.get(path.suffix.lstrip("."), path.suffix.lstrip("."))
    result = await _aggregator.scan(code=code, language=language, filename=path.name)

    if result.error:
        return f"❌ 스캔 오류: {result.error}"

    if not result.findings:
        return f"✅ {path.name} — 취약점 없음 ({result.scanned_lines}줄 분석 완료)"

    summary = _build_summary(result.findings)
    return f"📄 **{path.name}** 스캔 결과\n\n{summary}\n\n{result.annotated_code}"


# ------------------------------------------------------------------ #
# Tool 3: SBOM / 패키지 스캔
# ------------------------------------------------------------------ #

@mcp.tool()
async def check_packages(requirements_path: str) -> str:
    """
    requirements.txt 또는 package.json 에서 취약 패키지 및 패키지 환각을 검사합니다.

    Args:
        requirements_path: requirements.txt 또는 package.json 경로

    Returns:
        SBOM 보안 진단 결과 (Markdown 형식).
        문제가 없으면 "✅ 취약한 패키지 없음" 메시지 반환.
    """
    findings = _sbom.scan_file(requirements_path)

    if not findings:
        return f"✅ 취약한 패키지 없음 — `{requirements_path}` 검사 완료"

    return _formatter.format_sbom_report(findings, requirements_path)


# ------------------------------------------------------------------ #
# 내부 유틸
# ------------------------------------------------------------------ #

def _build_summary(findings) -> str:
    from collections import Counter
    counts = Counter(f.severity.value for f in findings)
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if counts[sev]:
            parts.append(f"{sev}: {counts[sev]}건")
    total = len(findings)
    reachable = sum(1 for f in findings if f.reachable is True)
    return (
        f"🚨 **VSH 스캔 결과** — 총 {total}건 탐지 "
        f"({', '.join(parts)}) | Reachability 확인: {reachable}건"
    )


def run():
    mcp.run()
