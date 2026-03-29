import re


_REQUIREMENT_PATTERN = re.compile(r"^([a-zA-Z0-9_\-]+)(?:[=!<>~]+([0-9\.]+))?")


# hyeonexcel 수정: dependency requirement 파싱 규칙이 retriever/verifier/analyzer에
# 중복되어 있어, 공급망 취약점 처리 기준을 한 곳에서 유지하도록 공통 유틸로 분리한다.
def parse_requirement_line(requirement_line: str) -> tuple[str | None, str | None]:
    normalized = requirement_line.strip()
    if not normalized or normalized.startswith(("-e", "git+", "http://", "https://", "./", "../", "/", "@")):
        return None, None

    match = _REQUIREMENT_PATTERN.match(normalized)
    if not match:
        return None, None
    return match.group(1).lower(), match.group(2)
