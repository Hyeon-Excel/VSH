import re
from pathlib import Path

from models.vulnerability import Vulnerability
from .import_risk import guess_language

PY_SOURCE_PATTERNS = [r"\binput\(", r"flask\.request", r"request\.(args|form|json)", r"sys\.argv", r"os\.environ"]
PY_SINK_PATTERNS = [r"cursor\.execute\(", r"\.execute\(", r"\beval\(", r"subprocess\.", r"os\.system\("]

JS_SOURCE_PATTERNS = [r"req\.(body|query|params)", r"document\.URL", r"window\.location", r"location\."]
JS_SINK_PATTERNS = [r"innerHTML", r"\beval\(", r"Function\(", r"dangerouslySetInnerHTML", r"document\.write\("]


def _matching_lines(lines: list[str], patterns: list[str]) -> list[int]:
    compiled = [re.compile(pattern) for pattern in patterns]
    hits: list[int] = []
    for idx, line in enumerate(lines, start=1):
        if any(pattern.search(line) for pattern in compiled):
            hits.append(idx)
    return hits


def _min_distance(line_number: int, candidates: list[int]) -> int | None:
    if not candidates:
        return None
    return min(abs(line_number - candidate) for candidate in candidates)


def annotate_reachability(file_path: str, findings: list[Vulnerability]) -> list[Vulnerability]:
    language = guess_language(file_path)
    source_patterns = JS_SOURCE_PATTERNS if language in {"javascript", "typescript"} else PY_SOURCE_PATTERNS
    sink_patterns = JS_SINK_PATTERNS if language in {"javascript", "typescript"} else PY_SINK_PATTERNS

    path = Path(file_path)
    if not path.exists():
        return findings

    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return findings

    source_hits = _matching_lines(lines, source_patterns)
    sink_hits = _matching_lines(lines, sink_patterns)

    for finding in findings:
        if finding.cwe_id == "CWE-829":
            continue
        if not source_hits or not sink_hits:
            finding.reachability_status = "NO"
            continue

        line_number = max(1, min(finding.line_number, len(lines)))
        source_distance = _min_distance(line_number, source_hits)
        sink_distance = _min_distance(line_number, sink_hits)
        source_sink_distance = min(abs(source - sink) for source in source_hits for sink in sink_hits)

        if (
            source_distance is not None
            and sink_distance is not None
            and source_distance <= 12
            and sink_distance <= 12
            and source_sink_distance <= 20
        ):
            finding.reachability_status = "YES"
        elif source_sink_distance <= 80:
            finding.reachability_status = "UNKNOWN"
        else:
            finding.reachability_status = "NO"

        finding.metadata.setdefault("reachability_mode", "lightweight_heuristic")
        finding.metadata["source_hits"] = len(source_hits)
        finding.metadata["sink_hits"] = len(sink_hits)

    return findings
