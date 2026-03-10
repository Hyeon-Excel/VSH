import re
from pathlib import Path

from vsh.core.models import Finding
from vsh.core.utils import clamp, read_text

# Lightweight reachability heuristic (NOT full call graph/taint analysis)
PY_SOURCE_PATTERNS = [r"\binput\(", r"flask\.request", r"request\.(args|form|json)", r"sys\.argv", r"os\.environ"]
PY_SINK_PATTERNS = [r"cursor\.execute\(", r"\.execute\(", r"\beval\(", r"subprocess\.", r"os\.system\("]

JS_SOURCE_PATTERNS = [r"req\.(body|query|params)", r"document\.URL", r"window\.location", r"location\."]
JS_SINK_PATTERNS = [r"innerHTML", r"\beval\(", r"Function\(", r"dangerouslySetInnerHTML", r"document\.write\("]


def _matching_lines(lines: list[str], patterns: list[str]) -> list[int]:
    compiled = [re.compile(p) for p in patterns]
    hits: list[int] = []
    for idx, line in enumerate(lines, 1):
        if any(c.search(line) for c in compiled):
            hits.append(idx)
    return hits


def _min_distance(line: int, candidates: list[int]) -> int | None:
    if not candidates:
        return None
    return min(abs(line - c) for c in candidates)


def annotate_reachability(project_root: Path, language: str, findings: list[Finding]) -> list[Finding]:
    source_patterns = JS_SOURCE_PATTERNS if language == "javascript" else PY_SOURCE_PATTERNS
    sink_patterns = JS_SINK_PATTERNS if language == "javascript" else PY_SINK_PATTERNS

    for finding in findings:
        path = project_root / finding.file
        if not path.exists():
            continue

        lines = read_text(path).splitlines()
        if not lines:
            finding.reachability = "NO"
            continue

        source_hits = _matching_lines(lines, source_patterns)
        sink_hits = _matching_lines(lines, sink_patterns)

        if not source_hits or not sink_hits:
            finding.reachability = "NO"
            finding.meta["reachability_mode"] = "lightweight_heuristic"
            finding.meta["source_hits"] = len(source_hits)
            finding.meta["sink_hits"] = len(sink_hits)
            continue

        idx = clamp(finding.line, 1, len(lines))
        d_source = _min_distance(idx, source_hits)
        d_sink = _min_distance(idx, sink_hits)
        source_sink_distance = min(abs(s - k) for s in source_hits for k in sink_hits)

        if d_source is not None and d_sink is not None and d_source <= 12 and d_sink <= 12 and source_sink_distance <= 20:
            finding.reachability = "YES"
        elif source_sink_distance <= 80:
            finding.reachability = "UNKNOWN"
        else:
            finding.reachability = "NO"

        finding.meta["reachability_mode"] = "lightweight_heuristic"
        finding.meta["source_hits"] = len(source_hits)
        finding.meta["sink_hits"] = len(sink_hits)
        finding.meta["source_sink_distance"] = source_sink_distance

    return findings
