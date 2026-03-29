from __future__ import annotations

import re
from pathlib import Path

from models.vulnerability import Vulnerability
from .import_risk import guess_language

PY_SOURCE_PATTERNS = [r"\binput\(", r"flask\.request", r"request\.(args|form|json)", r"sys\.argv", r"os\.environ"]
PY_SINK_PATTERNS = [r"cursor\.execute\(", r"\.execute\(", r"\beval\(", r"subprocess\.", r"os\.system\("]
JS_SOURCE_PATTERNS = [r"req\.(body|query|params)", r"document\.URL", r"window\.location", r"location\."]
JS_SINK_PATTERNS = [r"innerHTML", r"\beval\(", r"Function\(", r"dangerouslySetInnerHTML", r"document\.write\("]

FUNC_DEF_RE = re.compile(r"^\s*def\s+(\w+)\s*\(")
FUNC_CALL_RE = re.compile(r"\b(\w+)\s*\(")


def _matching_lines(lines: list[str], patterns: list[str]) -> list[int]:
    compiled = [re.compile(pattern) for pattern in patterns]
    return [idx for idx, line in enumerate(lines, start=1) if any(pattern.search(line) for pattern in compiled)]


def _build_function_boundaries(lines: list[str]) -> dict[str, tuple[int, int]]:
    boundaries: dict[str, tuple[int, int]] = {}
    current_fn = None
    start_line = 1
    for idx, line in enumerate(lines, start=1):
        m = FUNC_DEF_RE.match(line)
        if m:
            if current_fn is not None:
                boundaries[current_fn] = (start_line, idx - 1)
            current_fn = m.group(1)
            start_line = idx
    if current_fn is not None:
        boundaries[current_fn] = (start_line, len(lines))
    return boundaries


def _find_function_for_line(line_number: int, boundaries: dict[str, tuple[int, int]]) -> str | None:
    for fn, (start, end) in boundaries.items():
        if start <= line_number <= end:
            return fn
    return None


def _build_call_graph(lines: list[str], boundaries: dict[str, tuple[int, int]]) -> dict[str, set[str]]:
    calls: dict[str, set[str]] = {fn: set() for fn in boundaries}
    global_calls: set[str] = set()
    for fn, (start, end) in boundaries.items():
        for line in lines[start - 1:end]:
            for call in FUNC_CALL_RE.findall(line):
                if call != fn and call in boundaries:
                    calls[fn].add(call)
    for idx, line in enumerate(lines, start=1):
        if not any(start <= idx <= end for start, end in boundaries.values()):
            for call in FUNC_CALL_RE.findall(line):
                if call in boundaries:
                    global_calls.add(call)
    if global_calls:
        calls["<global>"] = global_calls
    return calls


def _compute_reachable_functions(start_points: set[str], call_graph: dict[str, set[str]]) -> set[str]:
    reached = set()

    def dfs(fn: str):
        if fn in reached:
            return
        reached.add(fn)
        for callee in call_graph.get(fn, set()):
            if callee not in reached:
                dfs(callee)

    for sp in start_points:
        dfs(sp)
    return reached


def annotate_reachability(file_path: str, findings: list[Vulnerability]) -> list[Vulnerability]:
    language = guess_language(file_path)
    source_patterns = JS_SOURCE_PATTERNS if language in {"javascript", "typescript"} else PY_SOURCE_PATTERNS
    sink_patterns = JS_SINK_PATTERNS if language in {"javascript", "typescript"} else PY_SINK_PATTERNS
    path = Path(file_path)
    if not path.exists():
        return findings
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not lines:
        return findings

    source_hits = _matching_lines(lines, source_patterns)
    sink_hits = _matching_lines(lines, sink_patterns)
    boundaries = _build_function_boundaries(lines)
    call_graph = _build_call_graph(lines, boundaries)

    source_functions = set(filter(None, (_find_function_for_line(i, boundaries) for i in source_hits)))
    sink_functions = set(filter(None, (_find_function_for_line(i, boundaries) for i in sink_hits)))

    reachable_from_source = _compute_reachable_functions(source_functions, call_graph) if source_functions else set()

    for finding in findings:
        if finding.cwe_id == "CWE-829":
            continue

        fn = _find_function_for_line(finding.line_number, boundaries)

        if not source_hits or not sink_hits:
            status = "unreachable"
            confidence = "low"
        elif not boundaries or (not source_functions and not sink_functions):
            # Simple scripts with direct source->sink patterns should be considered reachable.
            status = "reachable"
            confidence = "high"
        elif fn and fn in reachable_from_source and fn in sink_functions:
            status = "reachable"
            confidence = "high"
        elif fn and fn in reachable_from_source:
            status = "conditionally_reachable"
            confidence = "medium"
        else:
            status = "unknown"
            confidence = "medium"

        finding.reachability_status = status
        finding.metadata.update({
            "reachability_mode": "call_graph",
            "reachability_confidence": confidence,
            "reachability_evidence": {
                "source_hits": len(source_hits),
                "sink_hits": len(sink_hits),
                "source_functions": list(source_functions),
                "sink_functions": list(sink_functions),
                "current_function": fn,
                "call_graph": {k: list(v) for k, v in call_graph.items()},
            },
        })

    return findings
