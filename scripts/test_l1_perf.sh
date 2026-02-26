#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python3"
fi

export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

timestamp="$(date +"%Y%m%d_%H%M%S")"
DEFAULT_OUTPUT_JSON="$ROOT_DIR/artifacts/test-results/l1/l1_perf_${timestamp}.json"
export L1_PERF_OUTPUT_JSON="${L1_PERF_OUTPUT_JSON:-$DEFAULT_OUTPUT_JSON}"
export L1_PERF_P95_MS="${L1_PERF_P95_MS:-2500}"
export L1_CACHE_HIT_P95_MS="${L1_CACHE_HIT_P95_MS:-200}"

mkdir -p "$(dirname "$L1_PERF_OUTPUT_JSON")"

cd "$ROOT_DIR"
"$PYTHON_BIN" - <<'PY'
from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path

from vsh.common.models import L1ScanAnnotateRequest, ScanMode
from vsh.l1_hot.service import L1Service


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(p * len(ordered)))
    return ordered[rank - 1]


def summarize(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0}
    return {
        "count": float(len(values)),
        "p50": round(percentile(values, 0.50), 2),
        "p95": round(percentile(values, 0.95), 2),
        "max": round(max(values), 2),
    }


root = Path.cwd()
fixture_dir = root / "tests" / "fixtures"

samples = [
    ("python_bad", (fixture_dir / "python_sqli_bad.py").read_text(encoding="utf-8"), "python"),
    ("python_good", (fixture_dir / "python_sqli_good.py").read_text(encoding="utf-8"), "python"),
    ("js_bad", (fixture_dir / "js_xss_bad.js").read_text(encoding="utf-8"), "javascript"),
    ("js_good", (fixture_dir / "js_xss_good.js").read_text(encoding="utf-8"), "javascript"),
]

service = L1Service()
cache_miss_ms: list[float] = []
cache_hit_ms: list[float] = []

for round_idx in range(3):
    for sample_name, code, language in samples:
        suffix = f"# perf-miss-{round_idx}-{sample_name}" if language == "python" else f"// perf-miss-{round_idx}-{sample_name}"
        request = L1ScanAnnotateRequest(
            code=f"{code.rstrip()}\n{suffix}\n",
            language=language,
            file_path=f"tests/fixtures/{sample_name}.txt",
            mode=ScanMode.SNIPPET,
        )
        started = time.perf_counter()
        response = service.scan_annotate(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if response.errors:
            raise RuntimeError(f"cache miss run failed: {response.errors}")
        cache_miss_ms.append(elapsed_ms)

for sample_name, code, language in samples:
    request = L1ScanAnnotateRequest(
        code=code,
        language=language,
        file_path=f"tests/fixtures/{sample_name}.txt",
        mode=ScanMode.SNIPPET,
    )
    warmup = service.scan_annotate(request)
    if warmup.errors:
        raise RuntimeError(f"cache warmup failed: {warmup.errors}")
    for _ in range(4):
        started = time.perf_counter()
        response = service.scan_annotate(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if response.errors:
            raise RuntimeError(f"cache hit run failed: {response.errors}")
        cache_hit_ms.append(elapsed_ms)

miss_summary = summarize(cache_miss_ms)
hit_summary = summarize(cache_hit_ms)

miss_threshold = int(os.environ["L1_PERF_P95_MS"])
hit_threshold = int(os.environ["L1_CACHE_HIT_P95_MS"])

gate = {
    "cache_miss_p95": miss_summary["p95"] <= miss_threshold,
    "cache_hit_p95": hit_summary["p95"] <= hit_threshold,
}
gate["overall"] = all(gate.values())

report = {
    "samples": len(samples),
    "cache_miss_ms": miss_summary,
    "cache_hit_ms": hit_summary,
    "threshold_ms": {
        "cache_miss_p95": miss_threshold,
        "cache_hit_p95": hit_threshold,
    },
    "gate": gate,
}

output_path = Path(os.environ["L1_PERF_OUTPUT_JSON"])
output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

print("L1 perf checks passed." if gate["overall"] else "L1 perf checks failed.")
print(f"- cache_miss_p50_ms: {miss_summary['p50']}")
print(f"- cache_miss_p95_ms: {miss_summary['p95']}")
print(f"- cache_hit_p50_ms: {hit_summary['p50']}")
print(f"- cache_hit_p95_ms: {hit_summary['p95']}")
print(f"- threshold_cache_miss_p95_ms: {miss_threshold}")
print(f"- threshold_cache_hit_p95_ms: {hit_threshold}")
print(f"- perf_json: {output_path}")

if not gate["overall"]:
    raise SystemExit(1)
PY
