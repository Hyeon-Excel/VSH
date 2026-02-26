#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write L1 test result markdown from test artifacts.")
    parser.add_argument("--pytest-log", required=True, help="Path to pytest log file.")
    parser.add_argument("--smoke-log", required=True, help="Path to smoke log file.")
    parser.add_argument("--perf-json", required=True, help="Path to perf JSON file.")
    parser.add_argument("--all-log", required=True, help="Path to integrated L1 log file.")
    parser.add_argument("--output", required=True, help="Path to output markdown report.")
    return parser.parse_args()


def safe_read(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def get_git_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return "unknown"
    return result.stdout.strip() or "unknown"


def parse_pytest_counts(text: str) -> dict[str, int]:
    counts = {
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }
    for number, kind in re.findall(r"(\d+)\s+(passed|failed|error|errors|skipped|xfailed|xpassed)", text):
        key = "errors" if kind in {"error", "errors"} else kind
        counts[key] += int(number)
    return counts


def parse_smoke_status(text: str) -> bool:
    return "L1 smoke checks passed." in text


def parse_perf(path: Path) -> dict[str, object]:
    if not path.exists():
        return {
            "cache_miss_ms": {"p95": 0.0},
            "cache_hit_ms": {"p95": 0.0},
            "threshold_ms": {"cache_miss_p95": 0, "cache_hit_p95": 0},
            "gate": {"overall": False},
        }
    return json.loads(path.read_text(encoding="utf-8"))


def build_failed_cases(pytest_counts: dict[str, int], smoke_ok: bool, perf_gate: bool) -> list[str]:
    failures: list[str] = []
    if pytest_counts["failed"] > 0 or pytest_counts["errors"] > 0:
        failures.append("Pytest 실패 또는 에러가 존재합니다.")
    if not smoke_ok:
        failures.append("Smoke 테스트 실패가 존재합니다.")
    if not perf_gate:
        failures.append("성능 게이트(cache miss/cache hit p95) 기준을 충족하지 못했습니다.")
    return failures


def main() -> None:
    args = parse_args()

    pytest_log = Path(args.pytest_log)
    smoke_log = Path(args.smoke_log)
    perf_json = Path(args.perf_json)
    all_log = Path(args.all_log)
    output = Path(args.output)

    pytest_text = safe_read(pytest_log)
    smoke_text = safe_read(smoke_log)
    perf = parse_perf(perf_json)

    pytest_counts = parse_pytest_counts(pytest_text)
    tested_total = pytest_counts["passed"] + pytest_counts["failed"] + pytest_counts["errors"]
    if tested_total == 0:
        tested_total = sum(pytest_counts.values())
    pass_rate = 0.0 if tested_total == 0 else round((pytest_counts["passed"] / tested_total) * 100, 2)

    smoke_ok = parse_smoke_status(smoke_text)
    perf_gate = bool(perf.get("gate", {}).get("overall", False))
    overall_ok = pytest_counts["failed"] == 0 and pytest_counts["errors"] == 0 and smoke_ok and perf_gate

    failed_cases = build_failed_cases(pytest_counts, smoke_ok, perf_gate)
    if not failed_cases:
        failed_cases = ["없음"]

    unresolved_items = [
        "TypeScript alias/multiline import 추출 확장 케이스 추가 필요",
        "GitHub branch protection에서 `L1 CI Gate / L1 Tests`를 required check로 지정 필요",
        "패키지 실존성/타이포스쿼팅 검증은 L2 구현 연동 필요",
    ]

    now_local = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    git_sha = get_git_sha()

    miss = perf.get("cache_miss_ms", {})
    hit = perf.get("cache_hit_ms", {})
    threshold = perf.get("threshold_ms", {})

    lines = [
        "# L1 Test Result",
        "",
        f"- 작성 시각: {now_local}",
        f"- 대상 프로젝트: `{Path.cwd()}`",
        f"- 커밋 SHA: `{git_sha}`",
        "",
        "## 1. 판정 요약",
        "",
        f"- 전체 판정: {'PASS' if overall_ok else 'FAIL'}",
        f"- Pytest 통과율: {pytest_counts['passed']}/{tested_total} ({pass_rate}%)",
        f"- Smoke 테스트: {'PASS' if smoke_ok else 'FAIL'}",
        f"- 성능 게이트: {'PASS' if perf_gate else 'FAIL'}",
        "",
        "## 2. 성능 지표(D4)",
        "",
        f"- cache miss p95: {miss.get('p95', 0.0)} ms (기준 <= {threshold.get('cache_miss_p95', 0)} ms)",
        f"- cache hit p95: {hit.get('p95', 0.0)} ms (기준 <= {threshold.get('cache_hit_p95', 0)} ms)",
        f"- cache miss p50: {miss.get('p50', 0.0)} ms",
        f"- cache hit p50: {hit.get('p50', 0.0)} ms",
        "",
        "## 3. 실패 케이스",
        "",
    ]

    lines.extend([f"- {item}" for item in failed_cases])
    lines.extend(
        [
            "",
            "## 4. 미구현/잔여 리스크",
            "",
        ]
    )
    lines.extend([f"- {item}" for item in unresolved_items])
    lines.extend(
        [
            "",
            "## 5. 실행 산출물",
            "",
            f"- 통합 로그: `{all_log}`",
            f"- Pytest 로그: `{pytest_log}`",
            f"- Smoke 로그: `{smoke_log}`",
            f"- 성능 JSON: `{perf_json}`",
            "",
            "## 6. 기준 문서",
            "",
            "- `docs/layer1.md`",
            "- `docs/roadmap.md`",
        ]
    )

    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
