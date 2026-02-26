#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/artifacts/test-results/l1"
mkdir -p "$LOG_DIR"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python3"
fi

timestamp="$(date +"%Y%m%d_%H%M%S")"
log_file="$LOG_DIR/l1_test_${timestamp}.log"
pytest_log="$LOG_DIR/l1_pytest_${timestamp}.log"
smoke_log="$LOG_DIR/l1_smoke_${timestamp}.log"
perf_log="$LOG_DIR/l1_perf_${timestamp}.log"
perf_json="$LOG_DIR/l1_perf_${timestamp}.json"
report_file="$ROOT_DIR/L1-test-result.md"

test_status=0
: > "$log_file"

echo "[L1] pytest tests 시작" | tee -a "$log_file"
if ! "$ROOT_DIR/scripts/test_l1_pytest.sh" >"$pytest_log" 2>&1; then
  test_status=1
fi
cat "$pytest_log" | tee -a "$log_file"
echo "" | tee -a "$log_file"
echo "[L1] smoke tests 시작" | tee -a "$log_file"
if ! "$ROOT_DIR/scripts/test_l1_smoke.sh" >"$smoke_log" 2>&1; then
  test_status=1
fi
cat "$smoke_log" | tee -a "$log_file"
echo "" | tee -a "$log_file"
echo "[L1] perf tests 시작" | tee -a "$log_file"
if ! L1_PERF_OUTPUT_JSON="$perf_json" "$ROOT_DIR/scripts/test_l1_perf.sh" >"$perf_log" 2>&1; then
  test_status=1
fi
cat "$perf_log" | tee -a "$log_file"
echo "" | tee -a "$log_file"
echo "[L1] 전체 테스트 완료" | tee -a "$log_file"

"$PYTHON_BIN" "$ROOT_DIR/scripts/write_l1_test_result.py" \
  --pytest-log "$pytest_log" \
  --smoke-log "$smoke_log" \
  --perf-json "$perf_json" \
  --all-log "$log_file" \
  --output "$report_file"

echo "L1 test log: $log_file"
echo "L1 test report: $report_file"

exit "$test_status"
