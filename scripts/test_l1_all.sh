#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/artifacts/test-results/l1"
mkdir -p "$LOG_DIR"

timestamp="$(date +"%Y%m%d_%H%M%S")"
log_file="$LOG_DIR/l1_test_${timestamp}.log"

{
  echo "[L1] pytest tests 시작"
  "$ROOT_DIR/scripts/test_l1_pytest.sh"
  echo ""
  echo "[L1] smoke tests 시작"
  "$ROOT_DIR/scripts/test_l1_smoke.sh"
  echo ""
  echo "[L1] 전체 테스트 완료"
} | tee "$log_file"

echo "L1 test log: $log_file"
