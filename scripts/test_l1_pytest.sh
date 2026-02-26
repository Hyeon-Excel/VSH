#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_VENV_PYTHON="$ROOT_DIR/.venv/bin/python"
PYTHON_BIN="${PYTHON_BIN:-$DEFAULT_VENV_PYTHON}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python3"
fi

export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

cd "$ROOT_DIR"
if ! "$PYTHON_BIN" -c "import pytest" >/dev/null 2>&1; then
  PYTHON_BIN="python3"
fi
"$PYTHON_BIN" -m pytest -q \
  tests/test_l1_scan.py \
  tests/test_l1_patch.py \
  tests/test_l1_patch_apply.py \
  tests/test_l1_tree_sitter.py \
  tests/test_l1_resilience.py \
  tests/test_l1_cache.py \
  tests/test_l1_vuln_samples.py
