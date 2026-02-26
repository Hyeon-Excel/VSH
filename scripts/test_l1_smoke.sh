#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python3"
fi

export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

cd "$ROOT_DIR"
"$PYTHON_BIN" - <<'PY'
from __future__ import annotations

import os
from pathlib import Path

from vsh.common.models import L1ScanAnnotateRequest, ScanMode
from vsh.l1_hot.semgrep_runner import SemgrepRunner
from vsh.l1_hot.service import L1Service

root = Path.cwd()
fixture_dir = root / "tests" / "fixtures"
python_bad = (fixture_dir / "python_sqli_bad.py").read_text(encoding="utf-8")
js_bad = (fixture_dir / "js_xss_bad.js").read_text(encoding="utf-8")

# 1) service-level smoke test on Python sample
service = L1Service()
response = service.scan_annotate(
    L1ScanAnnotateRequest(
        code=python_bad,
        language="python",
        file_path="tests/fixtures/python_sqli_bad.py",
        mode=ScanMode.FILE,
    )
)
assert response.errors == [], f"L1 service errors: {response.errors}"
assert len(response.findings) >= 1, "L1 should detect at least one Python SQLi finding."
assert response.annotation_patch.strip(), "L1 should return non-empty annotation patch."
assert response.import_candidates, "L1 should extract import candidates."
assert any(c.package_name == "sqlite3" for c in response.import_candidates), "sqlite3 import should be extracted."

# 2) ensure semgrep-cli path works when semgrep binary is available
runner = SemgrepRunner()
semgrep_bin = runner._resolve_semgrep_binary()
python_result = runner.run_semgrep(python_bad, "python")
python_engine = python_result.get("engine", "semgrep-cli")
assert len(python_result.get("results", [])) >= 1, "Runner should detect Python issue."
if semgrep_bin:
    assert (
        python_engine == "semgrep-cli"
    ), f"semgrep binary exists ({semgrep_bin}) but engine was {python_engine}"

# 3) detect JavaScript XSS sample
js_result = runner.run_semgrep(js_bad, "javascript")
assert len(js_result.get("results", [])) >= 1, "Runner should detect JavaScript XSS issue."

# 4) force fallback path and validate behavior
original_semgrep_bin = os.environ.get("SEMGREP_BIN")
os.environ["SEMGREP_BIN"] = "/tmp/vsh-semgrep-does-not-exist"
try:
    fallback_result = SemgrepRunner().run_semgrep(python_bad, "python")
finally:
    if original_semgrep_bin is None:
        os.environ.pop("SEMGREP_BIN", None)
    else:
        os.environ["SEMGREP_BIN"] = original_semgrep_bin

assert fallback_result.get("engine") == "fallback", "Fallback engine was not used as expected."
assert len(fallback_result.get("results", [])) >= 1, "Fallback should still detect issue."

print("L1 smoke checks passed.")
print(f"- semgrep_bin: {semgrep_bin or 'not found'}")
print(f"- python_engine: {python_engine}")
print(f"- python_findings: {len(python_result.get('results', []))}")
print(f"- js_findings: {len(js_result.get('results', []))}")
print(f"- fallback_findings: {len(fallback_result.get('results', []))}")
print(f"- python_import_candidates: {len(response.import_candidates)}")
PY
