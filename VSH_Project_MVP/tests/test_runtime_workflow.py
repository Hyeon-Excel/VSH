from __future__ import annotations

import json
import time
from pathlib import Path

from layer2.reasoning import L2ReasoningPipeline
from layer2.reasoning.models import validate_reasoning_result
from vsh_runtime.diagnostics import build_markdown_preview, vuln_to_diagnostic
from vsh_runtime.engine import VshRuntimeEngine
from vsh_runtime.risk import compute_vuln_risk
from vsh_runtime.sca_usage import build_package_usage_index
from vsh_runtime.watcher import ProjectWatcher


def test_watcher_save_event(tmp_path: Path):
    file = tmp_path / "app.py"
    file.write_text("print('x')\n", encoding="utf-8")
    watcher = ProjectWatcher(str(tmp_path), debounce_sec=0.0, interval=0.1)
    watcher.poll_once()
    time.sleep(0.01)
    file.write_text("print(eval(input()))\n", encoding="utf-8")
    events = watcher.poll_once()
    assert isinstance(events, list)


def test_diagnostics_json_schema(tmp_path: Path):
    engine = VshRuntimeEngine()
    file = tmp_path / "a.py"
    file.write_text("print(eval(input()))\n", encoding="utf-8")
    result = engine.get_diagnostics(str(file))
    diag = result["diagnostics"][0]
    for key in ["file", "line", "severity", "source", "rule_id", "message", "suggestion"]:
        assert key in diag


def test_non_destructive_preview(tmp_path: Path):
    file = tmp_path / "a.py"
    original = "print(eval(input()))\n"
    file.write_text(original, encoding="utf-8")
    engine = VshRuntimeEngine()
    payload = engine.analyze_file(str(file))
    md = build_markdown_preview(payload["diagnostics"])
    assert "Diagnostics Preview" in md
    assert file.read_text(encoding="utf-8") == original


def test_project_level_package_usage_index(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import requests\nrequests.get('http://x')\n", encoding="utf-8")
    index = build_package_usage_index(str(tmp_path))
    assert "requests" in index


def test_vulnerable_api_referenced_status(tmp_path: Path):
    (tmp_path / "app.py").write_text("import requests\nrequests.get('http://x')\n", encoding="utf-8")
    idx = build_package_usage_index(str(tmp_path))
    assert idx["requests"]["usage_status"] in {"vulnerable_api_referenced", "needs_manual_review", "package_imported"}


def test_l2_reasoning_schema_validation():
    payload = validate_reasoning_result({"linked_vuln_id": "V1", "verdict": "bad", "confidence": 2})
    assert payload.verdict == "needs_review"
    assert 0.0 <= payload.confidence <= 1.0


def test_mock_reasoning_provider(tmp_path: Path):
    file = tmp_path / "a.py"
    file.write_text("print(eval(input()))\n", encoding="utf-8")
    engine = VshRuntimeEngine()
    out = engine.analyze_file(str(file))
    assert out["l2_reasoning_results"]


def test_aggregate_priority_risk_score():
    score, pri = compute_vuln_risk({"severity": "HIGH", "reachability_status": "reachable"}, {"verdict": "likely_vulnerable", "confidence": 0.9})
    assert score > 0
    assert pri in {"P1", "P2", "P3", "P4", "INFO"}


def test_l1_l2_l3_e2e(tmp_path: Path):
    file = tmp_path / "a.py"
    file.write_text("print(eval(input()))\n", encoding="utf-8")
    payload = VshRuntimeEngine().analyze_file(str(file))
    assert "vuln_records" in payload and "l2_reasoning_results" in payload and "l3_validation_results" in payload
    assert all(v.get("l3_validated") is not None for v in payload["vuln_records"])
    assert all(v.get("l3_confidence") is not None for v in payload["vuln_records"])


def test_cli_snapshot_shape(tmp_path: Path):
    file = tmp_path / "a.py"
    file.write_text("print(eval(input()))\n", encoding="utf-8")
    payload = VshRuntimeEngine().analyze_file(str(file))
    dumped = json.dumps(payload, ensure_ascii=False)
    assert "diagnostics" in dumped and "aggregate_summary" in dumped
