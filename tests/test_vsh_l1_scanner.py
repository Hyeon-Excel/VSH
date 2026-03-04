from pathlib import Path

from modules.scanner.base_scanner import BaseScanner
from modules.scanner.vsh_l1_scanner import VSHL1Scanner
from pipeline.analysis_pipeline import AnalysisPipeline
from vsh.core.config import VSHConfig


def test_vsh_l1_scanner_implements_base_scanner(tmp_path: Path):
    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    scanner = VSHL1Scanner(cfg)
    assert isinstance(scanner, BaseScanner)


def test_pipeline_run_l1_returns_scan_result(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("user_input = input()\nquery = f\"SELECT * FROM users WHERE id = {user_input}\"\n")

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    pipeline = AnalysisPipeline(scanner=VSHL1Scanner(cfg))

    result = pipeline.run_l1()

    assert result.project == tmp_path.name
    assert isinstance(result.notes, list)
    assert any(note.startswith("layer=L1") for note in result.notes)
