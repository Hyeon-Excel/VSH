import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from l3.providers.sbom.real import RealSBOMProvider

# [1] _detect_languages() 테스트 (케이스 1~5)

def test_detect_python():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "requirements.txt").touch()
        provider = RealSBOMProvider()
        langs = provider._detect_languages(tmpdir)
        assert langs == ["python"]

def test_detect_js():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "package.json").touch()
        provider = RealSBOMProvider()
        langs = provider._detect_languages(tmpdir)
        assert langs == ["js"]

def test_detect_python_and_js():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "requirements.txt").touch()
        (Path(tmpdir) / "package.json").touch()
        provider = RealSBOMProvider()
        langs = provider._detect_languages(tmpdir)
        assert set(langs) == {"python", "js"}

def test_detect_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        provider = RealSBOMProvider()
        langs = provider._detect_languages(tmpdir)
        assert langs == []

def test_detect_nonexistent():
    provider = RealSBOMProvider()
    langs = provider._detect_languages("/nonexistent/12345")
    assert langs == []

# [2] _run_cdxgen() 테스트 (케이스 6~9)

def make_cdxgen_mock(output_data: dict):
    def side_effect(cmd, **kwargs):
        output_path = cmd[5]
        import json
        from pathlib import Path
        Path(output_path).write_text(
            json.dumps(output_data), encoding="utf-8"
        )
        return MagicMock(returncode=0)
    return side_effect

@patch("subprocess.run")
def test_cdxgen_success(mock_run):
    CDXGEN_OUTPUT = {
        "components": [
            {
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20"
            },
            {
                "name": "express",
                "version": "4.18.0",
                "purl": "pkg:npm/express@4.18.0"
            }
        ]
    }
    mock_run.side_effect = make_cdxgen_mock(CDXGEN_OUTPUT)
    
    provider = RealSBOMProvider()
    result = provider._run_cdxgen(".", "js")
    
    assert len(result) == 2
    assert {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"} in result
    assert {"name": "express", "version": "4.18.0", "ecosystem": "npm"} in result

@patch("subprocess.run")
def test_cdxgen_purl_ecosystem(mock_run):
    CDXGEN_OUTPUT = {
        "components": [
            {
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20"
            }
        ]
    }
    mock_run.side_effect = make_cdxgen_mock(CDXGEN_OUTPUT)
    
    provider = RealSBOMProvider()
    result = provider._run_cdxgen(".", "js")
    assert len(result) == 1
    assert result[0]["ecosystem"] == "npm"

@patch("subprocess.run")
def test_cdxgen_empty_components(mock_run):
    mock_run.side_effect = make_cdxgen_mock({"components": []})
    
    provider = RealSBOMProvider()
    result = provider._run_cdxgen(".", "js")
    assert result == []

@patch("subprocess.run")
def test_cdxgen_missing_name_or_version(mock_run):
    CDXGEN_OUTPUT = {
        "components": [
            {"name": "valid", "version": "1.0.0", "purl": "pkg:npm/valid@1.0.0"},
            {"name": "no-version", "purl": "pkg:npm/no-version@"},
            {"version": "1.0.0", "purl": "pkg:npm/no-name@1.0.0"}
        ]
    }
    mock_run.side_effect = make_cdxgen_mock(CDXGEN_OUTPUT)
    
    provider = RealSBOMProvider()
    result = provider._run_cdxgen(".", "js")
    
    assert len(result) == 1
    assert result[0]["name"] == "valid"

# [3] scan() 분기 테스트 (케이스 10~13)

@pytest.mark.asyncio
@patch.object(RealSBOMProvider, "_run_syft", return_value=[])
@patch.object(RealSBOMProvider, "_run_cdxgen", return_value=[])
@patch.object(RealSBOMProvider, "_detect_languages", return_value=["python"])
async def test_scan_python_only(mock_detect, mock_cdxgen, mock_syft):
    provider = RealSBOMProvider()
    await provider.scan(".")
    mock_syft.assert_called_once()
    mock_cdxgen.assert_not_called()

@pytest.mark.asyncio
@patch.object(RealSBOMProvider, "_run_syft", return_value=[])
@patch.object(RealSBOMProvider, "_run_cdxgen", return_value=[])
@patch.object(RealSBOMProvider, "_detect_languages", return_value=["js"])
async def test_scan_js_only(mock_detect, mock_cdxgen, mock_syft):
    provider = RealSBOMProvider()
    await provider.scan(".")
    mock_syft.assert_not_called()
    mock_cdxgen.assert_called_once()

@pytest.mark.asyncio
@patch.object(RealSBOMProvider, "_run_syft", return_value=[])
@patch.object(RealSBOMProvider, "_run_cdxgen", return_value=[])
@patch.object(RealSBOMProvider, "_detect_languages", return_value=["python", "js"])
async def test_scan_python_and_js(mock_detect, mock_cdxgen, mock_syft):
    provider = RealSBOMProvider()
    await provider.scan(".")
    mock_syft.assert_called_once()
    mock_cdxgen.assert_called_once()

@pytest.mark.asyncio
@patch.object(RealSBOMProvider, "_query_osv_batch", return_value={})
@patch.object(RealSBOMProvider, "_run_syft", return_value=[{"name": "pkg-a", "version": "1.0", "ecosystem": "PyPI"}])
@patch.object(RealSBOMProvider, "_run_cdxgen", return_value=[{"name": "pkg-a", "version": "1.0", "ecosystem": "PyPI"}])
@patch.object(RealSBOMProvider, "_detect_languages", return_value=["python", "js"])
async def test_scan_deduplicate(mock_detect, mock_cdxgen, mock_syft, mock_query):
    provider = RealSBOMProvider()
    await provider.scan(".")
    
    mock_query.assert_called_once()
    args, kwargs = mock_query.call_args
    passed_packages = args[0]
    assert len(passed_packages) == 1
    assert passed_packages[0] == {"name": "pkg-a", "version": "1.0", "ecosystem": "PyPI"}