import json
import asyncio
import pytest
from unittest.mock import patch, MagicMock
from l3.providers.sbom.real import RealSBOMProvider
from l3.models.package_record import PackageRecord

SYFT_OUTPUT = {
    "artifacts": [
        {"name": "PyYAML", "version": "5.3.1", "type": "python"},
        {"name": "numpy",  "version": "1.24.0", "type": "python"},
        {"name": "somepkg","version": "1.0.0",  "type": "javascript"},
        {"name": "broken", "version": "",        "type": "python"}
    ]
}

OSV_BATCH_RESPONSE = {
    "results": [
        {"vulns": [{"id": "GHSA-aaa"}, {"id": "PYSEC-bbb"}]},
        {"vulns": []}
    ]
}

OSV_VULN_RESPONSE = {
    "id": "GHSA-aaa",
    "aliases": ["CVE-2020-14343"],
    "database_specific": {"severity": "CRITICAL"},
    "severity": []
}

OSV_NO_SEVERITY_RESPONSE = {
    "id": "GHSA-bbb",
    "aliases": ["CVE-2021-99999"],
    "database_specific": {},
    "severity": []
}

OSV_DUPLICATE_RESPONSE_1 = {
    "id": "GHSA-aaa",
    "aliases": ["CVE-2020-14343"],
    "database_specific": {"severity": "CRITICAL"},
    "severity": []
}

OSV_DUPLICATE_RESPONSE_2 = {
    "id": "PYSEC-bbb",
    "aliases": ["CVE-2020-14343"],
    "database_specific": {"severity": "HIGH"},
    "severity": []
}

def make_urlopen_mock(response_data: dict) -> MagicMock:
    mock_response = MagicMock()
    mock_response.read.return_value = (
        json.dumps(response_data).encode("utf-8")
    )
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    return mock_response

def make_subprocess_mock(output: dict) -> MagicMock:
    return MagicMock(stdout=json.dumps(output))

def test_scan_returns_package_records():
    provider = RealSBOMProvider()
    with patch("l3.providers.sbom.real.subprocess.run") as mock_run, \
         patch("l3.providers.sbom.real.urllib.request.urlopen") as mock_urlopen:
        mock_run.return_value = make_subprocess_mock(SYFT_OUTPUT)
        mock_urlopen.side_effect = [
            make_urlopen_mock(OSV_BATCH_RESPONSE),
            make_urlopen_mock(OSV_DUPLICATE_RESPONSE_1),
            make_urlopen_mock(OSV_DUPLICATE_RESPONSE_2)
        ]
        results = asyncio.run(provider.scan("some/project/file.py"))
        assert isinstance(results, list)
        assert len(results) >= 1
        assert all(isinstance(r, PackageRecord) for r in results)

def test_scan_returns_empty_on_syft_failure():
    provider = RealSBOMProvider()
    with patch("l3.providers.sbom.real.subprocess.run") as mock_run:
        mock_run.return_value = make_subprocess_mock({"artifacts": []})
        results = asyncio.run(provider.scan("some/project/file.py"))
        assert results == []

def test_run_syft_filters_python_only():
    provider = RealSBOMProvider()
    with patch("l3.providers.sbom.real.subprocess.run") as mock_run:
        mock_run.return_value = make_subprocess_mock(SYFT_OUTPUT)
        results = provider._run_syft("some/project/file.py")
        assert len(results) == 2
        names = [r["name"] for r in results]
        assert names == ["PyYAML", "numpy"]

def test_run_syft_skips_missing_fields():
    provider = RealSBOMProvider()
    with patch("l3.providers.sbom.real.subprocess.run") as mock_run:
        mock_run.return_value = make_subprocess_mock({
            "artifacts": [
                {"name": "valid",  "version": "1.0.0", "type": "python"},
                {"name": "broken", "version": "",       "type": "python"}
            ]
        })
        results = provider._run_syft("some/project/file.py")
        assert len(results) == 1
        assert results[0]["name"] == "valid"

def test_run_syft_returns_empty_on_failure():
    provider = RealSBOMProvider()
    with patch("l3.providers.sbom.real.subprocess.run") as mock_run:
        mock_run.side_effect = Exception("syft not found")
        results = provider._run_syft("some/project/file.py")
        assert results == []

def test_query_osv_batch_includes_vuln_packages():
    provider = RealSBOMProvider()
    packages = [
        {"name": "PyYAML", "version": "5.3.1", "ecosystem": "PyPI"},
        {"name": "numpy",  "version": "1.24.0", "ecosystem": "PyPI"}
    ]
    with patch("l3.providers.sbom.real.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = make_urlopen_mock(OSV_BATCH_RESPONSE)
        result = provider._query_osv_batch(packages)
        assert "PyYAML" in result
        assert result["PyYAML"] == ["GHSA-aaa", "PYSEC-bbb"]

def test_query_osv_batch_excludes_clean_packages():
    provider = RealSBOMProvider()
    packages = [
        {"name": "PyYAML", "version": "5.3.1", "ecosystem": "PyPI"},
        {"name": "numpy",  "version": "1.24.0", "ecosystem": "PyPI"}
    ]
    with patch("l3.providers.sbom.real.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = make_urlopen_mock(OSV_BATCH_RESPONSE)
        result = provider._query_osv_batch(packages)
        assert "numpy" not in result

def test_query_osv_batch_returns_empty_on_failure():
    provider = RealSBOMProvider()
    packages = [
        {"name": "PyYAML", "version": "5.3.1", "ecosystem": "PyPI"}
    ]
    with patch("l3.providers.sbom.real.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = Exception("network error")
        result = provider._query_osv_batch(packages)
        assert result == {}

def test_get_vuln_details_uses_db_severity():
    provider = RealSBOMProvider()
    pkg = {"name": "PyYAML", "version": "5.3.1", "ecosystem": "PyPI"}
    vuln_ids = ["GHSA-aaa"]
    with patch("l3.providers.sbom.real.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = make_urlopen_mock(OSV_VULN_RESPONSE)
        result = provider._get_vuln_details(pkg, vuln_ids)
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"
        assert result[0]["cve_id"] == "CVE-2020-14343"
        assert result[0]["cvss_score"] is None

def test_get_vuln_details_defaults_to_low():
    provider = RealSBOMProvider()
    pkg = {"name": "numpy", "version": "1.24.0", "ecosystem": "PyPI"}
    vuln_ids = ["GHSA-bbb"]
    with patch("l3.providers.sbom.real.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = make_urlopen_mock(OSV_NO_SEVERITY_RESPONSE)
        result = provider._get_vuln_details(pkg, vuln_ids)
        assert len(result) == 1
        assert result[0]["severity"] == "LOW"

def test_get_vuln_details_deduplicates_cve():
    provider = RealSBOMProvider()
    pkg = {"name": "PyYAML", "version": "5.3.1", "ecosystem": "PyPI"}
    vuln_ids = ["GHSA-aaa", "PYSEC-bbb"]
    with patch("l3.providers.sbom.real.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = [
            make_urlopen_mock(OSV_DUPLICATE_RESPONSE_1),
            make_urlopen_mock(OSV_DUPLICATE_RESPONSE_2)
        ]
        result = provider._get_vuln_details(pkg, vuln_ids)
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2020-14343"
        assert result[0]["severity"] == "CRITICAL"

def test_build_record_with_cve_id():
    provider = RealSBOMProvider()
    pkg = {"name": "PyYAML", "version": "5.3.1", "ecosystem": "PyPI"}
    vuln = {"cve_id": "CVE-2020-14343", "severity": "CRITICAL", "cvss_score": None}
    record = provider._build_record(pkg, vuln)
    assert isinstance(record, PackageRecord)
    assert record.package_id == "PKG-PyYAML-5.3.1-CVE-2020-14343"
    assert record.status == "upgrade_required"
    assert record.source == "L3_SBOM"

def test_build_record_without_cve_id():
    provider = RealSBOMProvider()
    pkg = {"name": "numpy", "version": "1.24.0", "ecosystem": "PyPI"}
    vuln = {"cve_id": None, "severity": "LOW", "cvss_score": None}
    record = provider._build_record(pkg, vuln)
    assert record.package_id == "PKG-numpy-1.24.0"
    assert record.cve_id is None
