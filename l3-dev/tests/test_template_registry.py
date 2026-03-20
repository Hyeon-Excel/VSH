import pytest
import asyncio
from unittest.mock import patch, MagicMock

from l3.providers.poc.template_registry import TemplateRegistry
from l3.providers.poc.real import RealPoCProvider
from l3.schema import VulnRecord

def get_dummy_record(cwe_id="CWE-89"):
    return VulnRecord(
        vuln_id="VSH-20260320-12345678",
        rule_id="java:S3649",
        source="L3_POC",
        detected_at="2026-03-20T12:00:00",
        file_path="src/main.java",
        line_number=10,
        end_line_number=10,
        column_number=0,
        end_column_number=10,
        language="java",
        code_snippet="String query = ...",
        vuln_type="SQLi",
        cwe_id=cwe_id,
        cve_id=None,
        cvss_score=None,
        severity="HIGH",
        reachability_status="unknown",
        reachability_confidence="low",
        kisa_ref="입력데이터 검증",
        fss_ref=None,
        owasp_ref=None,
        fix_suggestion="파라미터화된 쿼리 사용"
    )

def test_load_cwe89_success():
    result = TemplateRegistry.load("CWE-89")
    assert isinstance(result, list)
    assert len(result) >= 10
    assert any("or" in p.lower() for p in result)

def test_load_unknown_cwe():
    result = TemplateRegistry.load("CWE-999")
    assert result == []

def test_load_no_empty_lines():
    result = TemplateRegistry.load("CWE-89")
    for p in result:
        assert p.strip() != ""

@patch("l3.providers.poc.template_registry.urllib.request.urlopen")
@patch("l3.providers.poc.template_registry.Path.exists")
def test_load_network_failure(mock_exists, mock_urlopen):
    mock_exists.return_value = False
    mock_urlopen.side_effect = Exception("Network Error")
    
    result = TemplateRegistry.load("CWE-89")
    assert result == []

def test_verify_no_payloads_returns_poc_skipped():
    record = get_dummy_record(cwe_id="CWE-89")
    provider = RealPoCProvider(llm=MagicMock())
    
    with patch("l3.providers.poc.real.TemplateRegistry.load", return_value=[]):
        result = asyncio.run(provider.verify(record))
        
    assert result.status == "poc_skipped"

def test_verify_none_cwe_id_returns_poc_skipped():
    record = get_dummy_record(cwe_id=None)
    provider = RealPoCProvider(llm=MagicMock())
    
    result = asyncio.run(provider.verify(record))
    assert result.status == "poc_skipped"
