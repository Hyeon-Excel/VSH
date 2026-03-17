import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from l3.providers.poc.real import RealPoCProvider
from l3.schema import VulnRecord

def make_record(cwe_id="CWE-89", status="pending"):
    return VulnRecord(
        vuln_id=f"VSH-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}",
        rule_id="java:S3649",
        source="L3_SONARQUBE",
        detected_at=datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S"
        ),
        file_path="src/main.py",
        line_number=10,
        end_line_number=10,
        column_number=1,
        end_column_number=10,
        language="python",
        code_snippet="...",
        vuln_type="SQLi",
        cwe_id=cwe_id,
        cve_id=None,
        cvss_score=None,
        severity="HIGH",
        reachability_status="unknown",
        reachability_confidence="low",
        kisa_ref="KISA 시큐어코딩 가이드 참조",
        fss_ref=None,
        owasp_ref=None,
        fix_suggestion="...",
        status=status,
    )

def test_poc_verified():
    """_run_poc True 반환 시 poc_verified"""
    provider = RealPoCProvider(llm=MagicMock())
    record = make_record(cwe_id="CWE-89")
    provider._run_poc = AsyncMock(return_value=True)

    result = asyncio.run(provider.verify(record))

    assert result.status == "poc_verified"
    provider._run_poc.assert_called_once()

def test_poc_failed():
    """_run_poc False 반환 시 poc_failed"""
    provider = RealPoCProvider(llm=MagicMock())
    record = make_record(cwe_id="CWE-89")
    provider._run_poc = AsyncMock(return_value=False)

    result = asyncio.run(provider.verify(record))

    assert result.status == "poc_failed"
    provider._run_poc.assert_called_once()

def test_poc_skipped_no_cwe_id():
    """cwe_id None 시 _run_poc 호출 없이 poc_skipped"""
    provider = RealPoCProvider(llm=MagicMock())
    record = make_record(cwe_id=None)
    provider._run_poc = AsyncMock()

    result = asyncio.run(provider.verify(record))

    assert result.status == "poc_skipped"
    provider._run_poc.assert_not_called()

def test_poc_skipped_no_template():
    """TEMPLATE_MAP 에 없는 CWE 시 poc_skipped"""
    provider = RealPoCProvider(llm=MagicMock())
    record = make_record(cwe_id="CWE-79")
    provider._run_poc = AsyncMock()

    result = asyncio.run(provider.verify(record))

    assert result.status == "poc_skipped"
    provider._run_poc.assert_not_called()

def test_scan_error_on_exception():
    """_run_poc 예외 발생 시 verify 가 scan_error 반환"""
    provider = RealPoCProvider(llm=MagicMock())
    record = make_record(cwe_id="CWE-89")
    provider._run_poc = AsyncMock(
        side_effect=Exception("Docker 실행 실패")
    )

    result = asyncio.run(provider.verify(record))

    assert result.status == "scan_error"
