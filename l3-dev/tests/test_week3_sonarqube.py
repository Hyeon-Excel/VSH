import asyncio
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock, AsyncMock
from requests.auth import HTTPBasicAuth
from l3.llm.claude_adapter import ClaudeAdapter
from l3.providers.sonarqube.real import RealSonarQubeProvider
from l3.schema import VulnRecord

def get_provider():
    llm = ClaudeAdapter()
    provider = RealSonarQubeProvider(llm=llm)
    provider.sonar_url = "https://sonarcloud.io"
    provider.sonar_token = "test-token"
    provider.sonar_org = "test-org"
    provider.sonar_project_key = "test-project"
    provider.auth = HTTPBasicAuth("test-token", "")
    return provider

def get_past_time():
    return datetime.now(timezone.utc) - timedelta(seconds=60)

def get_future_submitted():
    return (datetime.now(timezone.utc) + timedelta(seconds=10)).strftime(
        "%Y-%m-%dT%H:%M:%S+0000"
    )

# --- _health_check ---

def test_health_check_success():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "UP"}
        mock_response.text = ""
        mock_get.return_value = mock_response
        
        result = asyncio.run(provider._health_check())
        assert result == True

def test_health_check_not_up():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "DOWN"}
        mock_response.text = ""
        mock_get.return_value = mock_response
        
        result = asyncio.run(provider._health_check())
        assert result == False

def test_health_check_exception():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.get") as mock_get:
        mock_get.side_effect = Exception("connection error")
        
        result = asyncio.run(provider._health_check())
        assert result == False

# --- _ensure_project ---

def test_ensure_project_created():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_response.text = ""
        mock_post.return_value = mock_response
        
        result = asyncio.run(provider._ensure_project())
        assert result is None

def test_ensure_project_already_exists():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {}
        mock_response.text = "key already exists"
        mock_post.return_value = mock_response
        
        result = asyncio.run(provider._ensure_project())
        assert result is None

def test_ensure_project_exception():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.post") as mock_post:
        mock_post.side_effect = Exception("network error")
        
        result = asyncio.run(provider._ensure_project())
        assert result is None

# --- _run_scanner ---

def test_run_scanner_success():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.subprocess.run") as mock_subprocess:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = asyncio.run(provider._run_scanner("project_path"))
        assert result == True

def test_run_scanner_failure():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.subprocess.run") as mock_subprocess:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        result = asyncio.run(provider._run_scanner("project_path"))
        assert result == False

def test_run_scanner_exception():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.subprocess.run") as mock_subprocess:
        mock_subprocess.side_effect = Exception("docker not found")
        
        result = asyncio.run(provider._run_scanner("project_path"))
        assert result == False

# --- _wait_for_analysis ---

def test_wait_for_analysis_success():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.get") as mock_get, \
         patch("l3.providers.sonarqube.real.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"tasks": [{"status": "SUCCESS", "submittedAt": get_future_submitted()}]}
        mock_response.text = ""
        mock_get.return_value = mock_response
        
        result = asyncio.run(provider._wait_for_analysis(get_past_time()))
        assert result == True

def test_wait_for_analysis_failed():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.get") as mock_get, \
         patch("l3.providers.sonarqube.real.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"tasks": [{"status": "FAILED", "submittedAt": get_future_submitted()}]}
        mock_response.text = ""
        mock_get.return_value = mock_response
        
        result = asyncio.run(provider._wait_for_analysis(get_past_time()))
        assert result == False

def test_wait_for_analysis_empty_then_success():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.get") as mock_get, \
         patch("l3.providers.sonarqube.real.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        mock_response1 = MagicMock()
        mock_response1.status_code = 200
        mock_response1.json.return_value = {"tasks": []}
        mock_response1.text = ""
        
        mock_response2 = MagicMock()
        mock_response2.status_code = 200
        mock_response2.json.return_value = {"tasks": [{"status": "SUCCESS", "submittedAt": get_future_submitted()}]}
        mock_response2.text = ""
        
        mock_get.side_effect = [mock_response1, mock_response2]
        
        result = asyncio.run(provider._wait_for_analysis(get_past_time()))
        assert result == True

def test_wait_for_analysis_timeout():
    provider = get_provider()
    result = asyncio.run(provider._wait_for_analysis(get_past_time(), timeout=0))
    assert result == False

# --- _fetch_issues ---

def test_fetch_issues_returns_list():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"issues": [
            {"rule": "squid:S2076", "severity": "CRITICAL"}
        ]}
        mock_response.text = ""
        mock_get.return_value = mock_response
        
        result = asyncio.run(provider._fetch_issues())
        assert len(result) == 1
        assert result[0]["rule"] == "squid:S2076"

def test_fetch_issues_empty():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"issues": []}
        mock_response.text = ""
        mock_get.return_value = mock_response
        
        result = asyncio.run(provider._fetch_issues())
        assert result == []

def test_fetch_issues_exception():
    provider = get_provider()
    with patch("l3.providers.sonarqube.real.requests.get") as mock_get:
        mock_get.side_effect = Exception("timeout")
        
        result = asyncio.run(provider._fetch_issues())
        assert result == []

# --- _map_severity ---

def test_map_severity_all_cases():
    provider = get_provider()
    assert provider._map_severity("BLOCKER") == "CRITICAL"
    assert provider._map_severity("CRITICAL") == "HIGH"
    assert provider._map_severity("MAJOR") == "MEDIUM"
    assert provider._map_severity("MINOR") == "LOW"
    assert provider._map_severity("INFO") == "LOW"

def test_map_severity_unknown_defaults_to_low():
    provider = get_provider()
    assert provider._map_severity("UNKNOWN_XYZ") == "LOW"

# --- _build_vuln_record ---

def test_build_vuln_record_success():
    provider = get_provider()
    mock_issue = {
        "rule": "squid:S2076",
        "severity": "CRITICAL",
        "component": "org:proj:app/db.py",
        "line": 34,
        "message": "SQL injection detected",
        "textRange": {"startOffset": 4, "endOffset": 20}
    }
    provider.llm.classify_cwe = AsyncMock(return_value="CWE-89")
    record = asyncio.run(provider._build_vuln_record(mock_issue))
    
    assert isinstance(record, VulnRecord) == True
    assert record.source == "L3_SONARQUBE"
    assert record.status == "pending"
    assert record.file_path == "app/db.py"
    assert record.cwe_id == "CWE-89"

def test_build_vuln_record_severity_mapping():
    provider = get_provider()
    mock_issue = {
        "rule": "squid:S2076",
        "severity": "CRITICAL",
        "component": "org:proj:app/db.py",
        "line": 34,
        "message": "SQL injection detected",
        "textRange": {"startOffset": 4, "endOffset": 20}
    }
    provider.llm.classify_cwe = AsyncMock(return_value="CWE-89")
    record = asyncio.run(provider._build_vuln_record(mock_issue))
    assert record.severity == "HIGH"

def test_build_vuln_record_fixed_values():
    provider = get_provider()
    mock_issue = {
        "rule": "squid:S2076",
        "severity": "CRITICAL",
        "component": "org:proj:app/db.py",
        "line": 34,
        "message": "SQL injection detected",
        "textRange": {"startOffset": 4, "endOffset": 20}
    }
    provider.llm.classify_cwe = AsyncMock(return_value="CWE-89")
    record = asyncio.run(provider._build_vuln_record(mock_issue))
    
    assert record.cvss_score is None
    assert record.kisa_ref == "KISA 시큐어코딩 가이드 참조"
    assert record.fss_ref is None
    assert record.language == "unknown"
    assert record.reachability_status == "unknown"
    assert record.reachability_confidence == "low"

def test_build_vuln_record_scan_error_on_exception():
    provider = get_provider()
    mock_issue = {
        "rule": "squid:S2076",
        "severity": "CRITICAL",
        "component": "org:proj:app/db.py",
        "line": 34,
        "message": "SQL injection detected",
        "textRange": {"startOffset": 4, "endOffset": 20}
    }
    provider._map_severity = MagicMock(return_value="INVALID_SEVERITY")
    provider.llm.classify_cwe = AsyncMock(return_value="CWE-89")
    record = asyncio.run(provider._build_vuln_record(mock_issue))
    
    assert record.status == "scan_error"
    assert record.source == "L3_SONARQUBE"

# --- scan() ---

def test_scan_returns_empty_when_health_check_fails():
    provider = get_provider()
    provider._health_check = AsyncMock(return_value=False)
    result = asyncio.run(provider.scan("project_path"))
    assert result == []

def test_scan_returns_empty_when_scanner_fails():
    provider = get_provider()
    provider._health_check = AsyncMock(return_value=True)
    provider._ensure_project = AsyncMock(return_value=None)
    provider._run_scanner = AsyncMock(return_value=False)
    result = asyncio.run(provider.scan("project_path"))
    assert result == []

def test_scan_full_flow():
    provider = get_provider()
    provider._health_check = AsyncMock(return_value=True)
    provider._ensure_project = AsyncMock(return_value=None)
    provider._run_scanner = AsyncMock(return_value=True)
    provider._wait_for_analysis = AsyncMock(return_value=True)
    provider._fetch_issues = AsyncMock(return_value=[
        {"rule": "squid:S2076",
         "severity": "CRITICAL",
         "component": "org:proj:app/db.py",
         "line": 34,
         "message": "SQL injection detected",
         "textRange": {"startOffset": 4, "endOffset": 20}}
    ])
    provider.llm.classify_cwe = AsyncMock(return_value="CWE-89")
    
    result = asyncio.run(provider.scan("project_path"))
    
    assert len(result) == 1
    assert result[0].source == "L3_SONARQUBE"
    assert result[0].status == "pending"
    assert result[0].severity == "HIGH"
