import os
import json
import pytest
import requests
from dotenv import load_dotenv
from config import LOG_PATH as DEFAULT_LOG_PATH
from pipeline import PipelineFactory

load_dotenv()

BASE_URL = "http://localhost:3000"

def is_server_running():
    try:
        requests.get(BASE_URL, timeout=1)
        return True
    except Exception:
        return False

requires_server = pytest.mark.skipif(
    not is_server_running(),
    reason=f"Dashboard 서버가 실행 중이 아닙니다. uvicorn dashboard.app:app --port 3000 실행 후 재시도"
)

# log.json 경로 가져오기
LOG_PATH = os.getenv("LOG_PATH", DEFAULT_LOG_PATH)

def _clear_log_json():
    """log.json을 빈 리스트로 초기화합니다."""
    try:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            json.dump([], f)
    except Exception as e:
        print(f"Error clearing {LOG_PATH}: {e}")

@pytest.fixture(autouse=True)
def reset_log_json():
    # setup: 테스트 시작 전 초기화
    _clear_log_json()
    yield
    # teardown: 테스트 종료 후 초기화
    _clear_log_json()

@pytest.fixture
def pipeline(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return PipelineFactory.create()

def test_e2e_scan_vulnerable_file(pipeline):
    """시나리오 1 — 취약 파일 스캔 검증"""
    result = pipeline.run("tests/e2e_target.py")
    
    assert result["is_clean"] is False
    assert len(result["scan_results"]) > 0
    assert len(result["fix_suggestions"]) > 0
    assert len(result["l2_vuln_records"]) > 0
    
    cwe_ids = [v["cwe_id"] for v in result["scan_results"]]
    assert "CWE-89" in cwe_ids, f"CWE-89 탐지 실패. 현재 탐지: {cwe_ids}"
    assert "CWE-798" in cwe_ids, f"CWE-798 탐지 실패. 현재 탐지: {cwe_ids}"
    
    for suggestion in result["fix_suggestions"]:
        assert suggestion.get("fixed_code"), "fixed_code가 비어있습니다."
        assert suggestion.get("vuln_id"), "vuln_id가 비어있습니다."
        metadata = suggestion.get("metadata", {}).get("l2", {})
        assert metadata, "metadata.l2가 비어있습니다."
        assert metadata.get("evidence_refs"), "metadata.l2.evidence_refs가 비어있습니다."
        assert metadata.get("evidence_summary"), "metadata.l2.evidence_summary가 비어있습니다."
        assert metadata.get("retrieval_backend"), "metadata.l2.retrieval_backend가 비어있습니다."
        assert metadata.get("chroma_status"), "metadata.l2.chroma_status가 비어있습니다."
        assert metadata.get("decision_status"), "metadata.l2.decision_status가 비어있습니다."
        assert "confidence_score" in metadata, "metadata.l2.confidence_score가 누락되었습니다."
        assert metadata.get("confidence_reason"), "metadata.l2.confidence_reason이 비어있습니다."

    supply_chain = next((s for s in result["fix_suggestions"] if s["cwe_id"] == "CWE-829"), None)
    assert supply_chain is not None, "CWE-829 공급망 finding이 누락되었습니다."
    supply_chain_metadata = supply_chain["metadata"]["l2"]
    assert supply_chain_metadata["registry_status"] == "FOUND"
    assert supply_chain_metadata["osv_status"] == "FOUND"
    assert supply_chain_metadata.get("verification_summary"), "verification_summary가 비어있습니다."
    assert supply_chain_metadata["patch_status"] == "GENERATED"
    assert supply_chain_metadata.get("patch_diff"), "patch_diff가 비어있습니다."
    assert supply_chain_metadata.get("processing_trace"), "processing_trace가 비어있습니다."
    assert supply_chain_metadata["category"] == "supply_chain"
    assert supply_chain_metadata["remediation_kind"] == "version_bump_patch"
    assert supply_chain_metadata["target_ref"] == "dependency:requests"
    assert supply_chain_metadata["decision_status"] == "confirmed"
    assert supply_chain_metadata["confidence_score"] >= 85
    assert supply_chain_metadata.get("confidence_reason"), "confidence_reason이 비어있습니다."
    assert result["summary"]["findings_total"] >= 1
    assert result["summary"]["l2_vuln_records_total"] >= 1
    assert result["summary"]["supply_chain_findings_total"] >= 1
    assert result["summary"]["patch_generated_total"] >= 1
    assert result["summary"]["decision_confirmed_total"] >= 1
    assert result["summary"]["confidence_high_total"] >= 1

@requires_server
def test_e2e_dashboard_api(pipeline):
    """시나리오 2 — Dashboard API 검증"""
    # 1. 파일 스캔하여 데이터 생성
    pipeline.run("tests/e2e_target.py")
    
    # 2. GET /api/logs 호출
    response = requests.get(f"{BASE_URL}/api/logs")
    assert response.status_code == 200
    data = response.json()
    
    assert len(data["logs"]) > 0
    assert data["total"] == len(data["logs"])
    for log in data["logs"]:
        assert "original_code" in log
        assert "fixed_code" in log
        assert "rule_id" in log
        assert "l1_reachability_status" in log
        assert "l1_references" in log
        assert "evidence_refs" in log
        assert "evidence_summary" in log
        assert "retrieval_backend" in log
        assert "chroma_status" in log
        assert "chroma_summary" in log
        assert "chroma_hits" in log
        assert "registry_status" in log
        assert "osv_status" in log
        assert "verification_summary" in log
        assert "decision_status" in log
        assert "confidence_score" in log
        assert "confidence_reason" in log
        assert "patch_status" in log
        assert "patch_summary" in log
        assert "patch_diff" in log
        assert "processing_trace" in log
        assert "processing_summary" in log
        assert "category" in log
        assert "remediation_kind" in log
        assert "target_ref" in log
        
    # 3. pending 항목 추출
    pending_logs = [l for l in data["logs"] if l["status"] == "pending"]
    assert len(pending_logs) > 0, "pending 항목이 없음. scan_file을 먼저 실행했는지 확인"
    
    # 4. POST /api/logs/{id}/accept 호출
    first_issue_id = pending_logs[0]["issue_id"]
    accept_response = requests.post(f"{BASE_URL}/api/logs/{first_issue_id}/accept")
    assert accept_response.status_code == 200
    accept_data = accept_response.json()
    assert accept_data["status"] == "accepted"
    assert accept_data.get("fixed_code"), "accept 응답에 fixed_code가 비어있음"
    
    # 5. POST /api/logs/{id}/dismiss 호출 (다음 pending 항목이 있을 경우)
    if len(pending_logs) > 1:
        second_issue_id = pending_logs[1]["issue_id"]
        dismiss_response = requests.post(f"{BASE_URL}/api/logs/{second_issue_id}/dismiss")
        assert dismiss_response.status_code == 200
        dismiss_data = dismiss_response.json()
        assert dismiss_data["status"] == "dismissed"
        
    # 6. 존재하지 않는 issue_id -> 404 확인
    not_found_response = requests.post(f"{BASE_URL}/api/logs/nonexistent_id/accept")
    assert not_found_response.status_code == 404

def test_e2e_rescan_fixed_file(pipeline):
    """시나리오 3 — 수정된 파일 재스캔 검증"""
    result = pipeline.run("tests/e2e_target_fixed.py")
    
    cwe_ids = [v["cwe_id"] for v in result["scan_results"]]
    assert "CWE-89" not in cwe_ids, f"CWE-89 오탐 발생. 현재 탐지: {cwe_ids}"
    assert "CWE-798" not in cwe_ids, f"CWE-798 오탐 발생. 현재 탐지: {cwe_ids}"

def test_e2e_log_history(pipeline):
    """시나리오 4 — log.json 전체 이력 검증"""
    pipeline.run("tests/e2e_target.py")
    
    logs = pipeline.log_repo.find_all()
    assert len(logs) > 0
    
    expected_fields = [
        "issue_id", "file_path", "cwe_id", 
        "vuln_id", "metadata",
        "severity", "line_number", "code_snippet",
        "original_code", "fixed_code", "status",
        "l2_vuln_record",
        "rule_id", "l1_reachability_status", "l1_references",
        "evidence_refs", "evidence_summary",
        "retrieval_backend", "chroma_status", "chroma_summary", "chroma_hits",
        "registry_status", "registry_summary",
        "osv_status", "osv_summary",
        "verification_summary",
        "decision_status", "confidence_score", "confidence_reason",
        "patch_status", "patch_summary", "patch_diff",
        "processing_trace", "processing_summary",
        "category", "remediation_kind", "target_ref",
    ]
    
    for log in logs:
        for field in expected_fields:
            assert field in log, f"로그에 '{field}' 필드가 누락되었습니다: {log.get('issue_id')}"
        assert log["l2_vuln_record"] is not None, "로그에 l2_vuln_record가 비어 있습니다."
        assert log["l2_vuln_record"]["source"] == "L2"
        assert log["l2_vuln_record"]["vuln_id"]
        assert log["status"] == "pending", f"초기 상태가 pending이 아닙니다: {log.get('status')}"
