import os
import json
import pytest
import requests
from dotenv import load_dotenv
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
LOG_PATH = os.getenv("LOG_PATH", "mock_db/log.json")

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
def pipeline():
    return PipelineFactory.create()

def test_e2e_scan_vulnerable_file(pipeline):
    """시나리오 1 — 취약 파일 스캔 검증"""
    result = pipeline.run("tests/e2e_target.py")
    
    assert result["is_clean"] is False
    assert len(result["scan_results"]) > 0
    assert len(result["fix_suggestions"]) > 0
    
    cwe_ids = [v["cwe_id"] for v in result["scan_results"]]
    assert "CWE-89" in cwe_ids, f"CWE-89 탐지 실패. 현재 탐지: {cwe_ids}"
    assert "CWE-798" in cwe_ids, f"CWE-798 탐지 실패. 현재 탐지: {cwe_ids}"
    
    for suggestion in result["fix_suggestions"]:
        assert suggestion.get("fixed_code"), "fixed_code가 비어있습니다."

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
        "severity", "line_number", "code_snippet",
        "original_code", "fixed_code", "status"
    ]
    
    for log in logs:
        for field in expected_fields:
            assert field in log, f"로그에 '{field}' 필드가 누락되었습니다: {log.get('issue_id')}"
        assert log["status"] == "pending", f"초기 상태가 pending이 아닙니다: {log.get('status')}"
