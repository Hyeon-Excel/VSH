from repository import MockKnowledgeRepo, MockFixRepo, MockLogRepo
import os

def test_repository():
    print("=== Repository Tests ===")

    # 테스트 1 — KnowledgeRepo 정상 조회
    knowledge_repo = MockKnowledgeRepo()
    result = knowledge_repo.find_by_id("CWE-78")
    assert result is not None, "CWE-78 조회 실패"
    assert result["id"] == "CWE-78", "id 불일치"
    print(f"[PASS] KnowledgeRepo 정상 조회: {result['name']}")

    # 테스트 2 — KnowledgeRepo 없는 항목 조회
    result = knowledge_repo.find_by_id("CWE-999")
    assert result is None, "없는 항목은 None이어야 함"
    print("[PASS] KnowledgeRepo 없는 항목 -> None 정상 반환")

    # 테스트 3 — FixRepo 정상 조회
    fix_repo = MockFixRepo()
    result = fix_repo.find_by_id("CWE-78")
    assert result is not None, "CWE-78 수정 예시 조회 실패"
    print(f"[PASS] FixRepo 정상 조회: {result['description']}")

    # 테스트 4 — LogRepo 저장 및 조회
    log_repo = MockLogRepo()
    log_data = {
        "issue_id": "issue-001",
        "file_path": "test.py",
        "cwe_id": "CWE-78",
        "severity": "HIGH",
        "status": "pending"
    }
    
    # Save log data
    if log_repo.save(log_data):
         print(f"[PASS] LogRepo 저장 성공")
    else:
         print(f"[FAIL] LogRepo 저장 실패")

    result = log_repo.find_by_id("issue-001")
    assert result is not None, "저장 후 조회 실패"
    assert result["status"] == "pending", "status 불일치"
    print(f"[PASS] LogRepo 조회 성공: {result['issue_id']}")

    # 테스트 5 — LogRepo 상태 업데이트
    success = log_repo.update_status("issue-001", "accepted")
    assert success is True, "update_status 실패"
    
    result = log_repo.find_by_id("issue-001")
    assert result["status"] == "accepted", "status 업데이트 실패"
    print(f"[PASS] LogRepo 상태 업데이트 성공: {result['status']}")

    # 테스트 6 — LogRepo 잘못된 status 값
    try:
        log_repo.update_status("issue-001", "invalid_status")
        print("[FAIL] ValueError NOT raised for invalid status")
    except ValueError as e:
        print(f"[PASS] ValueError 정상 발생: {e}")

    # 테스트 7 — 없는 항목 status 업데이트
    result = log_repo.update_status("issue-999", "accepted")
    assert result is False, "없는 항목 업데이트는 False여야 함"
    print("[PASS] 없는 항목 update_status -> False 정상 반환")

if __name__ == "__main__":
    test_repository()
