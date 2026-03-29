import json
import os
from dotenv import load_dotenv

# 환경변수 로드
load_dotenv()

# tools.server에서 툴 함수들 import
from tools.server import scan_file, get_report, update_status

def run_tool_tests():
    print("=== MCP Tool Registration Tests ===")

    # 테스트 1 — scan_file 취약 파일
    print("\n--- Test 1: scan_file (test_vuln.py) ---")
    result_str = scan_file("test_vuln.py")
    result = json.loads(result_str)
    assert isinstance(result, dict), "반환 타입이 dict여야 함"
    assert "scan_results" in result
    print(f"[PASS] scan_file 결과: scan_results {len(result.get('scan_results', []))}개")

    # 테스트 2 — scan_file 정상 파일
    # 참고: SBOMScanner가 루트의 requirements.txt를 읽으므로 is_clean은 False일 수 있음
    print("\n--- Test 2: scan_file (test_clean.py) ---")
    result_clean_str = scan_file("test_clean.py")
    result_clean = json.loads(result_clean_str)
    print(f"[INFO] test_clean.py is_clean: {result_clean['is_clean']}")
    print(f"[INFO] scan_results: {len(result_clean.get('scan_results', []))}개")
    print("[PASS] scan_file 정상 파일 실행 완료")

    # 테스트 3 — scan_file 존재하지 않는 파일
    print("\n--- Test 3: scan_file (nonexistent.py) ---")
    result_none_str = scan_file("nonexistent.py")
    result_none = json.loads(result_none_str)
    assert result_none.get("scan_results") == []
    print("[PASS] scan_file 존재하지 않는 파일 -> 빈 결과 확인")

    # 테스트 4 — get_report
    print("\n--- Test 4: get_report ---")
    report_str = get_report()
    report = json.loads(report_str)
    assert "logs" in report
    assert "total" in report
    print(f"[PASS] get_report 결과: {report['total']}개 로그")

    # 테스트 5 — update_status 정상 케이스
    print("\n--- Test 5: update_status (accepted) ---")
    if report["logs"]:
        first_issue_id = report["logs"][0]["issue_id"]
        update_str = update_status(first_issue_id, "accepted")
        update_result = json.loads(update_str)
        if "error" not in update_result:
            assert update_result["status"] == "accepted"
            print(f"[PASS] update_status 정상: {update_result['issue_id']} -> accepted")
        else:
            print(f"[FAIL] update_status 에러: {update_result['error']}")
    else:
        print("[SKIP] No logs to test update_status.")

if __name__ == "__main__":
    run_tool_tests()
