import requests
import json

BASE_URL = "http://localhost:3000"

def run_tests():
    print("=== Dashboard API Tests ===")

    # 테스트 1 — GET / (HTML 반환)
    try:
        response = requests.get(f"{BASE_URL}/")
        assert response.status_code == 200, f"HTML 반환 실패: {response.status_code}"
        assert "VSH" in response.text, "HTML에 VSH 텍스트 없음"
        print("[PASS] GET / -> HTML 정상 반환")
    except Exception as e:
        print(f"[FAIL] GET / 실패: {e}")
        return

    # 테스트 2 — GET /api/logs
    try:
        response = requests.get(f"{BASE_URL}/api/logs")
        assert response.status_code == 200, f"로그 조회 실패: {response.status_code}"
        data = response.json()
        assert "logs" in data, "logs 키 없음"
        assert "total" in data, "total 키 없음"
        assert data["total"] == len(data["logs"]), "total이 logs 개수와 불일치"
        print(f"[PASS] GET /api/logs -> {data['total']}개 로그 조회")
    except Exception as e:
        print(f"[FAIL] GET /api/logs 실패: {e}")
        return

    # 테스트를 위한 초기화: log.json이 비어있을 수 있으므로 pipeline run을 통해 하나 생성
    if data["total"] == 0:
        print("[INFO] 로그가 비어있어 MCP 툴(또는 파이프라인)을 호출하여 테스트 데이터를 생성합니다.")
        from tools.server import scan_file
        scan_file("test_vuln.py")
        response = requests.get(f"{BASE_URL}/api/logs")
        data = response.json()
        print(f"[INFO] 데이터 생성 후 로그 개수: {data['total']}")

    # 테스트 3 — POST accept
    try:
        pending_logs = [l for l in data["logs"] if l["status"] == "pending"]
        
        if pending_logs:
            issue_id = pending_logs[0]["issue_id"]
            response = requests.post(f"{BASE_URL}/api/logs/{issue_id}/accept")
            assert response.status_code == 200, f"accept 실패: {response.status_code}"
            result = response.json()
            assert result["status"] == "accepted", "status가 accepted로 업데이트되지 않음"
            assert "fixed_code" in result, "응답에 fixed_code 없음"
            assert result["fixed_code"] != "", "fixed_code가 비어있음"
            print(f"[PASS] POST accept -> {result['issue_id']} accepted")
            print(f"       fixed_code 포함 확인: {result['fixed_code'][:50]}...")
        else:
            print("[SKIP] POST accept: pending 상태 로그가 없음.")
    except Exception as e:
        print(f"[FAIL] POST accept 실패: {e}")

    # 테스트 4 — POST dismiss
    try:
        # data 새로 갱신
        response = requests.get(f"{BASE_URL}/api/logs")
        data = response.json()
        pending_logs = [l for l in data["logs"] if l["status"] == "pending"]
        
        if pending_logs:
            issue_id = pending_logs[0]["issue_id"]
            response = requests.post(f"{BASE_URL}/api/logs/{issue_id}/dismiss")
            assert response.status_code == 200, f"dismiss 실패: {response.status_code}"
            result = response.json()
            assert result["status"] == "dismissed", "status가 dismissed로 업데이트되지 않음"
            print(f"[PASS] POST dismiss -> {result['issue_id']} dismissed")
        else:
             print("[SKIP] POST dismiss: pending 상태 로그가 없음.")
    except Exception as e:
        print(f"[FAIL] POST dismiss 실패: {e}")

    # 테스트 5 — 존재하지 않는 issue_id -> 404
    try:
        response = requests.post(f"{BASE_URL}/api/logs/nonexistent_id/accept")
        assert response.status_code == 404, f"404 반환 실패: {response.status_code}"
        print("[PASS] 존재하지 않는 issue_id -> 404 정상 반환")
    except Exception as e:
         print(f"[FAIL] 존재하지 않는 issue_id 처리 실패: {e}")

    print("모든 테스트 완료")

if __name__ == "__main__":
    run_tests()
