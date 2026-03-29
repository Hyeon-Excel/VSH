import os
from dotenv import load_dotenv
from pipeline import PipelineFactory, AnalysisPipeline
from models import Vulnerability

load_dotenv()

def test_pipeline():
    print("=== Pipeline Tests ===")
    try:
        pipeline = PipelineFactory.create()
        print("[PASS] PipelineFactory 생성 확인")
    except Exception as e:
        print(f"[FAIL] PipelineFactory 생성 실패: {e}")
        return

    # 테스트 1 — 취약 파일 전체 파이프라인 실행
    print("\n--- Test 1: test_vuln.py ---")
    try:
        result = pipeline.run("test_vuln.py")
        assert isinstance(result, dict), "반환 타입이 dict여야 함"
        assert "file_path" in result, "file_path 키 없음"
        assert "scan_results" in result, "scan_results 키 없음"
        assert "fix_suggestions" in result, "fix_suggestions 키 없음"
        assert "is_clean" in result, "is_clean 키 없음"
        assert isinstance(result['scan_results'], list), "scan_results는 list여야 함"
        assert isinstance(result['fix_suggestions'], list), "fix_suggestions는 list여야 함"
        if result['scan_results']:
            assert isinstance(result['scan_results'][0], dict), "scan_results 항목은 dict여야 함"
        if result['fix_suggestions']:
            assert isinstance(result['fix_suggestions'][0], dict), "fix_suggestions 항목은 dict여야 함"
        print(f"[PASS] 파이프라인 실행 완료")
        print(f"  scan_results: {len(result['scan_results'])}개")
        print(f"  fix_suggestions: {len(result['fix_suggestions'])}개")
        print(f"  is_clean: {result['is_clean']}")
        
        # 테스트 2 — LogRepo 저장 확인 (테스트 1 성공 시에만)
        print("\n--- Test 2: LogRepo Check ---")
        log_repo = pipeline.log_repo
        if result.get('fix_suggestions'):
            for s in result['fix_suggestions']:
                log_entry = log_repo.find_by_id(s['issue_id'])
                assert log_entry is not None, f"LogRepo에 저장되지 않음: {s['issue_id']}"
                assert log_entry['status'] == "pending", "초기 status는 pending이어야 함"
                assert 'line_number' in log_entry, "log_entry에 line_number가 없음"
                assert 'code_snippet' in log_entry, "log_entry에 code_snippet이 없음"
                print(f"[PASS] LogRepo 저장 확인: {log_entry['issue_id']}")
        else:
             print("[SKIP] No fix suggestions generated, skipping LogRepo check.")
    except Exception as e:
        print(f"[FAIL] Test 1/2 파이프라인 실행/로그 확인 실패: {e}")

    # 테스트 3 — 정상 파일 실행
    print("\n--- Test 3: test_clean.py ---")
    try:
        result_clean = pipeline.run("test_clean.py")
        assert result_clean['is_clean'] is True, "정상 파일은 is_clean이 True여야 함"
        print("[PASS] 정상 파일 -> is_clean: True 정상 반환")
    except Exception as e:
         print(f"[FAIL] Test 3 정상 파일 실행 실패: {e}")

    # 테스트 4 — 존재하지 않는 파일
    print("\n--- Test 4: nonexistent.py ---")
    try:
        result_none = pipeline.run("nonexistent.py")
        assert isinstance(result_none, dict), "반환 타입이 dict여야 함"
        assert result_none['scan_results'] == [], "파일 없으면 scan_results가 빈 리스트여야 함"
        assert result_none['fix_suggestions'] == [], "파일 없으면 fix_suggestions가 빈 리스트여야 함"
        print("[PASS] 존재하지 않는 파일 -> 빈 결과 dict 정상 반환")
    except Exception as e:
        print(f"[FAIL] Test 4 존재하지 않는 파일 실행 실패: {e}")

    # 테스트 5 — _deduplicate() 정적 메서드 직접 검증
    print("\n--- Test 5: _deduplicate() ---")
    try:
        v1 = Vulnerability(
            cwe_id="CWE-78", severity="HIGH",
            line_number=5,
            code_snippet="subprocess.run(user_input, shell=True)"
        )
        v2 = Vulnerability(
            cwe_id="CWE-78", severity="HIGH",
            line_number=5,
            code_snippet="subprocess.run(user_input, shell=True)"
        )
        v3 = Vulnerability(
            cwe_id="CWE-89", severity="HIGH",
            line_number=12,
            code_snippet="SELECT * FROM users"
        )
        deduped = AnalysisPipeline._deduplicate([v1, v2, v3])
        assert len(deduped) == 2, f"중복 제거 후 2개여야 하는데 {len(deduped)}개"
        print(f"[PASS] _deduplicate() 정상 동작: 3개 -> {len(deduped)}개")
    except Exception as e:
        print(f"[FAIL] Test 5 중복 제거 동작 실패: {e}")

if __name__ == "__main__":
    test_pipeline()
