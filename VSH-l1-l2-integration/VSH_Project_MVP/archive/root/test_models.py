from models.vulnerability import Vulnerability
from models.scan_result import ScanResult
from models.fix_suggestion import FixSuggestion

def test_models():
    print("=== Model Tests ===")

    # 테스트 1 — 정상 인스턴스 생성
    try:
        v = Vulnerability(cwe_id="CWE-78", severity="HIGH", line_number=4, code_snippet="subprocess.run(cmd, shell=True)")
        print(f"[PASS] Vulnerability created: {v}")
    except Exception as e:
        print(f"[FAIL] Vulnerability creation failed: {e}")

    try:
        f = FixSuggestion(issue_id="issue-001", original_code="subprocess.run(cmd, shell=True)", fixed_code="subprocess.run(['cmd'], shell=False)", description="shell=False로 변경")
        print(f"[PASS] FixSuggestion created: {f}")
    except Exception as e:
        print(f"[FAIL] FixSuggestion creation failed: {e}")

    s = None
    try:
        s = ScanResult(file_path="test.py", language="python", findings=[v])
        print(f"[PASS] ScanResult created: {s}")
    except Exception as e:
        print(f"[FAIL] ScanResult creation failed: {e}")

    # 테스트 2 — is_clean() 검증
    print("\n=== is_clean() Tests ===")
    if s and not s.is_clean():
        print("[PASS] s.is_clean() is False (Expected)")
    else:
        print(f"[FAIL] s.is_clean() returned True, expected False")

    try:
        s_clean = ScanResult(file_path="clean.py", language="python", findings=[])
        if s_clean.is_clean():
            print("[PASS] clean_result.is_clean() is True (Expected)")
        else:
            print(f"[FAIL] clean_result.is_clean() returned False, expected True")
    except Exception as e:
         print(f"[FAIL] clean_result creation failed: {e}")


    # 테스트 3 — severity 유효성 검사
    print("\n=== Severity Validation Test ===")
    try:
        Vulnerability(cwe_id="CWE-78", severity="INVALID", line_number=1, code_snippet="test")
        print("[FAIL] ValueError NOT raised for invalid severity")
    except ValueError as e:
        print(f"[PASS] ValueError raised correctly")
    except Exception as e:
        print(f"[FAIL] Unexpected exception raised: {type(e).__name__}: {e}")

if __name__ == "__main__":
    test_models()
