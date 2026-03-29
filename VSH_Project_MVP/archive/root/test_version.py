from modules.scanner.sbom_scanner import SBOMScanner
import config

def test_version_logic():
    # 1. 임시 테스트용 requirements.txt 생성
    with open("requirements.txt", "w", encoding="utf-8") as f:
        f.write("requests==2.9.0\n")
        f.write("flask==2.10.0\n")

    # 2. config.py 조작 (테스트 환경)
    config.VULNERABLE_PACKAGES["requests"] = {"vulnerable_below": "2.10.0", "cve": "CVE-TEST"}
    config.VULNERABLE_PACKAGES["flask"] = {"vulnerable_below": "2.9.0", "cve": "CVE-TEST"}

    # 3. 스캐너 실행
    scanner = SBOMScanner()
    result = scanner.scan("dummy.py")
    
    print("=== Version Comparison Test ===")
    print("Vulnerable below thresholds:")
    print(" - requests < 2.10.0")
    print(" - flask    < 2.9.0")
    print("Requirements installed:")
    print(" - requests==2.9.0 (Expected: VULNERABLE)")
    print(" - flask==2.10.0   (Expected: SAFE)")
    print("-" * 30)

    # 4. 검증 결과 확인
    findings = result.findings
    print(f"Total findings: {len(findings)}")
    
    found_requests = False
    for f in findings:
        print(f"Detected: {f.code_snippet}")
        if "requests" in f.code_snippet:
            found_requests = True
            
    if found_requests and len(findings) == 1:
        print("[SUCCESS] 'requests==2.9.0' correctly detected as < 2.10.0")
        print("[SUCCESS] 'flask==2.10.0' correctly ignored as >= 2.9.0")
        print("          (packaging.version logic is working perfectly!)")
    else:
        print("[FAIL] Version logic failed.")

if __name__ == "__main__":
    test_version_logic()
