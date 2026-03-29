from modules import SemgrepScanner, TreeSitterScanner, SBOMScanner
from repository import MockKnowledgeRepo

def run_tests():
    print("=== Scanner Tests ===")
    knowledge_repo = MockKnowledgeRepo()

    # 테스트 1 — SemgrepScanner 취약 파일 탐지
    semgrep_scanner = SemgrepScanner(knowledge_repo=knowledge_repo)
    result = semgrep_scanner.scan("test_vuln.py")
    assert not result.is_clean(), "취약 파일이 clean으로 판정되면 안 됨"
    assert result.language == "python", "language 불일치"
    assert len(result.findings) > 0, "findings가 비어있으면 안 됨"
    print(f"[PASS] SemgrepScanner 탐지 결과: {len(result.findings)}개")
    for f in result.findings:
        print(f"  - {f.cwe_id} / {f.severity} / line {f.line_number}")

    # 테스트 2 — SemgrepScanner 정상 파일 → clean
    result = semgrep_scanner.scan("test_clean.py")
    assert result.is_clean(), "정상 파일이 취약으로 판정되면 안 됨"
    print("[PASS] SemgrepScanner 정상 파일 -> clean 정상 반환")

    # 테스트 3 — SemgrepScanner 파일 없음 → 빈 ScanResult
    result = semgrep_scanner.scan("nonexistent.py")
    assert result.is_clean(), "파일 없으면 빈 ScanResult 반환해야 함"
    print("[PASS] SemgrepScanner 파일 없음 -> 빈 ScanResult 정상 반환")

    # 테스트 4 — TreeSitterScanner 취약 파일 탐지
    ts_scanner = TreeSitterScanner(knowledge_repo=knowledge_repo)
    result = ts_scanner.scan("test_vuln.py")
    assert result.language == "python", "language 불일치"
    print(f"[PASS] TreeSitterScanner 탐지 결과: {len(result.findings)}개")
    for f in result.findings:
        print(f"  - {f.cwe_id} / {f.severity} / line {f.line_number}")

    # 테스트 5 — TreeSitterScanner 지원하지 않는 언어
    try:
        ts_scanner.scan("test.js")
    except ValueError as e:
        print(f"[PASS] ValueError 정상 발생: {e}")

    # 테스트 6 — SBOMScanner 취약 패키지 탐지
    sbom_scanner = SBOMScanner()
    result = sbom_scanner.scan("test_vuln.py")
    assert not result.is_clean(), "취약 패키지가 있는데 clean으로 판정되면 안 됨"
    assert len(result.findings) > 0, "취약 패키지가 findings에 없으면 안 됨"
    print(f"[PASS] SBOMScanner 탐지 결과: {len(result.findings)}개")
    for f in result.findings:
        print(f"  - {f.cwe_id} / {f.severity} / line {f.line_number}")

    # 테스트 7 — supported_languages() 확인
    assert semgrep_scanner.supported_languages() == ["python"]
    assert ts_scanner.supported_languages() == ["python"]
    assert sbom_scanner.supported_languages() == ["python"]
    print("[PASS] supported_languages() 모두 ['python'] 정상 반환")

    # 테스트 8 — find_all() 동작 확인
    all_knowledge = knowledge_repo.find_all()
    assert isinstance(all_knowledge, list), "find_all()은 list를 반환해야 함"
    assert len(all_knowledge) > 0, "knowledge.json이 비어있으면 안 됨"
    print(f"[PASS] find_all() 정상 동작: {len(all_knowledge)}개 항목")

if __name__ == "__main__":
    run_tests()
