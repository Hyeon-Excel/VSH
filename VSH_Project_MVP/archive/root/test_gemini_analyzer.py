import os
import json
from dotenv import load_dotenv
from modules import GeminiAnalyzer, AnalyzerFactory
from repository import MockKnowledgeRepo, MockFixRepo
from models import ScanResult, Vulnerability

load_dotenv()

def run_gemini_tests():
    print("=== Gemini Analyzer & Factory Tests ===")
    
    knowledge_repo = MockKnowledgeRepo()
    fix_repo = MockFixRepo()
    knowledge = knowledge_repo.find_all()
    fix_hints = fix_repo.find_all()

    # 테스트 1 — AnalyzerFactory로 GeminiAnalyzer 생성
    provider = os.getenv("LLM_PROVIDER", "gemini")
    api_key = os.getenv("GEMINI_API_KEY")
    
    print(f"Current Provider: {provider}")
    
    try:
        analyzer = AnalyzerFactory.create(provider, api_key if api_key else "dummy_key")
        assert isinstance(analyzer, GeminiAnalyzer), "LLM_PROVIDER=gemini면 GeminiAnalyzer여야 함"
        print(f"[PASS] AnalyzerFactory 정상 생성: {type(analyzer).__name__}")
    except Exception as e:
        print(f"[FAIL] AnalyzerFactory 생성 실패: {e}")
        return

    # 테스트 4 — AnalyzerFactory 잘못된 provider
    try:
        AnalyzerFactory.create("invalid_provider", "key")
        print("[FAIL] ValueError NOT raised for invalid provider")
    except ValueError as e:
        print(f"[PASS] ValueError 정상 발생: {e}")

    # 테스트 3 — 빈 findings → 빈 리스트 반환
    empty_result = ScanResult(
        file_path="test_clean.py",
        language="python",
        findings=[]
    )
    suggestions = analyzer.analyze(empty_result, knowledge, fix_hints)
    assert suggestions == [], "빈 findings는 빈 리스트 반환해야 함"
    print("[PASS] 빈 findings -> 빈 리스트 정상 반환")

    # 테스트 2 — 실제 Gemini API 취약점 분석 (API 키가 있는 경우만)
    if not api_key or api_key == "your_gemini_api_key_here":
        print("\n[SKIP] GEMINI_API_KEY not set or is placeholder. Skipping real API test.")
    else:
        print("\n=== Real Gemini API Call Test ===")
        findings = [
            Vulnerability(
                cwe_id="CWE-78",
                severity="HIGH",
                line_number=5,
                code_snippet="subprocess.run(user_input, shell=True)"
            )
        ]
        scan_result = ScanResult(
            file_path="test_vuln.py",
            language="python",
            findings=findings
        )
        
        try:
            suggestions = analyzer.analyze(scan_result, knowledge, fix_hints)
            assert isinstance(suggestions, list), "반환 타입이 list여야 함"
            print(f"[PASS] Gemini API 분석 결과: {len(suggestions)}개 FixSuggestion 생성")
            if suggestions:
                for s in suggestions:
                    print(f"  issue_id: {s.issue_id}")
                    print(f"  fixed_code: {s.fixed_code}")
        except Exception as e:
            print(f"[FAIL] Gemini API 분석 중 오류 발생: {e}")

if __name__ == "__main__":
    run_gemini_tests()
