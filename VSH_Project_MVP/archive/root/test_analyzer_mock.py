import os
import unittest
import json
import re
from unittest.mock import MagicMock, patch
from dotenv import load_dotenv
from modules import LLMAnalyzer
from repository import MockKnowledgeRepo, MockFixRepo
from models import ScanResult, Vulnerability, FixSuggestion

load_dotenv()

# ANTHROPIC_API_KEY가 없으면 더미 키로 초기화 (로직 테스트용)
API_KEY = os.getenv("ANTHROPIC_API_KEY", "dummy_key")

def run_analyzer_tests():
    print("=== Analyzer Tests ===")
    knowledge_repo = MockKnowledgeRepo()
    fix_repo = MockFixRepo()
    knowledge = knowledge_repo.find_all()
    fix_hints = fix_repo.find_all()

    analyzer = LLMAnalyzer(api_key=API_KEY)

    # 테스트 3 — 빈 findings → 빈 리스트 반환
    empty_result = ScanResult(
        file_path="test_clean.py",
        language="python",
        findings=[]
    )
    suggestions = analyzer.analyze(empty_result, knowledge, fix_hints)
    assert suggestions == [], "빈 findings는 빈 리스트 반환해야 함"
    print("[PASS] 빈 findings -> 빈 리스트 정상 반환")

    # 테스트 4 — _parse_response() 직접 검증
    print("\n=== _parse_response() Tests ===")
    raw_valid = '[{"cwe_id":"CWE-78","line_number":5,' \
                '"is_real_threat":true,"reachability":"test",' \
                '"kisa_reference":"KISA 1항",' \
                '"original_code":"subprocess.run(cmd,shell=True)",' \
                '"fixed_code":"subprocess.run(cmd.split())",' \
                '"description":"설명"}]'
    parsed = analyzer._parse_response(raw_valid)
    assert isinstance(parsed, list), "_parse_response가 list를 반환해야 함"
    assert len(parsed) == 1, "파싱 결과가 1개여야 함"
    print("[PASS] _parse_response() 정상 JSON 파싱 확인")

    # Markdown 코드 블록 포함 케이스
    raw_markdown = '```json\n[{"cwe_id":"CWE-78","line_number":5,"is_real_threat":true}]\n```'
    parsed_md = analyzer._parse_response(raw_markdown)
    assert len(parsed_md) == 1, "마크다운 코드 블록 파싱 실패"
    print("[PASS] _parse_response() 마크다운 코드 블록 파싱 확인")

    raw_invalid = "이건 JSON이 아님"
    parsed_fail = analyzer._parse_response(raw_invalid)
    assert parsed_fail == [], "파싱 실패 시 빈 리스트 반환해야 함"
    print("[PASS] _parse_response() 파싱 실패 -> 빈 리스트 정상 반환")

    # API 호출 부분은 모의(Mock)를 사용하여 로직 검증
    print("\n=== Mock API Call Tests ===")
    
    # Mock Response를 위한 텍스트 정의
    mock_response_text = '[{"cwe_id":"CWE-78","line_number":5,"is_real_threat":true,"original_code":"subprocess.run(cmd,shell=True)","fixed_code":"subprocess.run(cmd.split())","description":"Fixed vulnerability"}]'

    with patch('anthropic.Anthropic') as mock_anthropic:
        # Anthropic 인스턴스 모의
        mock_client = mock_anthropic.return_value
        analyzer.client = mock_client
        
        # messages.create 호출 시 반환값 구성
        mock_msg = MagicMock()
        mock_msg.content = [MagicMock(text=mock_response_text)]
        mock_client.messages.create.return_value = mock_msg

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
        
        suggestions = analyzer.analyze(scan_result, knowledge, fix_hints)
        
        assert len(suggestions) == 1, "Mock API 분석 결과 생성 실패"
        s = suggestions[0]
        assert s.issue_id == "test_vuln.py_CWE-78_5", f"issue_id 불일치: {s.issue_id}"
        assert s.fixed_code == "subprocess.run(cmd.split())"
        print(f"[PASS] Mock API 호출 결과 처리 및 issue_id 생성 확인: {s.issue_id}")

        # 복수 취약점 API 1회 호출 검증
        mock_client.messages.create.reset_mock()
        findings_multi = [
            Vulnerability(cwe_id="CWE-78", severity="HIGH", line_number=5, code_snippet="..."),
            Vulnerability(cwe_id="CWE-89", severity="HIGH", line_number=12, code_snippet="...")
        ]
        scan_result_multi = ScanResult(file_path="test_vuln.py", language="python", findings=findings_multi)
        
        analyzer.analyze(scan_result_multi, knowledge, fix_hints)
        # create()가 한 번 호출되었는지 확인
        assert mock_client.messages.create.call_count == 1
        print(f"[PASS] 복수 취약점 API 호출 횟수 확인 (1회 통합 호출)")

if __name__ == "__main__":
    run_analyzer_tests()
