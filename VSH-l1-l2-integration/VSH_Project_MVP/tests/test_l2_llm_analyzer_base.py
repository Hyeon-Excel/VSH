from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from layer2.analyzer.base_llm_analyzer import BaseLlmAnalyzer


class FakeLlmAnalyzer(BaseLlmAnalyzer):
    provider_label = "FakeLLM"

    def __init__(self, response_text: str):
        super().__init__(api_key="test-key")
        self._response_text = response_text

    def _generate_response_text(self, prompt: str) -> str:
        return self._response_text


def test_base_llm_analyzer_builds_fix_suggestion_from_common_flow():
    analyzer = FakeLlmAnalyzer(
        """```json
        [
          {
            "finding_id": "finding-1",
            "file_path": "tests/sample.py",
            "cwe_id": "CWE-89",
            "line_number": 7,
            "is_real_threat": true,
            "reachability": "User input reaches the sink.",
            "kisa_reference": "KISA DB-01",
            "original_code": "cursor.execute(query % user_input)",
            "fixed_code": "cursor.execute(query, (user_input,))",
            "description": "Use parameter binding."
          }
        ]
        ```"""
    )
    scan_result = ScanResult(
        file_path="tests/sample.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="tests/sample.py",
                cwe_id="CWE-89",
                severity="HIGH",
                line_number=7,
                code_snippet="cursor.execute(query % user_input)",
            )
        ],
    )
    evidence_map = {
        "tests/sample.py_CWE-89_7": {
            "primary_reference": "KISA DB-01",
            "evidence_refs": ["CWE-89", "KISA DB-01"],
            "evidence_summary": "SQL Injection evidence",
            "retrieval_backend": "static_only",
            "chroma_status": "MISSING_DEPENDENCY",
            "chroma_summary": "disabled",
            "chroma_hits": 0,
        }
    }

    suggestions = analyzer.analyze(scan_result, knowledge=[], fix_hints=[], evidence_map=evidence_map)

    assert len(suggestions) == 1
    assert suggestions[0].issue_id == "tests/sample.py_CWE-89_7"
    assert suggestions[0].kisa_reference == "KISA DB-01"
    assert suggestions[0].decision_status == "confirmed"
    assert suggestions[0].confidence_score > 0
    assert suggestions[0].confidence_reason


def test_base_llm_analyzer_sets_last_error_on_invalid_json():
    analyzer = FakeLlmAnalyzer("not-json")
    scan_result = ScanResult(
        file_path="tests/sample.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="tests/sample.py",
                cwe_id="CWE-89",
                severity="HIGH",
                line_number=7,
                code_snippet="cursor.execute(query % user_input)",
            )
        ],
    )

    suggestions = analyzer.analyze(scan_result, knowledge=[], fix_hints=[], evidence_map={})

    assert suggestions == []
    assert analyzer.last_error
    assert "JSON parsing failed" in analyzer.last_error
