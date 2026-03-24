from unittest.mock import patch
from l3.providers.poc.template_registry import TemplateRegistry

def test_load_existing_cwes():
    """테스트 1: FILE_MAP에 있는 CWE-89, CWE-79, CWE-78 각각 1개 이상의 페이로드를 반환하는지 검증한다."""
    for cwe in ["CWE-89", "CWE-79", "CWE-78"]:
        result = TemplateRegistry.load(cwe)
        assert len(result) > 0, f"{cwe} should return at least 1 payload"

def test_load_nonexistent_cwe():
    """테스트 2: FILE_MAP에 없는 CWE-999는 [] 를 반환하는지 검증한다."""
    result = TemplateRegistry.load("CWE-999")
    assert result == []

def test_load_nonexistent_file():
    """테스트 3: 파일이 존재하지 않는 경로를 시뮬레이션한다."""
    with patch.object(
        TemplateRegistry,
        'FILE_MAP',
        {"CWE-89": "nonexistent/path.txt"}
    ):
        result = TemplateRegistry.load("CWE-89")
        assert result == []

def test_load_max_payloads():
    """테스트 4: max_payloads=5 로 호출하면 결과가 5개 이하인지 검증한다."""
    result = TemplateRegistry.load("CWE-89", max_payloads=5)
    assert len(result) <= 5
    assert len(result) > 0

def test_load_filtering():
    """테스트 5: 반환된 페이로드 목록을 순회하며 빈 문자열과 '#' 시작이 없는지 검증한다."""
    for cwe in ["CWE-89", "CWE-79", "CWE-78"]:
        result = TemplateRegistry.load(cwe)
        for payload in result:
            assert payload != "", f"Empty string found in {cwe} payloads"
            assert not payload.startswith("#"), f"Comment string found in {cwe} payloads: {payload}"
