from abc import ABC, abstractmethod

class LLMAdapter(ABC):
    """SonarQube 규칙 ID를 CWE ID로 분류하는 LLM 어댑터 추상 클래스"""
    
    @abstractmethod
    async def classify_cwe(self, rule_id: str, issue_message: str) -> str:
        """
        입력: rule_id (SonarQube 규칙 ID), issue_message (이슈 메시지)
        반환: 'CWE-숫자' 형태 문자열
        실패 시: 'CWE-UNKNOWN' 반환 (예외 raise 금지)
        """
        pass