from abc import ABC, abstractmethod
from typing import List, Dict
from models.scan_result import ScanResult
from models.fix_suggestion import FixSuggestion

class BaseScanner(ABC):
    """
    모든 스캐너의 기본이 되는 추상 클래스.
    """

    @abstractmethod
    def scan(self, file_path: str) -> ScanResult:
        """
        파일을 스캔하여 취약점을 탐지합니다.

        Args:
            file_path (str): 스캔할 파일의 경로

        Returns:
            ScanResult: 스캔 결과 (취약점 목록 포함)
        """
        pass

    @abstractmethod
    def supported_languages(self) -> List[str]:
        """
        이 스캐너가 지원하는 언어 목록을 반환합니다.

        Returns:
            List[str]: 지원하는 언어 문자열 목록 (예: ["python"])
        """
        pass

class BaseAnalyzer(ABC):
    """
    탐지된 취약점을 분석하고 수정 제안을 생성하는 추상 클래스.
    """

    @abstractmethod
    def analyze(self, 
                scan_result: ScanResult, 
                knowledge: List[Dict], 
                fix_hints: List[Dict],
                evidence_map: Dict[str, Dict] | None = None) -> List[FixSuggestion]:
        """
        L1 탐지 결과를 분석하여 실제 위협 여부를 판단하고 수정 제안을 생성합니다.

        Args:
            scan_result (ScanResult): L1 스캔 결과
            knowledge (List[Dict]): 전체 보안 지식 목록
            fix_hints (List[Dict]): 전체 수정 가이드 목록
            evidence_map (Dict[str, Dict] | None): finding별 retrieval 결과

        Returns:
            List[FixSuggestion]: 확정된 취약점에 대한 수정 제안 목록
            issue_id 외에도 cwe_id, line_number, reachability, kisa_reference,
            evidence_refs, evidence_summary
            같은 L2 메타데이터를 보존할 수 있습니다.
        """
        pass
