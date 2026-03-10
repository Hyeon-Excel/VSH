from abc import ABC, abstractmethod

class BasePipeline(ABC):
    """
    모든 파이프라인의 기본이 되는 추상 클래스.
    """

    @abstractmethod
    def run(self, file_path: str) -> dict:
        """
        주어진 파일에 대해 파이프라인을 실행합니다.

        Args:
            file_path (str): 스캔 및 분석할 파일의 경로

        Returns:
            dict: 직렬화 가능한 형태의 파이프라인 실행 결과 (ScanResult, FixSuggestion 포함)
        """
        pass
