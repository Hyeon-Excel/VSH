import os
from .base_pipeline import BasePipeline
from .analysis_pipeline import AnalysisPipeline
from modules.scanner.mock_semgrep_scanner import MockSemgrepScanner as SemgrepScanner
from modules.scanner.treesitter_scanner import TreeSitterScanner
from modules.scanner.sbom_scanner import SBOMScanner
from modules.analyzer.analyzer_factory import AnalyzerFactory
from repository.knowledge_repo import MockKnowledgeRepo
from repository.fix_repo import MockFixRepo
from repository.log_repo import MockLogRepo

class PipelineFactory:
    """
    모든 의존성을 조립하여 파이프라인 인스턴스를 생성하는 팩토리 클래스.
    """

    @staticmethod
    def create() -> BasePipeline:
        """
        환경 변수를 기반으로 필요한 스캐너, 분석기, 레포지토리를 인스턴스화하고
        의존성이 주입된 AnalysisPipeline을 반환합니다.

        Returns:
            BasePipeline: 조립이 완료된 파이프라인 인스턴스
            
        Raises:
            ValueError: 지원하지 않는 LLM 제공자일 경우
        """
        # 1. Repository 인스턴스화 (싱글톤처럼 파이프라인 안에서 공유)
        knowledge_repo = MockKnowledgeRepo()
        fix_repo = MockFixRepo()
        log_repo = MockLogRepo()

        # 2. Scanner 인스턴스화
        scanners = [
            SemgrepScanner(knowledge_repo=knowledge_repo),
            TreeSitterScanner(knowledge_repo=knowledge_repo),
            SBOMScanner()
        ]

        # 3. Analyzer 인스턴스화 (LLM_PROVIDER에 따라 분기)
        provider = os.getenv("LLM_PROVIDER", "gemini").lower()
        if provider == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
        elif provider == "claude":
            api_key = os.getenv("ANTHROPIC_API_KEY")
        else:
            raise ValueError(f"지원하지 않는 provider: {provider}")

        if not api_key:
            raise ValueError(f"{provider.upper()}_API_KEY가 .env에 설정되지 않았습니다.")
        
        analyzer = AnalyzerFactory.create(provider, api_key)

        # 4. 파이프라인 조립 및 반환
        pipeline = AnalysisPipeline(
            scanners=scanners,
            analyzer=analyzer,
            knowledge_repo=knowledge_repo,
            fix_repo=fix_repo,
            log_repo=log_repo
        )
        return pipeline
