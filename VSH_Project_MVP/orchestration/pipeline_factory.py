import os
from typing import List
from .base_pipeline import BasePipeline
from .analysis_pipeline import AnalysisPipeline
from layer1.scanner.mock_semgrep_scanner import MockSemgrepScanner as SemgrepScanner
from layer1.scanner.sbom_scanner import SBOMScanner
from layer2.analyzer.analyzer_factory import AnalyzerFactory
from layer2.patch_builder import PatchBuilder
from layer2.retriever.evidence_retriever import EvidenceRetriever
from layer2.verifier.registry_verifier import RegistryVerifier
from layer2.verifier.osv_verifier import OsvVerifier
from repository.knowledge_repo import MockKnowledgeRepo
from repository.fix_repo import MockFixRepo
from repository.log_repo import MockLogRepo

class PipelineFactory:
    """
    모든 의존성을 조립하여 파이프라인 인스턴스를 생성하는 팩토리 클래스.
    """

    @staticmethod
    def _create_scanners(knowledge_repo) -> List:
        # hyeonexcel 수정: layer2 기준 구조를 유지한 채 L1 donor 브랜치의 확장 scanner를
        # 선택적으로 붙일 수 있도록 mode 분기를 추가한다.
        l1_mode = os.getenv("L1_SCANNER_MODE", "classic").lower()
        if l1_mode in {"integrated", "vsh"}:
            from layer1.scanner import VSHL1Scanner

            return [VSHL1Scanner(knowledge_repo=knowledge_repo)]

        scanners = [SemgrepScanner(knowledge_repo=knowledge_repo)]

        try:
            from layer1.scanner.treesitter_scanner import TreeSitterScanner
        except ModuleNotFoundError as exc:
            print(f"[WARN] TreeSitterScanner unavailable: {exc}")
        else:
            scanners.append(TreeSitterScanner(knowledge_repo=knowledge_repo))

        scanners.append(SBOMScanner())
        return scanners

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
        scanners = PipelineFactory._create_scanners(knowledge_repo)

        # 3. Analyzer 인스턴스화 (LLM_PROVIDER에 따라 분기)
        provider = os.getenv("LLM_PROVIDER", "gemini").lower()
        if provider == "mock":
            api_key = ""
        elif provider == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
        elif provider == "claude":
            api_key = os.getenv("ANTHROPIC_API_KEY")
        else:
            raise ValueError(f"지원하지 않는 provider: {provider}")

        if provider != "mock" and not api_key:
            raise ValueError(
                f"{provider.upper()}_API_KEY가 .env에 설정되지 않았습니다. "
                "로컬 테스트만 필요하면 LLM_PROVIDER=mock 을 사용하세요."
            )
        
        analyzer = AnalyzerFactory.create(provider, api_key)

        # 4. 파이프라인 조립 및 반환
        pipeline = AnalysisPipeline(
            scanners=scanners,
            analyzer=analyzer,
            evidence_retriever=EvidenceRetriever(),
            registry_verifier=RegistryVerifier(),
            osv_verifier=OsvVerifier(),
            patch_builder=PatchBuilder(),
            knowledge_repo=knowledge_repo,
            fix_repo=fix_repo,
            log_repo=log_repo
        )
        return pipeline
