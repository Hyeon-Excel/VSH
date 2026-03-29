from __future__ import annotations

from layer2.reasoning.context_extractor import extract_finding_context
from layer2.reasoning.models import validate_reasoning_result
from layer2.reasoning.providers.base import ReasoningProvider
from layer2.reasoning.providers.mock_provider import MockReasoningProvider
from models.common_schema import VulnRecord


class L2ReasoningPipeline:
    def __init__(self, provider: ReasoningProvider | None = None):
        self.provider = provider or MockReasoningProvider()

    def run(self, vuln_records: list[VulnRecord]) -> list[dict]:
        results: list[dict] = []
        for vuln in vuln_records:
            context = extract_finding_context(vuln)
            raw = self.provider.reason(vuln.model_dump(), context)
            validated = validate_reasoning_result(raw)
            results.append(validated.to_dict())
        return results
