from __future__ import annotations

import os

from layer2.reasoning.context_extractor import extract_finding_context
from layer2.reasoning.models import validate_reasoning_result
from layer2.reasoning.providers import (
    MockReasoningProvider,
    GeminiReasoningProvider,
    OpenAIReasoningProvider,
)
from models.common_schema import VulnRecord


class L2ReasoningPipeline:
    def __init__(self, provider: str | None = None):
        provided = provider or os.environ.get("LLM_PROVIDER", "mock").lower()
        if provided == "openai":
            try:
                self.provider = OpenAIReasoningProvider()
            except Exception:
                self.provider = MockReasoningProvider()
        elif provided == "gemini":
            try:
                self.provider = GeminiReasoningProvider()
            except Exception:
                self.provider = MockReasoningProvider()
        else:
            self.provider = MockReasoningProvider()

    def run(self, vuln_records: list[VulnRecord]) -> list[dict]:
        results: list[dict] = []
        for vuln in vuln_records:
            context = extract_finding_context(vuln)
            raw = self.provider.reason(vuln.model_dump(), context)
            validated = validate_reasoning_result(raw)
            # map each record details
            record = validated.to_dict()
            record.update({
                "is_vulnerable": record["verdict"] in {"likely_vulnerable", "suspicious"},
                "target_line": context.get("target_line"),
                "analysis_context": context.get("context"),
            })
            results.append(record)
        return results
