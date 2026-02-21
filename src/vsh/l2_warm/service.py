"""L2 orchestration service."""

from __future__ import annotations

from vsh.common.models import (
    L2EnrichFixRequest,
    L2EnrichFixResponse,
    VerificationSummary,
)
from vsh.l2_warm.rag.retriever import EvidenceRetriever
from vsh.l2_warm.verification.osv import OsvVerifier
from vsh.l2_warm.verification.registry import RegistryVerifier


class L2Service:
    def __init__(
        self,
        evidence_retriever: EvidenceRetriever | None = None,
        registry_verifier: RegistryVerifier | None = None,
        osv_verifier: OsvVerifier | None = None,
    ) -> None:
        self.evidence_retriever = evidence_retriever or EvidenceRetriever()
        self.registry_verifier = registry_verifier or RegistryVerifier()
        self.osv_verifier = osv_verifier or OsvVerifier()

    def enrich_fix(self, request: L2EnrichFixRequest) -> L2EnrichFixResponse:
        enriched = []
        for finding in request.findings:
            evidence = self.evidence_retriever.lookup(finding.kisa_key, finding.fsec_key)
            enriched.append(
                finding.model_copy(
                    update={
                        "evidence_refs": evidence,
                        "rationale": "Evidence enrichment will be implemented in Phase 2.",
                    }
                )
            )

        verification = VerificationSummary(
            registry=[],
            osv=[],
        )
        return L2EnrichFixResponse(
            enriched_findings=enriched,
            fix_patch="",
            verification=verification,
            errors=[],
        )
