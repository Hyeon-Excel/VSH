from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class L2Metadata(BaseModel):
    """
    L2 내부 운영에만 필요한 메타데이터 블록.

    공통 스키마 밖의 retrieval / verification / confidence / patch / trace 정보는
    이 블록 안에 모아 두고, 다른 계층은 필요 시 metadata.l2만 참고한다.
    """

    reachability_note: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    evidence_summary: str | None = None
    retrieval_backend: str | None = None
    chroma_status: str | None = None
    chroma_summary: str | None = None
    chroma_hits: int = Field(default=0, ge=0)
    registry_status: str | None = None
    registry_summary: str | None = None
    osv_status: str | None = None
    osv_summary: str | None = None
    verification_summary: str | None = None
    decision_status: str | None = None
    confidence_score: int = Field(default=0, ge=0, le=100)
    confidence_reason: str | None = None
    patch_status: str | None = None
    patch_summary: str | None = None
    patch_diff: str | None = None
    processing_trace: list[str] = Field(default_factory=list)
    processing_summary: str | None = None
    category: str | None = None
    remediation_kind: str | None = None
    target_ref: str | None = None


class FixSuggestionMetadata(BaseModel):
    l2: L2Metadata = Field(default_factory=L2Metadata)


class FixSuggestion(BaseModel):
    """
    분석기(L2)가 제안하는 취약점 수정 정보.

    직렬화되는 공식 출력은 공통 스키마에 직접 대응되는 필드와 metadata.l2 블록만 사용한다.
    단, 기존 코드 경로가 한 번에 깨지지 않도록 issue_id, kisa_reference, retrieval_backend
    같은 예전 이름은 property로 하위호환만 제공한다.
    """

    vuln_id: str
    file_path: str | None = None
    cwe_id: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    reachability_status: str | None = None
    reachability_confidence: str | None = None
    kisa_ref: str | None = None
    evidence: str | None = None
    status: str = "pending"
    action_at: str | None = None
    original_code: str
    fixed_code: str
    description: str
    fix_suggestion: str | None = None
    metadata: FixSuggestionMetadata = Field(default_factory=FixSuggestionMetadata)

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_input(cls, data):
        if not isinstance(data, dict):
            return data

        normalized = dict(data)
        if not normalized.get("vuln_id"):
            normalized["vuln_id"] = normalized.get("issue_id")
        if not normalized.get("kisa_ref"):
            normalized["kisa_ref"] = normalized.get("kisa_reference")
        if not normalized.get("evidence"):
            normalized["evidence"] = normalized.get("original_code")
        if not normalized.get("fix_suggestion"):
            normalized["fix_suggestion"] = normalized.get("description") or normalized.get("fixed_code")

        metadata = normalized.get("metadata")
        if isinstance(metadata, FixSuggestionMetadata):
            metadata = metadata.model_dump()
        elif isinstance(metadata, BaseModel):
            metadata = metadata.model_dump()
        metadata = dict(metadata or {})

        l2 = metadata.get("l2")
        if isinstance(l2, L2Metadata):
            l2 = l2.model_dump()
        elif isinstance(l2, BaseModel):
            l2 = l2.model_dump()
        l2 = dict(l2 or {})

        legacy_to_l2 = {
            "reachability": "reachability_note",
            "evidence_refs": "evidence_refs",
            "evidence_summary": "evidence_summary",
            "retrieval_backend": "retrieval_backend",
            "chroma_status": "chroma_status",
            "chroma_summary": "chroma_summary",
            "chroma_hits": "chroma_hits",
            "registry_status": "registry_status",
            "registry_summary": "registry_summary",
            "osv_status": "osv_status",
            "osv_summary": "osv_summary",
            "verification_summary": "verification_summary",
            "decision_status": "decision_status",
            "confidence_score": "confidence_score",
            "confidence_reason": "confidence_reason",
            "patch_status": "patch_status",
            "patch_summary": "patch_summary",
            "patch_diff": "patch_diff",
            "processing_trace": "processing_trace",
            "processing_summary": "processing_summary",
            "category": "category",
            "remediation_kind": "remediation_kind",
            "target_ref": "target_ref",
        }
        for legacy_key, l2_key in legacy_to_l2.items():
            if l2.get(l2_key) in (None, "", [], 0) and normalized.get(legacy_key) not in (None, "", []):
                l2[l2_key] = normalized[legacy_key]

        metadata["l2"] = l2
        normalized["metadata"] = metadata
        return normalized

    @model_validator(mode="after")
    def sync_common_schema_and_metadata(self) -> "FixSuggestion":
        # 공통 스키마 필드 기본값 보정
        if not self.evidence:
            self.evidence = self.original_code
        if not self.fix_suggestion:
            self.fix_suggestion = self.description or self.fixed_code
        if not self.description:
            self.description = self.fix_suggestion or ""
        if not self.original_code:
            self.original_code = self.evidence or ""
        if not self.reachability_status:
            self.reachability_status = self._normalize_reachability(self.metadata.l2.reachability_note)
        if not self.reachability_confidence:
            self.reachability_confidence = self._confidence_band(self.metadata.l2.confidence_score)

        return self

    @property
    def issue_id(self) -> str:
        return self.vuln_id

    @property
    def kisa_reference(self) -> str | None:
        return self.kisa_ref

    @property
    def reachability(self) -> str | None:
        return self.metadata.l2.reachability_note

    @property
    def evidence_refs(self) -> list[str]:
        return self.metadata.l2.evidence_refs

    @property
    def evidence_summary(self) -> str | None:
        return self.metadata.l2.evidence_summary

    @property
    def retrieval_backend(self) -> str | None:
        return self.metadata.l2.retrieval_backend

    @property
    def chroma_status(self) -> str | None:
        return self.metadata.l2.chroma_status

    @property
    def chroma_summary(self) -> str | None:
        return self.metadata.l2.chroma_summary

    @property
    def chroma_hits(self) -> int:
        return self.metadata.l2.chroma_hits

    @property
    def registry_status(self) -> str | None:
        return self.metadata.l2.registry_status

    @property
    def registry_summary(self) -> str | None:
        return self.metadata.l2.registry_summary

    @property
    def osv_status(self) -> str | None:
        return self.metadata.l2.osv_status

    @property
    def osv_summary(self) -> str | None:
        return self.metadata.l2.osv_summary

    @property
    def verification_summary(self) -> str | None:
        return self.metadata.l2.verification_summary

    @property
    def decision_status(self) -> str | None:
        return self.metadata.l2.decision_status

    @property
    def confidence_score(self) -> int:
        return self.metadata.l2.confidence_score

    @property
    def confidence_reason(self) -> str | None:
        return self.metadata.l2.confidence_reason

    @property
    def patch_status(self) -> str | None:
        return self.metadata.l2.patch_status

    @property
    def patch_summary(self) -> str | None:
        return self.metadata.l2.patch_summary

    @property
    def patch_diff(self) -> str | None:
        return self.metadata.l2.patch_diff

    @property
    def processing_trace(self) -> list[str]:
        return self.metadata.l2.processing_trace

    @property
    def processing_summary(self) -> str | None:
        return self.metadata.l2.processing_summary

    @property
    def category(self) -> str | None:
        return self.metadata.l2.category

    @property
    def remediation_kind(self) -> str | None:
        return self.metadata.l2.remediation_kind

    @property
    def target_ref(self) -> str | None:
        return self.metadata.l2.target_ref

    @staticmethod
    def _normalize_reachability(reachability: str | None) -> str | None:
        if not reachability:
            return None
        lowered = reachability.lower()
        if "unreachable" in lowered:
            return "unreachable"
        if "reachable" in lowered or "reachability=yes" in lowered:
            return "reachable"
        if "unknown" in lowered:
            return "unknown"
        return None

    @staticmethod
    def _confidence_band(score: int) -> str | None:
        if score >= 85:
            return "high"
        if score >= 60:
            return "medium"
        if score > 0:
            return "low"
        return None
