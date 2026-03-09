from pydantic import BaseModel, Field

class FixSuggestion(BaseModel):
    """
    분석기(L2)가 제안하는 취약점 수정 정보.
    
    Attributes:
        issue_id (str): 취약점 ID
        file_path (str | None): 수정 제안이 적용되어야 하는 실제 파일 경로
        cwe_id (str | None): 취약점 CWE ID
        line_number (int | None): 취약점 라인 번호
        reachability (str | None): 실제 위협 여부 판단 근거
        kisa_reference (str | None): 연관된 KISA 기준 또는 참조
        evidence_refs (list[str]): 근거 참조 목록
        evidence_summary (str | None): 근거 요약
        original_code (str): 수정 전 원본 코드
        fixed_code (str): 수정 후 제안 코드
        description (str): 수정 내용에 대한 설명
    """
    issue_id: str
    file_path: str | None = None
    cwe_id: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    reachability: str | None = None
    kisa_reference: str | None = None
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
    original_code: str
    fixed_code: str
    description: str
