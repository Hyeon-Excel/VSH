from typing import Optional
from pydantic import BaseModel


class FixSuggestion(BaseModel):
    """
    분석기(L2)가 제안하는 취약점 수정 정보.
    VulnRecord 공통 스키마 연동에 필요한 필드를 포함합니다.
    """
    issue_id: str
    original_code: str
    fixed_code: str
    description: str
    # VulnRecord 공통 스키마 연동 필드
    kisa_ref: str = ""               # null 비허용 (LLM 미응답 시 빈 문자열)
    fss_ref: Optional[str] = None    # null 허용, 빈 문자열 금지
    owasp_ref: Optional[str] = None
    reachability: bool = False
    cve_id: Optional[str] = None
    cvss_score: float = 0.0
