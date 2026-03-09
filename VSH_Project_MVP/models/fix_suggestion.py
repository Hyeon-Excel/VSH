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
    original_code: str
    fixed_code: str
    description: str
