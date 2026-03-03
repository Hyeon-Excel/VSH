from pydantic import BaseModel

class FixSuggestion(BaseModel):
    """
    분석기(L2)가 제안하는 취약점 수정 정보.
    
    Attributes:
        issue_id (str): 취약점 ID
        original_code (str): 수정 전 원본 코드
        fixed_code (str): 수정 후 제안 코드
        description (str): 수정 내용에 대한 설명
    """
    issue_id: str
    original_code: str
    fixed_code: str
    description: str
