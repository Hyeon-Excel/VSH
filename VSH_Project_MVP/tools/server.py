import os
import json
from dotenv import load_dotenv
from fastmcp import FastMCP

# 1. 초기화 순서 준수: 환경변수 로드가 가장 먼저 수행되어야 함
load_dotenv()

# 2. Pipeline 생성 및 Repository 참조
from pipeline import PipelineFactory

# 초기화 실패 시 즉시 에러가 발생하여 서버 구동을 막음 (Fail-Fast)
pipeline = PipelineFactory.create()
log_repo = pipeline.log_repo

# 3. FastMCP 인스턴스 생성
mcp = FastMCP("VSH - Vibe Coding Secure Helper")

@mcp.tool()
def scan_file(file_path: str) -> str:
    """
    지정한 파일을 보안 스캔하고 분석 결과를 반환한다.
    
    Args:
        file_path (str): 스캔할 파일의 경로
        
    Returns:
        str: JSON 포맷의 분석 결과 문자열
    """
    if not pipeline:
        return json.dumps({"error": "Pipeline not initialized."}, ensure_ascii=False, indent=2)
    
    if not file_path:
        return json.dumps({"error": "file_path is required."}, ensure_ascii=False, indent=2)

    try:
        result = pipeline.run(file_path)
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False, indent=2)

@mcp.tool()
def get_report() -> str:
    """
    저장된 보안 진단 로그 전체를 조회한다.
    
    Returns:
        str: JSON 포맷의 통합 리포트 문자열
    """
    if not log_repo:
        return json.dumps({"error": "Repository not initialized."}, ensure_ascii=False, indent=2)

    try:
        logs = log_repo.find_all()
        report = {
            "logs": logs,
            "total": len(logs)
        }
        return json.dumps(report, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False, indent=2)

@mcp.tool()
def update_status(issue_id: str, status: str) -> str:
    """
    특정 취약점의 상태를 Accept 또는 Dismiss로 업데이트한다.
    
    Args:
        issue_id (str): 업데이트할 이슈의 고유 식별자
        status (str): "accepted" 또는 "dismissed"
        
    Returns:
        str: JSON 포맷의 업데이트 결과 문자열
    """
    if not log_repo:
        return json.dumps({"error": "Repository not initialized."}, ensure_ascii=False, indent=2)

    # 1. status 유효성 검사
    valid_statuses = {"accepted", "dismissed"}
    if status not in valid_statuses:
        return json.dumps({
            "error": "Invalid status. Must be 'accepted' or 'dismissed'."
        }, ensure_ascii=False, indent=2)

    try:
        # 2. issue_id 존재 여부 확인
        existing_log = log_repo.find_by_id(issue_id)
        if not existing_log:
            return json.dumps({
                "error": f"Issue not found: {issue_id}"
            }, ensure_ascii=False, indent=2)

        # 3. 상태 업데이트 호출
        success = log_repo.update_status(issue_id, status)
        if success:
            return json.dumps({
                "issue_id": issue_id,
                "status": status,
                "message": "Status updated successfully."
            }, ensure_ascii=False, indent=2)
        else:
            return json.dumps({"error": "Failed to update status."}, ensure_ascii=False, indent=2)
            
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
