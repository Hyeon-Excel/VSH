import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

# 1. 초기화 순서: 환경변수 로드
load_dotenv()

# 2. MockLogRepo 인스턴스 직접 생성 (파일 기반)
from repository.log_repo import MockLogRepo
log_repo = MockLogRepo()

# 3. FastAPI 인스턴스 생성
app = FastAPI(title="VSH Dashboard")

# 4. Jinja2 템플릿 설정
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """
    메인 대시보드 페이지(HTML)를 렌더링하여 반환합니다.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/logs")
async def get_logs():
    """
    저장된 모든 보안 진단 로그를 조회하여 반환합니다.
    
    Returns:
        dict: {"logs": list, "total": int}
    """
    try:
        logs = log_repo.find_all()
        return {
            "logs": logs,
            "total": len(logs)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/logs/{issue_id:path}/accept")
async def accept_issue(issue_id: str):
    """
    특정 취약점의 상태를 'accepted'로 업데이트합니다.
    (실제 소스 파일 수정은 하지 않으며, UI에서 fixed_code를 클립보드에 복사할 수 있도록 반환합니다.)
    """
    try:
        # 존재 여부 확인
        existing_log = log_repo.find_by_id(issue_id)
        if not existing_log:
            raise HTTPException(status_code=404, detail=f"Issue not found: {issue_id}")

        # 상태 업데이트
        success = log_repo.update_status(issue_id, "accepted")
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update status to accepted.")

        return {
            "issue_id": issue_id,
            "status": "accepted",
            "fixed_code": existing_log.get("fixed_code", ""),
            "message": "Status updated successfully."
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/logs/{issue_id:path}/dismiss")
async def dismiss_issue(issue_id: str):
    """
    특정 취약점의 상태를 'dismissed'로 업데이트합니다.
    """
    try:
        # 존재 여부 확인
        existing_log = log_repo.find_by_id(issue_id)
        if not existing_log:
            raise HTTPException(status_code=404, detail=f"Issue not found: {issue_id}")

        # 상태 업데이트
        success = log_repo.update_status(issue_id, "dismissed")
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update status to dismissed.")

        return {
            "issue_id": issue_id,
            "status": "dismissed",
            "message": "Status updated successfully."
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
