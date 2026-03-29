import json
from typing import Any, Dict, List
from dotenv import load_dotenv
from fastmcp import FastMCP
from vsh_runtime.engine import VshRuntimeEngine
from vsh_runtime.watcher import ProjectWatcher

# 1. 초기화 순서 준수: 환경변수 로드가 가장 먼저 수행되어야 함
load_dotenv()

# 2. Pipeline 생성 및 Repository 참조
from orchestration import PipelineFactory

# 초기화 실패 시 즉시 에러가 발생하여 서버 구동을 막음 (Fail-Fast)
pipeline = PipelineFactory.create()
log_repo = pipeline.log_repo

# 3. FastMCP 인스턴스 생성
mcp = FastMCP("VSH - Vibe Coding Secure Helper")
runtime_engine = VshRuntimeEngine()

# hyeonexcel 수정: MCP 공개 계약을 문서(GEMINI.md, CONVENTIONS.md)와 맞추기 위해
# 실제 비즈니스 로직은 내부 헬퍼로 모으고, 외부에 노출되는 tool 이름은 문서 기준으로 통일한다.
def _error_response(message: str) -> Dict[str, Any]:
    return {"error": message}


def _run_analysis(file_path: str) -> Dict[str, Any]:
    if not pipeline:
        return _error_response("Pipeline not initialized.")

    if not file_path:
        return _error_response("file_path is required.")

    try:
        return pipeline.run(file_path)
    except Exception as e:
        return _error_response(str(e))


def _get_all_logs() -> Dict[str, Any]:
    if not log_repo:
        return _error_response("Repository not initialized.")

    try:
        logs = log_repo.find_all()
        return {
            "logs": logs,
            "total": len(logs),
        }
    except Exception as e:
        return _error_response(str(e))


def _update_issue_status(issue_id: str, status: str, include_fixed_code: bool = False) -> Dict[str, Any]:
    if not log_repo:
        return _error_response("Repository not initialized.")

    try:
        existing_log = log_repo.find_by_id(issue_id)
        if not existing_log:
            return _error_response(f"Issue not found: {issue_id}")

        success = log_repo.update_status(issue_id, status)
        if not success:
            return _error_response(f"Failed to update status to {status}.")

        response: Dict[str, Any] = {
            "issue_id": issue_id,
            "status": status,
            "message": "Status updated successfully.",
        }
        if include_fixed_code:
            response["fixed_code"] = existing_log.get("fixed_code", "")
        return response
    except Exception as e:
        return _error_response(str(e))


def _get_logs_by_file(file_path: str) -> Dict[str, Any]:
    if not log_repo:
        return _error_response("Repository not initialized.")

    if not file_path:
        return _error_response("file_path is required.")

    try:
        logs = log_repo.find_all()
        filtered_logs: List[Dict[str, Any]] = [log for log in logs if log.get("file_path") == file_path]
        return {
            "file_path": file_path,
            "logs": filtered_logs,
            "total": len(filtered_logs),
        }
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
def validate_code(file_path: str) -> Dict[str, Any]:
    """
    지정한 파일에 대해 전체 L1 → L2 보안 검증을 실행한다.
    
    Args:
        file_path (str): 스캔할 파일의 경로
        
    Returns:
        Dict[str, Any]: 분석 결과 dict
    """
    return _run_analysis(file_path)


@mcp.tool()
def scan_only(file_path: str) -> Dict[str, Any]:
    """
    지정한 파일에 대해 탐지 결과만 반환한다.
    
    L2 수정 제안까지 포함한 validate_code와 달리,
    호출자는 scan_result 관점의 최소 정보만 확인할 수 있다.
    """
    if not pipeline:
        return _error_response("Pipeline not initialized.")

    if not file_path:
        return _error_response("file_path is required.")

    try:
        if hasattr(pipeline, "run_scan_only"):
            return pipeline.run_scan_only(file_path)

        result = _run_analysis(file_path)
        if "error" in result:
            return result

        return {
            "file_path": result.get("file_path"),
            "scan_results": result.get("scan_results", []),
            "is_clean": result.get("is_clean", True),
        }
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
def get_results() -> Dict[str, Any]:
    """
    저장된 보안 진단 로그 전체를 조회한다.
    """
    return _get_all_logs()


@mcp.tool()
def apply_fix(issue_id: str) -> Dict[str, Any]:
    """
    특정 이슈를 accepted 상태로 전환하고 수정 제안 코드를 반환한다.

    hyeonexcel 수정:
    현재 단계에서는 실제 파일 수정/백업 기능이 아직 없어서,
    L2가 만든 fixed_code를 반환하고 상태만 accepted로 바꾼다.
    나중에 apply 레이어가 구현되면 이 함수에서 실제 파일 반영 로직을 연결한다.
    """
    return _update_issue_status(issue_id, "accepted", include_fixed_code=True)


@mcp.tool()
def dismiss_issue(issue_id: str) -> Dict[str, Any]:
    """
    특정 이슈를 dismissed 상태로 전환한다.
    """
    return _update_issue_status(issue_id, "dismissed")


@mcp.tool()
def get_log(file_path: str) -> Dict[str, Any]:
    """
    특정 파일 경로에 해당하는 로그만 필터링하여 반환한다.
    """
    return _get_logs_by_file(file_path)


# hyeonexcel 수정: 기존 scan_file/get_report/update_status 호출 경로를 즉시 깨지 않게
# 문서 계약 함수로 위임하는 레거시 호환 래퍼를 남긴다. MCP 공개 이름은 위의 문서 계약을 따른다.
def scan_file(file_path: str) -> str:
    return json.dumps(validate_code(file_path), ensure_ascii=False, indent=2)


def get_report() -> str:
    return json.dumps(get_results(), ensure_ascii=False, indent=2)


def update_status(issue_id: str, status: str) -> str:
    if status == "accepted":
        return json.dumps(apply_fix(issue_id), ensure_ascii=False, indent=2)
    if status == "dismissed":
        return json.dumps(dismiss_issue(issue_id), ensure_ascii=False, indent=2)
    return json.dumps(
        _error_response("Invalid status. Must be 'accepted' or 'dismissed'."),
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def analyze_file(file_path: str) -> Dict[str, Any]:
    return runtime_engine.analyze_file(file_path)


@mcp.tool()
def analyze_project(project_path: str) -> Dict[str, Any]:
    return runtime_engine.analyze_project(project_path)


@mcp.tool()
def get_diagnostics(target_path: str) -> Dict[str, Any]:
    return runtime_engine.get_diagnostics(target_path)


@mcp.tool()
def watch_project(project_path: str, once: bool = True) -> Dict[str, Any]:
    watcher = ProjectWatcher(project_path)
    if once:
        events = watcher.poll_once()
        return {"events": events, "mode": "poll_once"}
    watcher.watch_forever()
    return {"started": True, "mode": "watch_forever"}

if __name__ == "__main__":
    mcp.run()
