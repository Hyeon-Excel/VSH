import sys
import os
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "VSH-l1-l2-integration/VSH_Project_MVP"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "l3-dev"))

import json
from typing import Any, Dict, List
from dotenv import load_dotenv
from fastmcp import FastMCP
from models.common_schema import (
    VulnRecord as PydanticVulnRecord
)

# 환경변수 로드 (L1/L2 파이프라인 초기화 전에 수행)
load_dotenv()

from orchestration import PipelineFactory
from l3.real_shared_db import RealSharedDB
from l3.providers.sonarqube.real import RealSonarQubeProvider
from l3.providers.sbom.real import RealSBOMProvider
from l3.providers.poc.real import RealPoCProvider
from l3.llm.gemini_adapter import GeminiAdapter
from l3.normalizer import L3Normalizer
from l3.pipeline import L3Pipeline
from l3.report_generator import L3ReportGenerator

# FastMCP 인스턴스
mcp = FastMCP("VSH - Vibe Coding Secure Helper Unified")

# L1/L2 파이프라인 초기화
pipeline = PipelineFactory.create()
log_repo = pipeline.log_repo

# L3 파이프라인 초기화
db = RealSharedDB()
sonarqube = RealSonarQubeProvider(llm=GeminiAdapter())
sbom = RealSBOMProvider()
poc = RealPoCProvider(llm=GeminiAdapter())
normalizer = L3Normalizer(db)
report_generator = L3ReportGenerator(db)
l3_pipeline = L3Pipeline(
    sonarqube=sonarqube,
    sbom=sbom,
    poc=poc,
    normalizer=normalizer
)

# ── L1/L2 헬퍼 함수 ────────────────────────────────────────────────────────────

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


# ── L1/L2 툴 6개 ───────────────────────────────────────────────────────────────

@mcp.tool()
def validate_code(file_path: str) -> Dict[str, Any]:
    """
    지정한 파일에 대해 전체 L1 → L2 보안 검증을 실행한다.

    Args:
        file_path (str): 스캔할 파일의 경로

    Returns:
        Dict[str, Any]: 분석 결과 dict
    """
    result = _run_analysis(file_path)
    if "error" not in result:
        for r in result.get("l2_vuln_records", []):
            try:
                db._vulns.append(PydanticVulnRecord(**r))
            except Exception as e:
                print(f"[VSH] L2 record write 실패: {e}")
    return result


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


# ── L3 툴 ──────────────────────────────────────────────────────────────────────

@mcp.tool()
async def scan_project(project_path: str) -> str:
    """Cursor/Claude IDE에서 호출하는 L3 프로젝트 보안 스캔 툴."""
    task = asyncio.create_task(
        l3_pipeline.run(project_path)
    )
    task.add_done_callback(
        lambda t: print(
            f"[L3] 스캔 완료: {project_path}"
            if not t.exception()
            else f"[L3] 스캔 실패: {t.exception()}"
        )
    )
    return f"L3 백그라운드 스캔 시작됨: {project_path}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
