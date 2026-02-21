"""FastMCP adapter for VSH tools."""

from __future__ import annotations

from typing import Any

from vsh.common.models import (
    L1ScanAnnotateRequest,
    L2EnrichFixRequest,
    L3FullReportRequest,
)
from vsh.l1_hot.service import L1Service
from vsh.l2_warm.service import L2Service
from vsh.l3_cold.service import L3Service

try:
    from fastmcp import FastMCP
except Exception:  # pragma: no cover - optional dependency at design stage
    FastMCP = None  # type: ignore[assignment]


def register_tools(app: Any, l1: L1Service, l2: L2Service, l3: L3Service) -> None:
    """Register VSH tools on a FastMCP-compatible app object."""

    @app.tool(name="vsh.l1.scan_annotate")
    def l1_scan_annotate(payload: dict[str, Any]) -> dict[str, Any]:
        request = L1ScanAnnotateRequest.model_validate(payload)
        return l1.scan_annotate(request).model_dump(mode="json")

    @app.tool(name="vsh.l2.enrich_fix")
    def l2_enrich_fix(payload: dict[str, Any]) -> dict[str, Any]:
        request = L2EnrichFixRequest.model_validate(payload)
        return l2.enrich_fix(request).model_dump(mode="json")

    @app.tool(name="vsh.l3.full_report")
    def l3_full_report(payload: dict[str, Any]) -> dict[str, Any]:
        request = L3FullReportRequest.model_validate(payload)
        return l3.full_report(request).model_dump(mode="json")


def create_app() -> Any:
    if FastMCP is None:
        raise RuntimeError("fastmcp is not installed. Install with: pip install '.[mcp]'")

    app = FastMCP("VSH")
    register_tools(app, l1=L1Service(), l2=L2Service(), l3=L3Service())
    return app
