from fastmcp import FastMCP
from l3.providers.sonarqube.real import RealSonarQubeProvider
from l3.providers.sbom.real import RealSBOMProvider
from l3.providers.poc.real import RealPoCProvider
from l3.llm.gemini_adapter import GeminiAdapter
from l3.mock_shared_db import MockSharedDB
from l3.normalizer import L3Normalizer
from l3.pipeline import L3Pipeline
from l3.report_generator import L3ReportGenerator

mcp = FastMCP("VSH-L3")
# "VSH-L3": Cursor/Claude IDE에 노출될 서버 식별자

# 1단계: 의존성 없는 기반 객체
db = MockSharedDB()
sonarqube = RealSonarQubeProvider(llm=GeminiAdapter())
sbom = RealSBOMProvider()
poc = RealPoCProvider(llm=GeminiAdapter())

# 2단계: DB에 의존하는 객체
normalizer = L3Normalizer(db)
report_generator = L3ReportGenerator(db)

# 3단계: 전체를 조립하는 객체
pipeline = L3Pipeline(
    sonarqube=sonarqube,
    sbom=sbom,
    poc=poc,
    normalizer=normalizer
)

@mcp.tool()
async def scan_project(project_path: str) -> str:
    """Cursor/Claude IDE에서 호출하는 프로젝트 보안 스캔 툴."""
    print(f"[L3 MCP] 스캔 요청 수신: {project_path}")
    await pipeline.run(project_path)
    filepath = await report_generator.generate()
    return f"스캔 완료: {filepath}"

if __name__ == "__main__":
    mcp.run()
