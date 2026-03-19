import pytest
from pathlib import Path
from unittest.mock import patch, AsyncMock
from dotenv import load_dotenv
load_dotenv()      
from mcp_server import scan_project, db, sonarqube, sbom, poc
from l3.schema import VulnRecord, PackageRecord


# --- fixture ---

@pytest.fixture(autouse=True)
def reset_db():
    db.reset()

@pytest.fixture
def cleanup_reports():
    yield
    for f in Path("reports").glob("vsh_report_*.md"):
        try:
            f.unlink()
        except FileNotFoundError:
            pass

@pytest.fixture
def project_path():
    return "test/mock_project"

# --- 테스트 ---

async def test_scan_project_normal_flow(cleanup_reports, project_path):
    result = await scan_project(project_path)
    
    assert result.startswith("스캔 완료: reports/vsh_report_")
    filepath = result[len("스캔 완료: "):]
    
    vuln_records = await db.read_all_vuln()
    package_records = await db.read_all_package()
    
    assert len(vuln_records) > 0
    assert len(package_records) > 0
    assert all(isinstance(r, VulnRecord) for r in vuln_records)
    assert all(isinstance(r, PackageRecord) for r in package_records)
    
    assert Path(filepath).exists()
    
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
        assert "VSH 보안 진단 리포트" in content
        assert "종합 보안 점수" in content
        assert "취약점 상세" in content
        assert "SBOM 요약" in content

async def test_scan_project_empty_data(cleanup_reports, project_path):
    with patch.object(sonarqube, 'scan', new=AsyncMock(return_value=[])), \
         patch.object(sbom, 'scan', new=AsyncMock(return_value=[])):
        result = await scan_project(project_path)
        
    assert result.startswith("스캔 완료: reports/vsh_report_")
    filepath = result[len("스캔 완료: "):]
    
    vuln_records = await db.read_all_vuln()
    package_records = await db.read_all_package()
    
    assert len(vuln_records) == 0
    assert len(package_records) == 0
    
    assert Path(filepath).exists()
    
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
        assert "코드 취약점이 발견되지 않았습니다" in content
        assert "패키지 취약점이 발견되지 않았습니다" in content

async def test_scan_project_poc_skipped(cleanup_reports, project_path):
    with patch.object(poc, 'verify', new=AsyncMock(side_effect=Exception("Docker 미설치"))):
        result = await scan_project(project_path)
        
    assert result.startswith("스캔 완료: reports/vsh_report_")
    filepath = result[len("스캔 완료: "):]
    
    vuln_records = await db.read_all_vuln()
    assert len(vuln_records) == 1
    for r in vuln_records:
        assert r.status == "poc_skipped"
        
    package_records = await db.read_all_package()
    assert len(package_records) > 0
    
    assert Path(filepath).exists()
    
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
        assert "poc_skipped" in content

