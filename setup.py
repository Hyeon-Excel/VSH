# setup.py
import os

dirs = [
    "VSH_Project/tools",
    "VSH_Project/pipeline",
    "VSH_Project/modules/scanner",
    "VSH_Project/modules/analyzer",
    "VSH_Project/repository",
    "VSH_Project/models",
    "VSH_Project/mock_db",
    "VSH_Project/dashboard",
    "VSH_Project/docs",
]

files = [
    "VSH_Project/mcp_server.py",
    "VSH_Project/tools/analysis_tools.py",
    "VSH_Project/tools/dashboard_tools.py",
    "VSH_Project/tools/status_tools.py",
    "VSH_Project/pipeline/base_pipeline.py",
    "VSH_Project/pipeline/analysis_pipeline.py",
    "VSH_Project/pipeline/pipeline_factory.py",
    "VSH_Project/modules/base_module.py",
    "VSH_Project/modules/scanner/semgrep_scanner.py",
    "VSH_Project/modules/scanner/treesitter_scanner.py",
    "VSH_Project/modules/scanner/sbom_scanner.py",
    "VSH_Project/modules/analyzer/llm_analyzer.py",
    "VSH_Project/repository/base_repository.py",
    "VSH_Project/repository/knowledge_repo.py",
    "VSH_Project/repository/fix_repo.py",
    "VSH_Project/repository/log_repo.py",
    "VSH_Project/models/scan_result.py",
    "VSH_Project/models/vulnerability.py",
    "VSH_Project/models/fix_suggestion.py",
    "VSH_Project/GEMINI.md",
    "VSH_Project/PRD.md",
    "VSH_Project/ARCHITECTURE.md",
    "VSH_Project/CONVENTIONS.md",
    "VSH_Project/PROGRESS.md",
    "VSH_Project/requirements.txt",
    "VSH_Project/.env.example",
    "VSH_Project/docs/ONBOARDING.md",
    "VSH_Project/docs/FLOW.md",
    "VSH_Project/docs/API_REFERENCE.md",
    "VSH_Project/docs/VARIABLES.md",
]

# 디렉터리 생성
for d in dirs:
    os.makedirs(d, exist_ok=True)

# 파일 생성
for f in files:
    open(f, "w").close()

# mock_db 초기화
open("VSH_Project/mock_db/log.json", "w").write("[]")
open("VSH_Project/mock_db/knowledge.json", "w").write("[]")
open("VSH_Project/mock_db/kisa_fix.json", "w").write("[]")

# __init__.py 생성
init_dirs = ["tools", "pipeline", "modules", "modules/scanner",
             "modules/analyzer", "repository", "models"]
for d in init_dirs:
    open(f"VSH_Project/{d}/__init__.py", "w").close()

print("✅ VSH_Project 구조 생성 완료")