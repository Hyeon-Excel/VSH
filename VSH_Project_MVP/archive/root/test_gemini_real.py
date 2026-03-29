import os
from dotenv import load_dotenv
from modules import AnalyzerFactory
from repository import MockKnowledgeRepo, MockFixRepo
from models import ScanResult, Vulnerability

load_dotenv()

knowledge = MockKnowledgeRepo().find_all()
fix_hints = MockFixRepo().find_all()

analyzer = AnalyzerFactory.create(
    os.getenv("LLM_PROVIDER", "gemini"),
    os.getenv("GEMINI_API_KEY")
)

findings = [
    Vulnerability(
        cwe_id="CWE-78",
        severity="HIGH",
        line_number=5,
        code_snippet="subprocess.run(user_input, shell=True)"
    )
]
scan_result = ScanResult(
    file_path="test_vuln.py",
    language="python",
    findings=findings
)

suggestions = analyzer.analyze(scan_result, knowledge, fix_hints)
print(f"결과 개수: {len(suggestions)}")
for s in suggestions:
    print(f"  issue_id: {s.issue_id}")
    print(f"  original_code: {s.original_code}")
    print(f"  fixed_code: {s.fixed_code}")
    print(f"  description: {s.description}")
