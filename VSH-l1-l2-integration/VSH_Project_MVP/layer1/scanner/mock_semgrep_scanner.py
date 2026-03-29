import os
import re
from typing import List
from shared.contracts import BaseScanner
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from repository.base_repository import BaseReadRepository

class MockSemgrepScanner(BaseScanner):
    """
    Semgrep을 대신하여 knowledge.json 패턴 기반 문자열 매칭을 수행하는 Mock Scanner.
    """
    def __init__(self, knowledge_repo: BaseReadRepository):
        self.knowledge_repo = knowledge_repo

    def scan(self, file_path: str) -> ScanResult:
        findings: List[Vulnerability] = []
        if not os.path.exists(file_path):
            return ScanResult(file_path=file_path, language="python", findings=[])

        knowledge_list = self.knowledge_repo.find_all()

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                
            for line_idx, line in enumerate(lines):
                line_number = line_idx + 1
                for knowledge in knowledge_list:
                    pattern = knowledge.get("pattern")
                    if pattern and re.search(pattern, line):
                        v = Vulnerability(
                            file_path=file_path,
                            cwe_id=knowledge.get("id", "UNKNOWN"),
                            severity=knowledge.get("severity", "MEDIUM"),
                            line_number=line_number,
                            code_snippet=line.strip()
                        )
                        findings.append(v)
        except Exception as e:
            print(f"[ERROR] MockSemgrepScanner file read error: {e}")
            
        return ScanResult(file_path=file_path, language="python", findings=findings)

    def supported_languages(self) -> List[str]:
        return ["python"]
