import os
import re
from typing import List
from pathlib import Path
from packaging.version import parse as parse_version
from ..base_module import BaseScanner
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability

try:
    from config import PROJECT_ROOT, VULNERABLE_PACKAGES
except ImportError:
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    VULNERABLE_PACKAGES = {}

class SBOMScanner(BaseScanner):
    """
    프로젝트 루트의 requirements.txt를 분석하여 취약한 패키지를 탐지하는 Scanner.
    """
    def scan(self, file_path: str) -> ScanResult:
        req_path = os.path.join(PROJECT_ROOT, "requirements.txt")
        findings: List[Vulnerability] = []

        if not os.path.exists(req_path):
            return ScanResult(file_path=file_path, language="python", findings=[])

        try:
            with open(req_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                
            for line_idx, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                    
                # 패키지명과 버전 분리 추출 (예: requests==2.9.0)
                match = re.match(r"^([a-zA-Z0-9_\-]+)(?:[=!<>~]+([0-9\.]+))?", line)
                if match:
                    package_name = match.group(1).lower()
                    package_version = match.group(2)
                    
                    if package_name in VULNERABLE_PACKAGES:
                        vuln_info = VULNERABLE_PACKAGES[package_name]
                        vulnerable_below = vuln_info.get("vulnerable_below")
                        
                        is_vulnerable = False
                        
                        if package_version and vulnerable_below:
                            # 올바른 Semantic Version 비교 수행
                            if parse_version(package_version) < parse_version(vulnerable_below):
                                is_vulnerable = True
                        else:
                            # 버전이 명시되지 않았을 경우 보수적으로 취약하다고 판단
                            is_vulnerable = True
                            
                        if is_vulnerable:
                            v = Vulnerability(
                                cwe_id="CWE-829",
                                severity="HIGH",
                                line_number=line_idx + 1,
                                code_snippet=line
                            )
                            findings.append(v)
        except Exception as e:
             print(f"[ERROR] SBOMScanner read error: {e}")
             
        return ScanResult(file_path=file_path, language="python", findings=findings)

    def supported_languages(self) -> List[str]:
        return ["python"]
