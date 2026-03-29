import os
from typing import List, Dict, Any
from .base_pipeline import BasePipeline
from modules.base_module import BaseScanner, BaseAnalyzer
from repository.base_repository import BaseReadRepository, BaseWriteRepository
from models.vulnerability import Vulnerability
from models.scan_result import ScanResult
from models.fix_suggestion import FixSuggestion

class AnalysisPipeline(BasePipeline):
    """
    Scanner(L1)와 Analyzer(L2)를 연결하고 결과를 LogRepo에 저장하는 핵심 파이프라인.
    """

    def __init__(self,
                 scanners: List[BaseScanner],
                 analyzer: BaseAnalyzer,
                 knowledge_repo: BaseReadRepository,
                 fix_repo: BaseReadRepository,
                 log_repo: BaseWriteRepository):
        self.scanners = scanners
        self.analyzer = analyzer
        self.knowledge_repo = knowledge_repo
        self.fix_repo = fix_repo
        self.log_repo = log_repo

    def run(self, file_path: str) -> dict:
        """
        파일에 대해 L1 스캔, 중복 제거, L2 분석, 결과 저장을 수행합니다.
        파일이 없으면 빈 결과 dict를 반환합니다.
        """
        if not os.path.exists(file_path):
            return {
                "file_path": file_path,
                "scan_results": [],
                "fix_suggestions": [],
                "is_clean": True
            }

        # 1. 각 Scanner 실행
        all_findings: List[Vulnerability] = []
        for scanner in self.scanners:
            # 지원하는 언어인지 먼저 확인하거나 예외를 잡을 수 있지만, 
            # 여기서는 Scanner 내부의 언어 체크에 맡기고 실행
            try:
                result = scanner.scan(file_path)
                if result and result.findings:
                    all_findings.extend(result.findings)
            except ValueError as e:
                print(f"[WARN] Unsupported language: {e}")
                # 해당 Scanner 결과만 건너뛰고 계속 진행
            except Exception as e:
                print(f"[WARN] Scanner execution failed: {e}")
                
        # 2 & 3. 중복 제거
        unique_findings = self._deduplicate(all_findings)
        
        # 4. 중복 제거된 findings로 새 ScanResult 생성
        integrated_scan_result = ScanResult(
            file_path=file_path,
            language="python", # MVP에서는 python 고정
            findings=unique_findings
        )

        is_clean = integrated_scan_result.is_clean()
        fix_suggestions: List[FixSuggestion] = []

        if not is_clean:
            # 5. Repository에서 데이터 조회
            knowledge_data = self.knowledge_repo.find_all()
            fix_data = self.fix_repo.find_all()

            # 6. Analyzer 실행 (L2)
            fix_suggestions = self.analyzer.analyze(
                integrated_scan_result,
                knowledge_data,
                fix_data
            )

            # 7. LogRepo 저장
            for suggestion in fix_suggestions:
                # 매칭되는 원본 vulnerability 찾기 (line_number, cwe_id)
                # issue_id 형식: {file_path}_{cwe_id}_{line_number}
                parts = suggestion.issue_id.split("_")
                
                # issue_id 파싱이 정확하지 않을 수 있으니 find로 매칭 (안전한 접근)
                matching_vuln = next((v for v in unique_findings if f"{file_path}_{v.cwe_id}_{v.line_number}" == suggestion.issue_id), None)
                
                if matching_vuln:
                    log_data = {
                        "issue_id": suggestion.issue_id,
                        "file_path": file_path,
                        "cwe_id": matching_vuln.cwe_id,
                        "severity": matching_vuln.severity,
                        "line_number": matching_vuln.line_number,
                        "code_snippet": matching_vuln.code_snippet,
                        "original_code": suggestion.original_code,
                        "fixed_code": suggestion.fixed_code,
                        "status": "pending"
                    }
                    self.log_repo.save(log_data)

        # 8. 결과 dict로 변환 (Pydantic model_dump 사용)
        return {
            "file_path": file_path,
            "scan_results": [v.model_dump() for v in integrated_scan_result.findings],
            "fix_suggestions": [f.model_dump() for f in fix_suggestions],
            "is_clean": is_clean
        }

    @staticmethod
    def _deduplicate(findings: List[Vulnerability]) -> List[Vulnerability]:
        """
        cwe_id와 line_number 조합을 기준으로 중복된 취약점을 제거합니다.
        
        Args:
            findings (List[Vulnerability]): 원본 취약점 리스트
            
        Returns:
            List[Vulnerability]: 중복 제거된 취약점 리스트
        """
        unique_map = {}
        for f in findings:
            key = f"{f.cwe_id}_{f.line_number}"
            if key not in unique_map:
                unique_map[key] = f
        
        return list(unique_map.values())
