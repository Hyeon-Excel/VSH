import os
import re
from typing import List
import tree_sitter_python
from tree_sitter import Language, Parser
from ..base_module import BaseScanner
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from repository.base_repository import BaseReadRepository

class TreeSitterScanner(BaseScanner):
    """
    Tree-sitter를 이용하여 Python 코드의 AST를 파싱하고 Call Node를 추출하여 탐지하는 Scanner.
    """
    def __init__(self, knowledge_repo: BaseReadRepository):
        self.knowledge_repo = knowledge_repo
        self.language = Language(tree_sitter_python.language())
        self.parser = Parser(self.language)

    def scan(self, file_path: str) -> ScanResult:
        if not file_path.endswith(".py"):
            raise ValueError(f"Unsupported language for file: {file_path}. Supported: {self.supported_languages()}")
            
        if not os.path.exists(file_path):
            return ScanResult(file_path=file_path, language="python", findings=[])

        findings: List[Vulnerability] = []
        knowledge_list = self.knowledge_repo.find_all()

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code_bytes = f.read().encode("utf-8")
                
            tree = self.parser.parse(code_bytes)
            
            # Simple recursive AST traversal to find call nodes
            def find_call_nodes(node):
                call_nodes = []
                if node.type == 'call':
                    call_nodes.append(node)
                for child in node.children:
                    call_nodes.extend(find_call_nodes(child))
                return call_nodes
                
            call_nodes = find_call_nodes(tree.root_node)
            
            for node in call_nodes:
                snippet = code_bytes[node.start_byte:node.end_byte].decode("utf-8")
                line_number = node.start_point.row + 1
                
                for knowledge in knowledge_list:
                    pattern = knowledge.get("pattern")
                    if pattern and re.search(pattern, snippet):
                        v = Vulnerability(
                            cwe_id=knowledge.get("id", "UNKNOWN"),
                            severity=knowledge.get("severity", "MEDIUM"),
                            line_number=line_number,
                            code_snippet=snippet
                        )
                        findings.append(v)

        except Exception as e:
            print(f"[ERROR] TreeSitterScanner parse error: {e}")
            
        return ScanResult(file_path=file_path, language="python", findings=findings)

    def supported_languages(self) -> List[str]:
        return ["python"]
