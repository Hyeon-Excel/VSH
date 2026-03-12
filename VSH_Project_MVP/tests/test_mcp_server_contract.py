import importlib.util
import sys
import types
from pathlib import Path


SERVER_PATH = Path(__file__).resolve().parent.parent / "tools" / "server.py"


class FakeLogRepo:
    def __init__(self):
        self.logs = [
            {
                "issue_id": "issue-1",
                "file_path": "tests/sample.py",
                "fixed_code": "print('safe')",
                "status": "pending",
            },
            {
                "issue_id": "issue-2",
                "file_path": "tests/other.py",
                "fixed_code": "print('other')",
                "status": "pending",
            },
        ]

    def find_all(self):
        return list(self.logs)

    def find_by_id(self, issue_id: str):
        return next((log for log in self.logs if log["issue_id"] == issue_id), None)

    def update_status(self, issue_id: str, status: str):
        target = self.find_by_id(issue_id)
        if not target:
            return False
        target["status"] = status
        return True


class FakePipeline:
    def __init__(self):
        self.log_repo = FakeLogRepo()
        self.run_called = False
        self.run_scan_only_called = False

    def run(self, file_path: str):
        self.run_called = True
        return {
            "file_path": file_path,
            "scan_results": [{"cwe_id": "CWE-89"}],
            "vuln_records": [{"vuln_id": "VSH-001"}],
            "l2_vuln_records": [{"vuln_id": "VSH-001", "source": "L2"}],
            "package_records": [{"package_id": "PKG-001"}],
            "annotated_files": {file_path: "# preview"},
            "notes": ["layer=L1"],
            "fix_suggestions": [{"issue_id": "issue-1"}],
            "is_clean": False,
        }

    def run_scan_only(self, file_path: str):
        self.run_scan_only_called = True
        return {
            "file_path": file_path,
            "scan_results": [{"cwe_id": "CWE-89"}],
            "vuln_records": [{"vuln_id": "VSH-001"}],
            "package_records": [{"package_id": "PKG-001"}],
            "annotated_files": {file_path: "# preview"},
            "notes": ["layer=L1"],
            "is_clean": False,
        }


class FakeMCP:
    def __init__(self, name: str):
        self.name = name
        self.registered_tools = {}

    def tool(self):
        def decorator(func):
            self.registered_tools[func.__name__] = func
            return func

        return decorator


def _load_server_module(monkeypatch):
    fake_pipeline = FakePipeline()

    fake_fastmcp = types.ModuleType("fastmcp")
    fake_fastmcp.FastMCP = FakeMCP

    fake_orchestration_module = types.ModuleType("orchestration")

    class FakePipelineFactory:
        @staticmethod
        def create():
            return fake_pipeline

    fake_orchestration_module.PipelineFactory = FakePipelineFactory

    monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp)
    monkeypatch.setitem(sys.modules, "orchestration", fake_orchestration_module)

    spec = importlib.util.spec_from_file_location("test_server_module", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_server_exposes_documented_mcp_tool_names(monkeypatch):
    module = _load_server_module(monkeypatch)

    assert sorted(module.mcp.registered_tools.keys()) == [
        "apply_fix",
        "dismiss_issue",
        "get_log",
        "get_results",
        "scan_only",
        "validate_code",
    ]


def test_server_documented_tools_follow_expected_contract(monkeypatch):
    module = _load_server_module(monkeypatch)

    validate_result = module.validate_code("tests/sample.py")
    scan_only_result = module.scan_only("tests/sample.py")
    results = module.get_results()
    apply_result = module.apply_fix("issue-1")
    dismiss_result = module.dismiss_issue("issue-2")
    file_logs = module.get_log("tests/sample.py")

    assert validate_result["file_path"] == "tests/sample.py"
    assert "fix_suggestions" in validate_result
    assert validate_result["l2_vuln_records"] == [{"vuln_id": "VSH-001", "source": "L2"}]
    assert scan_only_result["file_path"] == "tests/sample.py"
    assert "fix_suggestions" not in scan_only_result
    assert "l2_vuln_records" not in scan_only_result
    assert scan_only_result["vuln_records"] == [{"vuln_id": "VSH-001"}]
    assert scan_only_result["package_records"] == [{"package_id": "PKG-001"}]
    assert scan_only_result["annotated_files"] == {"tests/sample.py": "# preview"}
    assert scan_only_result["notes"] == ["layer=L1"]
    assert results["total"] == 2
    assert apply_result["status"] == "accepted"
    assert apply_result["fixed_code"] == "print('safe')"
    assert dismiss_result["status"] == "dismissed"
    assert file_logs["file_path"] == "tests/sample.py"
    assert file_logs["total"] == 1


def test_scan_only_uses_detection_only_path_without_full_analysis(monkeypatch):
    module = _load_server_module(monkeypatch)
    module.pipeline.run_called = False
    module.pipeline.run_scan_only_called = False

    result = module.scan_only("tests/sample.py")

    assert result["scan_results"] == [{"cwe_id": "CWE-89"}]
    assert result["vuln_records"] == [{"vuln_id": "VSH-001"}]
    assert result["package_records"] == [{"package_id": "PKG-001"}]
    assert result["annotated_files"] == {"tests/sample.py": "# preview"}
    assert module.pipeline.run_scan_only_called is True
    assert module.pipeline.run_called is False
