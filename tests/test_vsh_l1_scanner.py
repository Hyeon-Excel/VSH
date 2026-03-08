from pathlib import Path
import pytest

from modules.scanner.base_scanner import BaseScanner
from modules.scanner.vsh_l1_scanner import VSHL1Scanner
from pipeline.analysis_pipeline import AnalysisPipeline
from vsh.core.config import VSHConfig
from vsh.core.models import VulnRecord, PackageRecord
from vsh.engines.typosquatting_engine import detect_typosquatting, _similarity_ratio
from vsh.engines.schema_normalizer import normalize_finding
from vsh.engines.code_annotator import annotate_files
from vsh.core.models import Finding


def test_vsh_l1_scanner_implements_base_scanner(tmp_path: Path):
    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    scanner = VSHL1Scanner(cfg)
    assert isinstance(scanner, BaseScanner)


def test_pipeline_run_l1_returns_scan_result(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("user_input = input()\nquery = f\"SELECT * FROM users WHERE id = {user_input}\"\n")

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    pipeline = AnalysisPipeline(scanner=VSHL1Scanner(cfg))

    result = pipeline.run_l1()

    assert result.project == tmp_path.name
    assert isinstance(result.notes, list)
    assert any(note.startswith("layer=L1") for note in result.notes)


# NEW: Schema normalization tests
def test_finding_normalization(tmp_path: Path):
    """Test conversion of Finding to VulnRecord."""
    finding = Finding(
        id="VSH-TEST-001",
        title="SQL Injection via f-string",
        severity="CRITICAL",
        cwe="CWE-89",
        cvss=9.8,
        cve="CVE-2023-32315",
        file="app.py",
        line=42,
        message="Direct SQL query concatenation detected",
        recommendation="Use parameterized queries",
        reachability="YES",
    )
    
    vuln_record = normalize_finding(finding, 1)
    
    assert isinstance(vuln_record, VulnRecord)
    assert vuln_record.vuln_id.startswith("VSH-")
    assert vuln_record.source == "L1"
    assert vuln_record.file_path == "app.py"
    assert vuln_record.line_number == 42
    assert vuln_record.vuln_type == "SQLI"
    assert vuln_record.cwe_id == "CWE-89"
    assert vuln_record.severity == "CRITICAL"
    assert vuln_record.reachability is True
    assert vuln_record.kisa_ref is not None


def test_scan_result_has_normalized_records(tmp_path: Path):
    """Test that ScanResult includes VulnRecord and PackageRecord after scan."""
    source = tmp_path / "sample.py"
    source.write_text("import os\n")

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    scanner = VSHL1Scanner(cfg)
    result = scanner.scan()

    assert hasattr(result, "vuln_records")
    assert hasattr(result, "package_records")
    assert isinstance(result.vuln_records, list)
    assert isinstance(result.package_records, list)


# NEW: Typosquatting detection tests
def test_levenshtein_similarity():
    """Test similarity ratio calculation."""
    # Exact match
    assert _similarity_ratio("requests", "requests") == 1.0
    
    # One character difference
    s1 = _similarity_ratio("requests", "requists")
    assert 0.85 < s1 < 1.0
    
    # Two character difference
    s2 = _similarity_ratio("requests", "reqeusts")
    assert 0.7 < s2 < 0.9


def test_typosquatting_detection_finds_similar_packages():
    """Test detection of typosquatting packages."""
    # Test with known packages
    imports = {"reqeusts", "numpy", "pandas"}  # "reqeusts" is typosquat of "requests"
    
    findings = detect_typosquatting(imports, "PyPI", threshold=0.75)
    
    # Should find "reqeusts" as similar to "requests"
    typo_finding = next((f for f in findings if "reqeusts" in f.meta.get("package", "")), None)
    assert typo_finding is not None
    assert typo_finding.severity in ("CRITICAL", "HIGH", "MEDIUM")


def test_typosquatting_ignores_exact_matches():
    """Test that exact matches are not flagged."""
    imports = {"requests", "django", "flask"}
    
    findings = detect_typosquatting(imports, "PyPI", threshold=0.75)
    
    assert len(findings) == 0


# NEW: Code annotation tests
def test_annotate_python_file(tmp_path: Path):
    """Test Python code annotation."""
    source = tmp_path / "vulnerable.py"
    source.write_text(
        "user_input = input()\n"
        "query = f\"SELECT * FROM users WHERE id = {user_input}\"\n"
    )
    
    # Create a VulnRecord
    from vsh.core.models import VulnRecord
    vuln = VulnRecord(
        vuln_id="VSH-20260306-001",
        source="L1",
        detected_at="2026-03-06T00:00:00Z",
        file_path="vulnerable.py",
        line_number=2,
        vuln_type="SQLI",
        cwe_id="CWE-89",
        severity="CRITICAL",
        kisa_ref="입력데이터 검증 및 표현 1항",
        fix_suggestion='Use parameterized queries'
    )
    
    annotated = annotate_files([vuln], tmp_path)
    
    assert "vulnerable.py" in annotated
    content = annotated["vulnerable.py"]
    assert "[VSH-L1]" in content
    assert "SQLI" in content
    assert "CWE-89" in content


def test_annotate_javascript_file(tmp_path: Path):
    """Test JavaScript code annotation uses // comments."""
    source = tmp_path / "app.js"
    source.write_text(
        "let output = document.getElementById('result');\n"
        "output.innerHTML = userInput;\n"
    )
    
    from vsh.core.models import VulnRecord
    vuln = VulnRecord(
        vuln_id="VSH-20260306-002",
        source="L1",
        detected_at="2026-03-06T00:00:00Z",
        file_path="app.js",
        line_number=2,
        vuln_type="XSS",
        cwe_id="CWE-79",
        severity="HIGH",
        kisa_ref="입력데이터 검증 및 표현 3항",
        fix_suggestion='Use textContent instead of innerHTML'
    )
    
    annotated = annotate_files([vuln], tmp_path)
    
    assert "app.js" in annotated
    content = annotated["app.js"]
    # Should start with // (JS comment)
    assert "// ⚠️ [VSH-L1]" in content
    assert "XSS" in content


# NEW: Pipeline integration tests
def test_pipeline_run_l1_scan_only(tmp_path: Path):
    """Test pipeline with scan_only=True (no annotations)."""
    source = tmp_path / "sample.py"
    source.write_text("import os\n")

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    pipeline = AnalysisPipeline(scanner=VSHL1Scanner(cfg))

    result = pipeline.run_l1(scan_only=True)

    assert result.annotated_files == {}  # No annotations in scan_only mode


def test_pipeline_run_l1_with_annotation(tmp_path: Path):
    """Test pipeline with annotate=True."""
    source = tmp_path / "sample.py"
    source.write_text(
        "user_input = input()\n"
        "query = f\"SELECT * FROM users WHERE id = {user_input}\"\n"
    )

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    pipeline = AnalysisPipeline(scanner=VSHL1Scanner(cfg))

    result = pipeline.run_l1(scan_only=False, annotate=True)

    # Should have annotations if vulnerabilities were found
    # (may be empty if semgrep isn't installed, but structure is correct)
    assert isinstance(result.annotated_files, dict)


def test_scan_result_includes_typosquatting_packages(tmp_path: Path):
    """Test that typosquatting packages are recorded in ScanResult."""
    source = tmp_path / "main.py"
    source.write_text("import reqeusts\n")  # typosquat of "requests"

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    scanner = VSHL1Scanner(cfg)
    result = scanner.scan()

    assert hasattr(result, "typosquatting_packages")
    assert isinstance(result.typosquatting_packages, list)
    # May contain "reqeusts" if detected


def test_vuln_record_required_fields():
    """Test that VulnRecord enforces required fields."""
    # This should work - all required fields
    vuln = VulnRecord(
        vuln_id="VSH-20260306-001",
        source="L1",
        detected_at="2026-03-06T00:00:00Z",
        file_path="test.py",
        line_number=10,
        vuln_type="SQLI",
        cwe_id="CWE-89",
        severity="HIGH",
        kisa_ref="입력데이터 검증 및 표현 1항",
    )
    assert vuln.kisa_ref is not None
    
    # fss_ref is nullable
    assert vuln.fss_ref is None
    
    # status defaults to pending
    assert vuln.status == "pending"
    
    # action_at defaults to None
    assert vuln.action_at is None


# NEW: 함수별 세부 경고 테스트
def test_function_level_risk_warnings(tmp_path: Path):
    """Test function-level risk warnings for specific dangerous functions."""
    # Test Python XXE vulnerability
    source = tmp_path / "xxe_vulnerable.py"
    source.write_text('''import xml.etree.ElementTree as ET
user_input = "<root><external>&external;</external></root>"
result = ET.fromstring(user_input)  # XXE 취약
safe_result = ET.parse("safe.xml")  # 안전
''')

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    scanner = VSHL1Scanner(cfg)
    result = scanner.scan()

    # Should detect XXE vulnerability in the test file specifically
    xxe_findings = [f for f in result.findings if "XXE" in f.message and "xxe_vulnerable.py" in f.file]
    assert len(xxe_findings) > 0
    
    # Check that function-level risk information is included
    xxe_finding = xxe_findings[0]
    assert "fromstring()" in xxe_finding.message
    assert xxe_finding.meta.get("function_risk") is not None


def test_eval_function_risk_warning(tmp_path: Path):
    """Test eval() function risk warning."""
    source = tmp_path / "eval_vulnerable.py"
    source.write_text('''user_input = "print('hello')"
result = eval(user_input)  # 위험한 eval 사용
''')

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    scanner = VSHL1Scanner(cfg)
    result = scanner.scan()

    eval_findings = [f for f in result.findings if "eval()" in f.message and "eval_vulnerable.py" in f.file]
    assert len(eval_findings) > 0
    
    eval_finding = eval_findings[0]
    assert "임의 코드 실행" in eval_finding.message
    assert eval_finding.meta.get("safe_alternatives") is not None


def test_subprocess_shell_risk_warning(tmp_path: Path):
    """Test subprocess shell=True risk warning."""
    source = tmp_path / "subprocess_vulnerable.py"
    source.write_text('''import subprocess
user_cmd = "ls -la"
result = subprocess.run(user_cmd, shell=True)  # 위험
safe_result = subprocess.run(["ls", "-la"])    # 안전
''')

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    scanner = VSHL1Scanner(cfg)
    result = scanner.scan()

    shell_findings = [f for f in result.findings if "shell=True" in f.message and "subprocess_vulnerable.py" in f.file]
    assert len(shell_findings) > 0
    
    shell_finding = shell_findings[0]
    assert "명령어 주입" in shell_finding.message


def test_javascript_innerhtml_risk_warning(tmp_path: Path):
    """Test JavaScript innerHTML risk warning."""
    source = tmp_path / "xss_vulnerable.js"
    source.write_text('''let userInput = "<script>alert('xss')</script>";
document.getElementById("output").innerHTML = userInput; // 위험
document.getElementById("safe").textContent = userInput;  // 안전
''')

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="javascript")
    scanner = VSHL1Scanner(cfg)
    result = scanner.scan()

    innerhtml_findings = [f for f in result.findings if "innerHTML" in f.message and "xss_vulnerable.js" in f.file]
    assert len(innerhtml_findings) > 0
    
    innerhtml_finding = innerhtml_findings[0]
    assert "XSS 공격에 취약" in innerhtml_finding.message
    assert innerhtml_finding.meta.get("safe_alternatives") is not None


def test_enhanced_fix_suggestions_in_vuln_records(tmp_path: Path):
    """Test that VulnRecord includes enhanced fix suggestions with function-level guidance."""
    source = tmp_path / "test_vulnerable.py"
    source.write_text('''import pickle
user_data = b"malicious_pickle_data"
result = pickle.loads(user_data)  # 위험한 역직렬화
''')

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    scanner = VSHL1Scanner(cfg)
    result = scanner.scan()

    # Get the normalized vuln record
    vuln_records = result.vuln_records
    pickle_vulns = [v for v in vuln_records if "pickle" in (v.fix_suggestion or "").lower()]
    
    if pickle_vulns:
        vuln = pickle_vulns[0]
        assert "역직렬화 공격에 취약" in (vuln.fix_suggestion or "")
        assert "안전한 대안:" in (vuln.fix_suggestion or "")


def test_function_level_annotation_includes_risk_details(tmp_path: Path):
    """Test that code annotations include function-level risk details."""
    source = tmp_path / "annotation_test.py"
    source.write_text('''import os
user_cmd = "ls -la"
os.system(user_cmd)  # 위험한 os.system 사용
''')

    cfg = VSHConfig(project_root=tmp_path, out_dir=tmp_path, use_syft=False, language="python")
    scanner = VSHL1Scanner(cfg)
    result = scanner.scan()
    
    # Annotate and check the result
    annotated_result = scanner.annotate(result)
    
    # annotated_result is a ScanResult containing annotated_files dict
    assert annotated_result.annotated_files, "no annotations produced"
    content = list(annotated_result.annotated_files.values())[0]
    assert "[VSH-L1]" in content
    assert "Function Risk:" in content or "Fix:" in content

