"""L1 Hot Path 단위 테스트"""
import pytest

from src.vsh.l1.scanner import SemgrepScanner
from src.vsh.l1.sbom import SBOMScanner, _edit_distance, _find_similar, _KNOWN_PYTHON
from src.vsh.l1.reachability import ReachabilityAnalyzer
from src.vsh.l1.aggregator import L1Aggregator
from src.vsh.l1.formatter import Formatter
from src.vsh.models import Severity, Finding


# ================================================================== #
# Scanner (폴백 패턴 매칭)
# ================================================================== #

class TestSemgrepScannerFallback:
    def setup_method(self):
        self.scanner = SemgrepScanner()

    def test_detects_sqli_fstring(self):
        code = (
            'user_input = request.GET["q"]\n'
            'query = f"SELECT * FROM users WHERE id={user_input}"\n'
            'cursor.execute(query)\n'
        )
        findings = self.scanner._scan_with_fallback(code, "python")
        sqli = [f for f in findings if f.cwe == "CWE-89"]
        assert sqli, "f-string SQL Injection 미탐지"

    def test_detects_cmdi_shell_true(self):
        code = "subprocess.run(cmd, shell=True)\n"
        findings = self.scanner._scan_with_fallback(code, "python")
        cmdi = [f for f in findings if f.cwe == "CWE-78"]
        assert cmdi, "Command Injection (shell=True) 미탐지"

    def test_detects_hardcoded_secret(self):
        code = 'SECRET_KEY = "supersecretvalue123"\n'
        findings = self.scanner._scan_with_fallback(code, "python")
        secrets = [f for f in findings if f.cwe == "CWE-798"]
        assert secrets, "하드코딩된 시크릿 미탐지"

    def test_detects_xss_innerhtml(self):
        code = "document.getElementById('out').innerHTML = userInput;\n"
        findings = self.scanner._scan_with_fallback(code, "javascript")
        xss = [f for f in findings if f.cwe == "CWE-79"]
        assert xss, "XSS (innerHTML) 미탐지"

    def test_clean_code_no_findings(self):
        code = (
            'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
        )
        findings = self.scanner._scan_with_fallback(code, "python")
        assert not findings, "안전한 코드에서 오탐 발생"

    def test_finding_has_kisa_reference(self):
        code = "os.system(user_cmd)\n"
        findings = self.scanner._scan_with_fallback(code, "python")
        for f in findings:
            if f.cwe == "CWE-78":
                assert f.kisa_reference, "KISA 참조 누락"
                return
        pytest.fail("CWE-78 Finding 없음")


# ================================================================== #
# SBOM
# ================================================================== #

class TestSBOM:
    def test_edit_distance_same(self):
        assert _edit_distance("requests", "requests") == 0

    def test_edit_distance_typo(self):
        dist = _edit_distance("reqeusts", "requests")
        assert dist <= 2, f"예상 편집거리 ≤2, 실제={dist}"

    def test_find_similar_typosquat(self):
        # "reqeusts" → "requests" 탐지
        result = _find_similar("reqeusts", _KNOWN_PYTHON)
        assert result == "requests", f"유사 패키지 탐지 실패: {result}"

    def test_find_similar_no_match(self):
        # 완전히 다른 이름은 None
        result = _find_similar("zzzzunknownpackage", _KNOWN_PYTHON)
        assert result is None

    def test_hallucination_detected_for_typo(self):
        scanner = SBOMScanner()
        hint = scanner._check_hallucination("reqeusts", "PyPI")
        assert hint is not None, "타이포 패키지 환각 미탐지"

    def test_no_hallucination_for_known(self):
        scanner = SBOMScanner()
        hint = scanner._check_hallucination("requests", "PyPI")
        assert hint is None, "알려진 패키지를 환각으로 오탐"


# ================================================================== #
# Reachability
# ================================================================== #

class TestReachability:
    def setup_method(self):
        self.analyzer = ReachabilityAnalyzer()

    def test_reachable_sqli(self):
        code = (
            "def view(request):\n"
            "    user_input = request.GET['q']\n"
            "    cursor.execute(f'SELECT * FROM t WHERE id={user_input}')\n"
        )
        findings = [Finding(
            rule_id="test", severity=Severity.CRITICAL, cwe="CWE-89",
            cvss=9.8, message="test", line=3,
        )]
        result = self.analyzer.analyze(code, "python", findings)
        assert result[0].reachable is True, "도달 가능 SQLi를 미탐지"

    def test_unreachable_no_taint(self):
        code = (
            "def view():\n"
            "    hard_id = 42\n"
            "    cursor.execute(f'SELECT * FROM t WHERE id={hard_id}')\n"
        )
        findings = [Finding(
            rule_id="test", severity=Severity.CRITICAL, cwe="CWE-89",
            cvss=9.8, message="test", line=3,
        )]
        result = self.analyzer.analyze(code, "python", findings)
        # 오염 변수가 없으므로 reachable=False 또는 None
        assert result[0].reachable in (False, None)


# ================================================================== #
# Formatter
# ================================================================== #

class TestFormatter:
    def setup_method(self):
        self.fmt = Formatter()

    def test_comment_inserted_after_line(self):
        code = "cursor.execute(f'SELECT * FROM t WHERE id={uid}')\n"
        f = Finding(
            rule_id="vsh.python.sqli", severity=Severity.CRITICAL,
            cwe="CWE-89", cvss=9.8, message="SQLi", line=1,
            fix_suggestion='cursor.execute("... WHERE id=%s", (uid,))',
            kisa_reference="KISA 입력데이터 검증 1항",
            impact="DB 조회/변조 가능",
            reachable=True,
        )
        result = self.fmt.annotate_code(code, [f], "python")
        assert "⚠️" in result, "주석 블록 미삽입"
        assert "CWE-89" in result
        assert "KISA" in result
        assert "✅ 실제 도달 가능" in result

    def test_no_findings_no_comment(self):
        code = "x = 1\n"
        result = self.fmt.annotate_code(code, [], "python")
        assert result == code


# ================================================================== #
# Aggregator (통합)
# ================================================================== #

class TestL1Aggregator:
    @pytest.mark.asyncio
    async def test_scan_returns_result(self):
        agg = L1Aggregator()
        code = (
            'user_input = request.GET["q"]\n'
            'cursor.execute(f"SELECT * FROM users WHERE id={user_input}")\n'
        )
        result = await agg.scan(code=code, language="python")
        assert result.error is None
        assert result.findings
        assert result.annotated_code

    @pytest.mark.asyncio
    async def test_scan_clean_code(self):
        agg = L1Aggregator()
        code = 'cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))\n'
        result = await agg.scan(code=code, language="python")
        assert result.error is None
        assert not result.findings
