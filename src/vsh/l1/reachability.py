"""L1 도달 가능성(Reachability) 분석 — Python AST 기반 Taint 추적"""
import ast
from typing import Optional

from ..models import Finding

# 외부 입력 소스 패턴 (Python)
_PYTHON_SOURCES: frozenset[str] = frozenset({
    "request.GET", "request.POST", "request.args", "request.form",
    "request.json", "request.data", "request.values", "request.files",
    "request.GET.get", "request.POST.get", "request.args.get",
    "sys.argv", "os.environ", "os.getenv", "input",
    "flask.request", "django.http",
})

# CWE → 위험 싱크 함수명 매핑
_PYTHON_SINKS: dict[str, frozenset[str]] = {
    "CWE-89":  frozenset({"execute", "executemany", "raw", "query", "rawqueryset"}),
    "CWE-78":  frozenset({"system", "popen", "run", "call", "check_output", "eval", "exec"}),
    "CWE-22":  frozenset({"open", "join", "path"}),
    "CWE-502": frozenset({"loads", "load", "unpickle"}),
}


class ReachabilityAnalyzer:
    """Finding 목록에 Reachability 정보를 채워 반환합니다."""

    def analyze(self, code: str, language: str, findings: list[Finding]) -> list[Finding]:
        if language == "python":
            return self._analyze_python(code, findings)
        # JS/기타는 L2 Warm Path에서 처리 (현재는 미분석)
        return findings

    # ------------------------------------------------------------------ #
    # Python AST 분석
    # ------------------------------------------------------------------ #

    def _analyze_python(self, code: str, findings: list[Finding]) -> list[Finding]:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings

        visitor = _TaintVisitor()
        visitor.visit(tree)

        lines = code.splitlines()
        for f in findings:
            if f.line <= 0:
                continue
            tainted = visitor.tainted_at(f.line)
            sink_names = _PYTHON_SINKS.get(f.cwe, frozenset())
            if not tainted or not sink_names:
                f.reachable = None
                continue

            line_src = lines[f.line - 1] if f.line <= len(lines) else ""
            f.reachable = any(var in line_src for var in tainted)

        return findings


# ------------------------------------------------------------------ #
# AST 방문자 — 변수 오염(Taint) 추적
# ------------------------------------------------------------------ #

class _TaintVisitor(ast.NodeVisitor):
    """
    각 함수 스코프 안에서 외부 입력 소스로부터 대입된 변수를 추적합니다.
    tainted[line] = {오염 변수 집합}
    """

    def __init__(self):
        self._tainted: dict[int, set[str]] = {}
        self._scope_vars: set[str] = set()

    # ---- 함수 경계 ---------------------------------------------------- #

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        saved = self._scope_vars.copy()
        self._scope_vars = set()
        self.generic_visit(node)
        self._scope_vars = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    # ---- 대입문 --------------------------------------------------------- #

    def visit_Assign(self, node: ast.Assign) -> None:
        if _is_tainted_expr(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._scope_vars.add(target.id)
        self._propagate_to_line(node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and _is_tainted_expr(node.value):
            if isinstance(node.target, ast.Name):
                self._scope_vars.add(node.target.id)
        self._propagate_to_line(node.lineno)
        self.generic_visit(node)

    # ---- 일반 스테이트먼트 -------------------------------------------- #

    def generic_visit(self, node: ast.AST) -> None:
        if hasattr(node, "lineno"):
            self._propagate_to_line(node.lineno)  # type: ignore[arg-type]
        super().generic_visit(node)

    # ------------------------------------------------------------------ #

    def _propagate_to_line(self, line: int) -> None:
        if self._scope_vars:
            if line not in self._tainted:
                self._tainted[line] = set()
            self._tainted[line] |= self._scope_vars

    def tainted_at(self, line: int) -> set[str]:
        return self._tainted.get(line, self._scope_vars)


def _is_tainted_expr(node: ast.expr) -> bool:
    """노드 문자열 표현에 외부 입력 소스가 포함되어 있는지 확인합니다."""
    try:
        src = ast.unparse(node)
    except Exception:
        return False
    return any(pattern in src for pattern in _PYTHON_SOURCES)
