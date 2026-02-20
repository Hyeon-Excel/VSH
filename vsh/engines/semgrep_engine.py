import json
import re
from pathlib import Path
from vsh.core.config import VSHConfig
from vsh.core.models import Finding
from vsh.core.utils import run_cmd, read_text, iter_source_files

RULE_DIR = Path(__file__).resolve().parent.parent / "rules" / "semgrep"

def _rule_file(language: str) -> Path:
    if language == "javascript":
        return RULE_DIR / "javascript.yml"
    return RULE_DIR / "python.yml"

def _simple_pattern_scan(project_root: Path, language: str) -> list[Finding]:
    """Simple pattern-based scanning as fallback"""
    findings: list[Finding] = []
    
    if language == "python":
        # Python patterns
        for f in iter_source_files(project_root, "python"):
            text = read_text(f)
            lines = text.splitlines()
            
            # Pattern 1: cursor.execute(f"...{...}...") - direct f-string
            # Pattern 2: query = f"...{...}..." + cursor.execute(query)
            for i, line in enumerate(lines, 1):
                if 'cursor.execute(f"' in line and '{' in line:
                    findings.append(Finding(
                        id="VSH-PY-SQLI-001",
                        title="SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.",
                        severity="CRITICAL",
                        cwe="CWE-89",
                        cvss=9.8,
                        cve="CVE-2023-32315",
                        file=str(f.relative_to(project_root)),
                        line=i,
                        message="SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.",
                        recommendation='query = "SELECT * FROM users WHERE id = %s"; cursor.execute(query, (user_input,))',
                        references=["KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현"],
                        meta={"engine":"pattern"}
                    ))
            
            # Pattern 2: Check for f-string queries
            if 'f"SELECT' in text or "f'SELECT" in text:
                for i, line in enumerate(lines, 1):
                    if ('f"' in line or "f'" in line) and 'SELECT' in line and '{' in line:
                        # Check if there's cursor.execute nearby
                        if 'cursor.execute' in text:
                            findings.append(Finding(
                                id="VSH-PY-SQLI-001",
                                title="SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.",
                                severity="CRITICAL",
                                cwe="CWE-89",
                                cvss=9.8,
                                cve="CVE-2023-32315",
                                file=str(f.relative_to(project_root)),
                                line=i,
                                message="SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.",
                                recommendation='query = "SELECT * FROM users WHERE id = %s"; cursor.execute(query, (user_input,))',
                                references=["KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현"],
                                meta={"engine":"pattern"}
                            ))
                            break
                
                # Pattern 3: hardcoded secrets
                for i, line in enumerate(lines, 1):
                    if re.search(r"(?i)(secret_key|api_key|token)\s*=\s*['\"][^'\"]+['\"]", line):
                        findings.append(Finding(
                            id="VSH-PY-SECRET-001",
                            title="하드코딩된 Secret Key 가능성: 민감정보가 코드에 포함될 수 있습니다.",
                            severity="HIGH",
                            cwe="CWE-798",
                            cvss=8.4,
                            file=str(f.relative_to(project_root)),
                            line=i,
                            message="하드코딩된 Secret Key 가능성: 민감정보가 코드에 포함될 수 있습니다.",
                            recommendation="환경변수(.env)로 분리하고 런타임에 로드하세요.",
                            references=["KISA 시큐어코딩 가이드 - 보안기능 (키 관리)"],
                            meta={"engine":"pattern"}
                        ))
    
    elif language == "javascript":
        # JavaScript patterns
        for f in iter_source_files(project_root, "javascript"):
            text = read_text(f)
            lines = text.splitlines()
            
            # Pattern: innerHTML assignment
            for i, line in enumerate(lines, 1):
                if '.innerHTML' in line and '=' in line:
                    findings.append(Finding(
                        id="VSH-JS-XSS-001",
                        title="XSS 가능성: 사용자 입력이 innerHTML로 직접 삽입됩니다.",
                        severity="HIGH",
                        cwe="CWE-79",
                        cvss=8.2,
                        cve="CVE-2022-25858",
                        file=str(f.relative_to(project_root)),
                        line=i,
                        message="XSS 가능성: 사용자 입력이 innerHTML로 직접 삽입됩니다.",
                        recommendation='document.getElementById("output").textContent = userInput;',
                        references=["KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현", "OWASP Top 10 - XSS"],
                        meta={"engine":"pattern"}
                    ))
    
    return findings

def run_semgrep(cfg: VSHConfig, language: str) -> list[Finding]:
    rule = _rule_file(language)
    cmd = [cfg.semgrep_bin, "--quiet", "--json", "--config", str(rule), str(cfg.project_root)]
    rc, out, err = run_cmd(cmd, cwd=cfg.project_root, timeout=cfg.timeout_sec)
    
    # Try using semgrep output if successful
    if rc in (0, 1) and out.strip():
        try:
            data = json.loads(out)
            findings: list[Finding] = []
            for r in data.get("results", []):
                path = r.get("path","")
                start = r.get("start", {}) or {}
                extra = r.get("extra", {}) or {}
                meta = extra.get("metadata", {}) or {}
                findings.append(Finding(
                    id=str(r.get("check_id","VSH-SEM")),
                    title=extra.get("message","Semgrep finding"),
                    severity=str(meta.get("severity","MEDIUM")).upper(),
                    cwe=meta.get("cwe"),
                    cvss=meta.get("cvss"),
                    cve=meta.get("cve"),
                    file=path,
                    line=int(start.get("line",1)),
                    column=int(start.get("col",1)),
                    message=extra.get("message",""),
                    recommendation=meta.get("fix"),
                    references=list(meta.get("references",[])),
                    meta={"engine":"semgrep"}
                ))
            return findings
        except Exception:
            pass
    
    # Fallback to simple pattern-based scanning
    return _simple_pattern_scan(cfg.project_root, language)

