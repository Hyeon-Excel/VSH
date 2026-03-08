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
            
            # Pattern 4: XXE vulnerability (xml.etree.ElementTree.fromstring)
            for i, line in enumerate(lines, 1):
                if "fromstring(" in line:
                    findings.append(Finding(
                        id="VSH-PY-XXE-001",
                        title="XXE 취약점: fromstring() 함수가 외부 엔티티를 처리할 수 있습니다.",
                        severity="CRITICAL",
                        cwe="CWE-611",
                        cvss=8.2,
                        file=str(f.relative_to(project_root)),
                        line=i,
                        message="XXE 취약점: fromstring() 함수가 외부 엔티티를 처리할 수 있습니다.",
                        recommendation="외부 입력을 신뢰하지 말고, parse() 메소드를 사용하거나 defusedxml 라이브러리를 사용하세요.",
                        references=["OWASP XXE Prevention Cheat Sheet"],
                        meta={
                            "engine": "pattern",
                            "function_risk": "xml.etree.ElementTree.fromstring() 함수는 XXE 공격에 취약합니다.",
                            "safe_alternatives": "xml.etree.ElementTree.parse() 또는 defusedxml 사용을 고려하세요."
                        }
                    ))
                
                # Pattern 5: Dangerous eval() usage
                for i, line in enumerate(lines, 1):
                    if re.search(r"\beval\s*\(", line):
                        findings.append(Finding(
                            id="VSH-PY-EVAL-001",
                            title="위험한 eval() 사용: 임의 코드 실행으로 이어질 수 있습니다.",
                            severity="CRITICAL",
                            cwe="CWE-95",
                            cvss=9.3,
                            file=str(f.relative_to(project_root)),
                            line=i,
                            message="위험한 eval() 사용: 임의 코드 실행으로 이어질 수 있습니다.",
                            recommendation="eval() 대신 ast.literal_eval()을 사용하거나, 입력을 엄격하게 검증하세요.",
                            references=["OWASP Code Injection Prevention"],
                            meta={
                                "engine": "pattern",
                                "function_risk": "eval()은 임의 코드 실행 공격에 취약합니다.",
                                "safe_alternatives": "ast.literal_eval(), json.loads(), 또는 안전한 파서 사용"
                            }
                        ))
                
                # Pattern 6: Dangerous subprocess with shell=True
                for i, line in enumerate(lines, 1):
                    if re.search(r"subprocess\.\w+\s*\(.+shell\s*=\s*True", line):
                        findings.append(Finding(
                            id="VSH-PY-SUBPROCESS-001",
                            title="위험한 subprocess 사용: shell=True는 명령어 주입 공격에 취약합니다.",
                            severity="HIGH",
                            cwe="CWE-78",
                            cvss=8.6,
                            file=str(f.relative_to(project_root)),
                            line=i,
                            message="위험한 subprocess 사용: shell=True는 명령어 주입 공격에 취약합니다.",
                            recommendation="shell=False로 변경하고 명령어를 리스트로 분리하세요: ['ls', '-la']",
                            references=["KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현"],
                            meta={"engine":"pattern"}
                        ))
                
                # Pattern 7: Dangerous os.system usage
                for i, line in enumerate(lines, 1):
                    if "os.system(" in line:
                        findings.append(Finding(
                            id="VSH-PY-OS-SYSTEM-001",
                            title="위험한 os.system() 사용: 명령어 주입에 취약합니다.",
                            severity="HIGH",
                            cwe="CWE-78",
                            cvss=7.8,
                            file=str(f.relative_to(project_root)),
                            line=i,
                            message="위험한 os.system() 사용: 명령어 주입에 취약합니다.",
                            recommendation="subprocess.run(['command', 'arg1'], shell=False)로 변경하세요.",
                            references=["OWASP Command Injection Prevention"],
                            meta={
                                "engine": "pattern",
                                "function_risk": "os.system()은 셸을 통해 명령어를 실행하므로 주입 공격에 취약합니다.",
                                "safe_alternatives": "subprocess.run() with shell=False"
                            }
                        ))
                
                # Pattern 6: Dangerous subprocess with shell=True
                for i, line in enumerate(lines, 1):
                    if re.search(r"subprocess\.\w+\s*\(.+shell\s*=\s*True", line):
                        findings.append(Finding(
                            id="VSH-PY-SUBPROCESS-001",
                            title="위험한 subprocess 사용: shell=True는 명령어 주입 공격에 취약합니다.",
                            severity="HIGH",
                            cwe="CWE-78",
                            cvss=8.6,
                            file=str(f.relative_to(project_root)),
                            line=i,
                            message="위험한 subprocess 사용: shell=True는 명령어 주입 공격에 취약합니다.",
                            recommendation="shell=False로 변경하고 명령어를 리스트로 분리하세요: ['ls', '-la']",
                            references=["OWASP Command Injection Prevention"],
                            meta={
                                "engine": "pattern",
                                "function_risk": "shell=True 옵션은 명령어 주입 공격에 취약합니다.",
                                "safe_alternatives": "shell=False로 설정하고 리스트 형태로 명령어 전달"
                            }
                        ))
                
                # Pattern 7: Dangerous pickle.loads
                for i, line in enumerate(lines, 1):
                    if "pickle.loads(" in line:
                        findings.append(Finding(
                            id="VSH-PY-DESERIALIZE-001",
                            title="안전하지 않은 역직렬화: pickle.loads()는 임의 코드 실행으로 이어질 수 있습니다.",
                            severity="CRITICAL",
                            cwe="CWE-502",
                            cvss=9.8,
                            file=str(f.relative_to(project_root)),
                            line=i,
                            message="안전하지 않은 역직렬화: pickle.loads()는 임의 코드 실행으로 이어질 수 있습니다.",
                            recommendation="신뢰할 수 있는 데이터만 역직렬화하고, 가능하면 JSON으로 마이그레이션하세요.",
                            references=["OWASP Deserialization Cheat Sheet"],
                            meta={
                                "engine": "pattern",
                                "function_risk": "pickle.loads()는 역직렬화 공격에 취약합니다.",
                                "safe_alternatives": "json.loads() 또는 안전한 직렬화 라이브러리 사용"
                            }
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
                        message="XSS 공격에 취약: 사용자 입력이 innerHTML로 직접 삽입됩니다.",
                        recommendation='document.getElementById("output").textContent = userInput;',
                        references=["KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현", "OWASP Top 10 - XSS"],
                        meta={
                            "engine":"pattern",
                            "function_risk": "innerHTML에 사용자 입력을 할당하면 DOM XSS 공격에 취약합니다.",
                            "safe_alternatives": "textContent 또는 기타 안전한 DOM 조작 메서드 사용"
                        }
                    ))
            
            # Pattern: Dangerous eval() in JavaScript
            for i, line in enumerate(lines, 1):
                if re.search(r"\beval\s*\(", line):
                    findings.append(Finding(
                        id="VSH-JS-EVAL-001",
                        title="위험한 eval() 사용: 코드 실행으로 이어질 수 있습니다.",
                        severity="CRITICAL",
                        cwe="CWE-95",
                        cvss=9.3,
                        file=str(f.relative_to(project_root)),
                        line=i,
                        message="위험한 eval() 사용: 코드 실행으로 이어질 수 있습니다.",
                        recommendation="eval() 대신 JSON.parse() 또는 안전한 대안을 사용하세요.",
                        references=["OWASP Code Injection Prevention"],
                        meta={
                            "engine": "pattern",
                            "function_risk": "eval()은 임의 코드 실행 공격에 취약합니다.",
                            "safe_alternatives": "JSON.parse(), Function 생성자 대신 안전한 파서 사용"
                        }
                    ))
            
            # Pattern: Dangerous innerHTML (enhanced)
            for i, line in enumerate(lines, 1):
                if '.innerHTML =' in line:
                    findings.append(Finding(
                        id="VSH-JS-INNERHTML-001",
                        title="XSS 위험: innerHTML이 사용자 입력을 직접 삽입합니다.",
                        severity="HIGH",
                        cwe="CWE-79",
                        cvss=8.2,
                        file=str(f.relative_to(project_root)),
                        line=i,
                        message="XSS 위험: innerHTML이 사용자 입력을 직접 삽입합니다.",
                        recommendation="element.textContent = input; 또는 element.innerText = input;로 변경하세요.",
                        references=["OWASP XSS Prevention Cheat Sheet"],
                        meta={
                            "engine": "pattern",
                            "function_risk": "innerHTML 속성은 XSS 공격에 취약합니다.",
                            "safe_alternatives": "textContent, innerText, 또는 DOM API 사용"
                        }
                    ))
            
            # Pattern: Dangerous document.write
            for i, line in enumerate(lines, 1):
                if 'document.write(' in line:
                    findings.append(Finding(
                        id="VSH-JS-DOCUMENT-WRITE-001",
                        title="XSS 위험: document.write()가 사용자 입력을 직접 출력합니다.",
                        severity="HIGH",
                        cwe="CWE-79",
                        cvss=7.8,
                        file=str(f.relative_to(project_root)),
                        line=i,
                        message="XSS 위험: document.write()가 사용자 입력을 직접 출력합니다.",
                        recommendation="document.write() 대신 DOM API를 사용하세요.",
                        references=["OWASP XSS Prevention Cheat Sheet"],
                        meta={
                            "engine": "pattern",
                            "function_risk": "document.write()는 XSS 공격에 취약합니다.",
                            "safe_alternatives": "innerHTML, textContent, 또는 DOM 조작 메소드"
                        }
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

