from pathlib import Path

_BASE = Path(__file__).parent
_CACHE = _BASE / "payloads"

class TemplateRegistry:
    FILE_MAP = {
        "CWE-89": "SQL Injection/Intruder/Auth_Bypass.txt",
        "CWE-79": "XSS Injection/Intruders/IntrudersXSS.txt",
        "CWE-78": "Command Injection/Intruder/command_exec.txt",
    }

    @staticmethod
    def load(cwe_id: str, max_payloads: int = 50) -> list[str]:
        try:
            relative_path_str = TemplateRegistry.FILE_MAP.get(cwe_id)
            if not relative_path_str:
                return []
                
            # Path 객체에 문자열을 그대로 넘기면 OS에 따라 슬래시 처리 문제가 발생할 수 있으므로
            # split("/")을 통해 각각의 파트를 넘겨 안전하게 조합합니다.
            cache_file = _CACHE.joinpath(*relative_path_str.split("/"))
            
            if not cache_file.exists():
                return []
                
            text = cache_file.read_text(encoding="utf-8")
            lines = text.splitlines()
            
            # 필터링: 빈 줄 및 주석 제거
            filtered_payloads = [
                l.strip() for l in lines 
                if l.strip() and not l.strip().startswith("#")
            ]
            
            # 슬라이싱
            return filtered_payloads[:max_payloads]
            
        except Exception:
            return []

