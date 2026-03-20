import urllib.request
import urllib.parse
from pathlib import Path

_BASE = Path(__file__).parent
_CACHE = _BASE / "payloads"

class TemplateRegistry:
    CWE_TO_FOLDER = {
        "CWE-89": "SQL Injection",
        # "CWE-79": "XSS Injection",       # 추후 확장
        # "CWE-78": "Command Injection",    # 추후 확장
        # "CWE-22": "Path Traversal",       # 추후 확장
    }

    FILE_NAME_MAP = {
        "SQL Injection": "Auth_Bypass.txt",
        # 추후 CWE 추가 시 여기에 파일명 함께 추가
    }

    BASE_URL = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"

    @staticmethod
    def load(cwe_id: str) -> list[str]:
        try:
            folder_name = TemplateRegistry.CWE_TO_FOLDER.get(cwe_id)
            if not folder_name:
                return []
                
            file_name = TemplateRegistry.FILE_NAME_MAP.get(folder_name)
            if not file_name:
                return []
                
            cache_file = _CACHE / folder_name / "Intruder" / file_name
            
            if not cache_file.exists():
                encoded_folder = urllib.parse.quote(folder_name, safe="")
                url = f"{TemplateRegistry.BASE_URL}/{encoded_folder}/Intruder/{file_name}"
                
                with urllib.request.urlopen(url) as response:
                    data = response.read()
                    
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_bytes(data)
                
            text = cache_file.read_text(encoding="utf-8")
            lines = text.splitlines()
            payloads = [l.strip() for l in lines if l.strip() != ""]
            return payloads
            
        except Exception:
            return []
