import asyncio
import subprocess
from l3.providers.base import AbstractPoCProvider
from l3.schema import VulnRecord
from l3.llm.base import LLMAdapter

class RealPoCProvider(AbstractPoCProvider):

    DOCKER_IMAGE = "vsh-poc-target"

    TEMPLATE_MAP = {
        "CWE-89": "sqli_basic",
    }

    PAYLOAD_MAP = {
        "sqli_basic": ["' OR '1'='1"],
    }

    SUCCESS_PATTERN = {
        "sqli_basic": "VULNERABLE",
    }

    def __init__(self, llm: LLMAdapter) -> None:
        self.llm = llm

    def _select_template(self, cwe_id: str) -> str | None:
        return self.TEMPLATE_MAP.get(cwe_id)

    def _load_payloads(self, template_name: str) -> list[str]:
        return self.PAYLOAD_MAP.get(template_name, [])

    async def _run_poc(self, payload: str) -> bool:
        proc = None
        try:
            cmd = [
                "docker", "run", "--rm", "-i",
                "--network", "none",
                "--memory", "128m",
                "--cpus", "0.5",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                self.DOCKER_IMAGE
            ]
            
            proc = await asyncio.to_thread(
                lambda: subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            )
            
            first_line = await asyncio.to_thread(
                lambda: proc.stdout.readline().decode().strip()
            )
            if first_line != "READY":
                return False
                
            await asyncio.to_thread(
                lambda: proc.stdin.write(
                    (payload + "\n").encode()
                )
            )
            await asyncio.to_thread(lambda: proc.stdin.flush())
            
            output = await asyncio.to_thread(
                lambda: proc.stdout.readline().decode().strip()
            )
            return output == "VULNERABLE"
            
        except Exception as e:
            print(f"[L3 PoC] _run_poc 예외: {e}")
            return False
        finally:
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass

    async def verify(self, record: VulnRecord) -> VulnRecord:
        try:
            if not record.cwe_id:
                record.status = "poc_skipped"
                return record
                
            template_name = self._select_template(record.cwe_id)
            if template_name is None:
                print(f"[L3 PoC] 템플릿 없음: {record.cwe_id}")
                record.status = "poc_skipped"
                return record
                
            payloads = self._load_payloads(template_name)
            if not payloads:
                record.status = "poc_skipped"
                return record
                
            for payload in payloads:
                result = await self._run_poc(payload)
                if result:
                    record.status = "poc_verified"
                    return record
            
            record.status = "poc_failed"
            return record
            
        except Exception as e:
            print(f"[L3 PoC] verify 예외: {e}")
            record.status = "scan_error"
            return record
