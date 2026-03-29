import asyncio
import subprocess
from l3.providers.base import AbstractPoCProvider
from l3.schema import VulnRecord
from l3.llm.base import LLMAdapter
from l3.providers.poc.template_registry import TemplateRegistry

class RealPoCProvider(AbstractPoCProvider):

    DOCKER_IMAGE = "vsh-poc-target"

    def __init__(self, llm: LLMAdapter) -> None:
        self.llm = llm

    def _load_payloads(self, cwe_id: str) -> list[str]:
        return TemplateRegistry.load(cwe_id)

    async def _run_poc(self, cwe_id: str, payload: str) -> bool:
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
                    (f"{cwe_id}|{payload}\n").encode()
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
                
            payloads = self._load_payloads(record.cwe_id)
            if not payloads:
                record.status = "poc_skipped"
                return record
                
            for payload in payloads:
                result = await self._run_poc(record.cwe_id, payload)
                if result:
                    record.status = "poc_verified"
                    return record
            
            record.status = "poc_failed"
            return record
            
        except Exception as e:
            print(f"[L3 PoC] verify 예외: {e}")
            record.status = "scan_error"
            return record
