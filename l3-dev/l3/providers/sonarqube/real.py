import os
import asyncio
import subprocess
import uuid
import time
from datetime import datetime,timezone
import requests
from requests.auth import HTTPBasicAuth
from l3.providers.base import AbstractSonarQubeProvider
from l3.schema import VulnRecord
from l3.llm.base import LLMAdapter

class RealSonarQubeProvider(AbstractSonarQubeProvider):
    def __init__(self, llm: LLMAdapter):
        self.llm = llm
        self.sonar_url = os.getenv("SONAR_URL", "https://sonarcloud.io")
        self.sonar_token = os.getenv("SONAR_TOKEN")
        self.sonar_org = os.getenv("SONAR_ORG")
        self.sonar_project_key = os.getenv("SONAR_PROJECT_KEY")
        self.auth = HTTPBasicAuth(self.sonar_token, "")

    async def scan(self, project_path: str) -> list[VulnRecord]:
        try:
            if not await self._health_check():
                return []
                
            await self._ensure_project()
            
            scan_start_time = datetime.now(timezone.utc)
            if not await self._run_scanner(project_path):
                return []
                
            if not await self._wait_for_analysis(scan_start_time):
                return []
                
            issues = await self._fetch_issues()
            if not issues:
                return []
                
            records = []
            for issue in issues:
                record = await self._build_vuln_record(issue)
                records.append(record)
                
            print(f"[L3 SonarQube] 스캔 완료: {len(records)}건")
            return records
        except Exception as e:
            print(f"[L3 SonarQube] 스캔 중 예외 발생: {str(e)}")
            return []

    async def _health_check(self) -> bool:
        try:
            url = f"{self.sonar_url}/api/system/status"
            response = await asyncio.to_thread(
                lambda: requests.get(url, auth=self.auth, timeout=10)
            )
            if response.status_code == 200 and response.json().get("status") == "UP":
                print("[L3 SonarQube] health check OK")
                return True
            print(f"[L3 SonarQube] health check FAILED: status={response.status_code}")
            return False
        except Exception as e:
            print(f"[L3 SonarQube] health check FAILED: {str(e)}")
            return False

    async def _ensure_project(self) -> None:
        try:
            url = f"{self.sonar_url}/api/projects/create"
            data = {
                "name": self.sonar_project_key,
                "project": self.sonar_project_key,
                "organization": self.sonar_org
            }
            response = await asyncio.to_thread(
                lambda: requests.post(url, data=data, auth=self.auth, timeout=10)
            )
            if response.status_code == 200:
                print("[L3 SonarQube] 프로젝트 생성 완료")
            elif response.status_code == 400 and "key already exists" in response.text:
                print("[L3 SonarQube] 프로젝트 이미 존재, skip")
            else:
                print(f"[L3 SonarQube] 프로젝트 등록 응답: {response.status_code}")
        except Exception as e:
            print(f"[L3 SonarQube] 프로젝트 등록 실패: {str(e)}")

    def _to_docker_path(self, path: str) -> str:
        import platform
        if platform.system() == "Windows":
            path = os.path.abspath(path)
            drive, rest = os.path.splitdrive(path)
            drive_letter = drive.replace(":", "").lower()
            rest = rest.replace("\\", "/").replace("\\", "/")
            return f"/{drive_letter}{rest}"
        return os.path.abspath(path)

    async def _run_scanner(self, project_path: str) -> bool:
        try:
            docker_path = self._to_docker_path(project_path)
            cmd = [
                "docker", "run", "--rm",
                "-e", f"SONAR_HOST_URL={self.sonar_url}",
                "-e", f"SONAR_TOKEN={self.sonar_token}",
                "-e", f"SONAR_SCANNER_OPTS="
                      f"-Dsonar.projectKey={self.sonar_project_key} "
                      f"-Dsonar.organization={self.sonar_org} "
                      f"-Dsonar.sources=.",
                "-v", f"{docker_path}:/usr/src",
                "sonarsource/sonar-scanner-cli"
            ]
            result = await asyncio.to_thread(
                lambda: subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300
                )
            )
            if result.returncode == 0:
                print("[L3 SonarQube] 스캐너 실행 완료")
                return True
            print(f"[L3 SonarQube] 스캐너 실행 실패: {result.returncode}")
            print(f"[L3 SonarQube] stdout: {result.stdout[-1000:]}")
            print(f"[L3 SonarQube] stderr: {result.stderr[-500:]}")
            return False
        except Exception as e:
            print(f"[L3 SonarQube] 스캐너 예외 발생: {str(e)}")
            return False

    async def _wait_for_analysis(self, scan_start_time: datetime, timeout: int = 120) -> bool:
        try:
            start = time.monotonic()
            url = f"{self.sonar_url}/api/ce/activity"
            params = {"component": self.sonar_project_key}

            while (time.monotonic() - start) < timeout:
                response = await asyncio.to_thread(
                    lambda: requests.get(url, params=params, auth=self.auth, timeout=10)
                )
                if response.status_code == 200:
                    data = response.json()
                    tasks = data.get("tasks", [])
                    for task in tasks:
                        submitted_str = task.get("submittedAt", "")
                        if not submitted_str:
                            continue
                        submitted = datetime.fromisoformat(
                            submitted_str.replace("+0000", "+00:00")
                        )
                        if submitted <= scan_start_time:
                            continue
                        status = task.get("status")
                        if status == "SUCCESS":
                            return True
                        elif status in ("FAILED", "CANCELLED"):
                            return False

                print("[L3 SonarQube] 분석 대기 중...")
                await asyncio.sleep(10)

            print("[L3 SonarQube] 분석 대기 timeout")
            return False
        except Exception as e:
            print(f"[L3 SonarQube] 분석 대기 예외 발생: {str(e)}")
            return False

    async def _fetch_issues(self) -> list:
        try:
            url = f"{self.sonar_url}/api/issues/search"
            params = {
                "componentKeys": self.sonar_project_key,
                "organization": self.sonar_org,
            }
            response = await asyncio.to_thread(
                lambda: requests.get(url, params=params, auth=self.auth, timeout=10)
            )
            if response.status_code == 200:
                issues = response.json().get("issues", [])
                print(f"[L3 SonarQube] 이슈 {len(issues)}건 발견")
                return issues
            print(f"[L3 SonarQube] 이슈 조회 실패: {response.status_code}")
            return []
        except Exception as e:
            print(f"[L3 SonarQube] 이슈 조회 예외 발생: {str(e)}")
            return []

    def _map_severity(self, sonar_severity: str) -> str:
        mapping = {
            "BLOCKER": "CRITICAL",
            "CRITICAL": "HIGH",
            "MAJOR": "MEDIUM",
            "MINOR": "LOW",
            "INFO": "LOW"
        }
        return mapping.get(sonar_severity.upper(), "LOW")

    def _error_vuln_record(self, issue: dict) -> VulnRecord:
        vuln_id = f"VSH-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"
        return VulnRecord(
            vuln_id=vuln_id,
            rule_id=issue.get("rule", "UNKNOWN"),
            source="L3_SONARQUBE",
            detected_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            file_path="unknown",
            line_number=0,
            end_line_number=0,
            column_number=0,
            end_column_number=0,
            language="unknown",
            code_snippet="scan_error",
            vuln_type="UNKNOWN",
            cwe_id="CWE-UNKNOWN",
            cve_id=None,
            cvss_score=None,
            severity="LOW",
            reachability_status="unknown",
            reachability_confidence="low",
            kisa_ref="KISA 시큐어코딩 가이드 참조",
            fss_ref=None,
            owasp_ref=None,
            fix_suggestion="scan_error",
            status="scan_error",
            action_at=None
        )

    async def _build_vuln_record(self, issue: dict) -> VulnRecord:
        try:
            rule_id = issue.get("rule", "UNKNOWN")
            sonar_sev = issue.get("severity", "INFO")
            file_path = issue.get("component", "unknown").split(":")[-1]
            line_number = issue.get("line", 0)
            message = issue.get("message", "")
            
            cwe_id = await self.llm.classify_cwe(rule_id, message)
            
            vuln_id = f"VSH-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"
            vuln_type = message.split()[0] if message else "UNKNOWN"
            
            return VulnRecord(
                vuln_id=vuln_id,
                rule_id=rule_id,
                source="L3_SONARQUBE",
                detected_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                file_path=file_path,
                line_number=line_number,
                end_line_number=line_number,
                column_number=issue.get("textRange", {}).get("startOffset", 0),
                end_column_number=issue.get("textRange", {}).get("endOffset", 0),
                language="unknown",
                code_snippet=message,
                vuln_type=vuln_type,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                severity=self._map_severity(sonar_sev),
                reachability_status="unknown",
                reachability_confidence="low",
                kisa_ref="KISA 시큐어코딩 가이드 참조",
                fss_ref=None,
                owasp_ref=None,
                fix_suggestion=f"SonarQube 규칙 {rule_id} 참조",
                status="pending",
                action_at=None
            )
        except Exception:
            return self._error_vuln_record(issue)
