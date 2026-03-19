import json
import subprocess
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from l3.models.package_record import PackageRecord
from l3.providers.base import AbstractSBOMProvider

class RealSBOMProvider(AbstractSBOMProvider):

    async def scan(self, project_path: str) -> List[PackageRecord]:
        packages = self._run_syft(project_path)
        if not packages:
            return []
            
        vuln_map = self._query_osv_batch(packages)
        if not vuln_map:
            return []
            
        results = []
        for pkg in packages:
            pkg_name = pkg["name"]
            if pkg_name in vuln_map:
                vuln_ids = vuln_map[pkg_name]
                vulns = self._get_vuln_details(pkg, vuln_ids)
                for vuln in vulns:
                    record = self._build_record(pkg, vuln)
                    results.append(record)
                    
        return results

    def _run_syft(self, project_path: str) -> List[dict]:
        try:
            scan_dir = str(Path(project_path).parent)
            result = subprocess.run(
                ["syft", scan_dir, "-o", "json"],
                capture_output=True, text=True, timeout=60
            )
            data = json.loads(result.stdout)
            
            packages = []
            for artifact in data.get("artifacts", []):
                if artifact.get("type", "").lower() == "python" and artifact.get("name") and artifact.get("version"):
                    packages.append({
                        "name": artifact["name"],
                        "version": artifact["version"],
                        "ecosystem": "PyPI"
                    })
            return packages
        except Exception:
            return []

    def _query_osv_batch(self, packages: List[dict]) -> Dict[str, List[str]]:
        try:
            payload = {
                "queries": [
                    {
                        "package": {
                            "name": pkg["name"],
                            "ecosystem": "PyPI"
                        },
                        "version": pkg["version"]
                    }
                    for pkg in packages
                ]
            }
            
            url = "https://api.osv.dev/v1/querybatch"
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            
            with urllib.request.urlopen(req) as response:
                result_data = json.loads(response.read().decode("utf-8"))
                
            vuln_map = {}
            for pkg, result in zip(packages, result_data.get("results", [])):
                vuln_ids = [v["id"] for v in result.get("vulns", [])]
                if vuln_ids:
                    vuln_map[pkg["name"]] = vuln_ids
                    
            return vuln_map
        except Exception:
            return {}

    def _get_vuln_details(self, pkg: dict, vuln_ids: List[str]) -> List[dict]:
        results = []
        seen_cves = set()
        
        ALLOWED = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        
        for vuln_id in vuln_ids:
            try:
                url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req) as resp:
                    vuln = json.loads(resp.read().decode("utf-8"))
                    
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                
                if cve_id:
                    if cve_id in seen_cves:
                        continue
                    seen_cves.add(cve_id)
                
                severity = "LOW"
                db_severity = vuln.get(
                    "database_specific", {}
                ).get("severity", "")
                if db_severity.upper() in ALLOWED:
                    severity = db_severity.upper()

                cvss_score = None
                
                results.append({
                    "cve_id": cve_id,
                    "severity": severity,
                    "cvss_score": cvss_score
                })

            except Exception:
                continue
                
        return results

    def _build_record(self, pkg: dict, vuln: dict) -> PackageRecord:
        name = pkg["name"]
        version = pkg["version"]
        cve_id = vuln.get("cve_id")
        
        if cve_id:
            package_id = f"PKG-{name}-{version}-{cve_id}"
        else:
            package_id = f"PKG-{name}-{version}"
            
        return PackageRecord(
            package_id=package_id,
            detected_at=datetime.now().isoformat(),
            name=name,
            version=version,
            ecosystem="PyPI",
            cve_id=cve_id,
            severity=vuln["severity"],
            cvss_score=vuln.get("cvss_score"),
            license=None,
            license_risk=False,
            status="upgrade_required",
            code_snippet=f"requirements.txt: {name}=={version}",
            fix_suggestion="최신 버전으로 업그레이드하세요"
        )
