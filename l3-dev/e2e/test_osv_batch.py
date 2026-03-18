import urllib.request
import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

url = "https://api.osv.dev/v1/querybatch"
payload = {
    "queries": [
        {"package": {"name": "PyYAML", "ecosystem": "PyPI"}, "version": "5.3.1"},
        {"package": {"name": "numpy", "ecosystem": "PyPI"}, "version": "1.24.0"},
        {"package": {"name": "pillow", "ecosystem": "PyPI"}, "version": "9.4.0"},
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.28.0"},
    ]
}

data = json.dumps(payload).encode("utf-8")
req = urllib.request.Request(
    url,
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST"
)

with urllib.request.urlopen(req) as response:
    result = json.loads(response.read().decode("utf-8"))

responses = result.get("results", [])
packages = ["PyYAML", "numpy", "pillow", "requests"]

for pkg, res in zip(packages, responses):
    vulns = res.get("vulns", [])
    print(f"{pkg}: {len(vulns)}개 취약점")
    for v in vulns:
        aliases = v.get("aliases", [])
        cves = [a for a in aliases if a.startswith("CVE")]
        severity = v.get("database_specific", {}).get("severity", "없음")
        print(f"  CVE: {cves} 심각도: {severity}")
