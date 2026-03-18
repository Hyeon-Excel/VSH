import urllib.request
import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

url = "https://api.osv.dev/v1/query"
payload = {
    "package": {
        "name": "PyYAML",
        "ecosystem": "PyPI"
    },
    "version": "5.3.1"
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

vulns = result.get("vulns", [])
print(f"발견된 취약점 수: {len(vulns)}개")
for v in vulns:
    print(f"  ID: {v['id']}")
    aliases = v.get("aliases", [])
    cves = [a for a in aliases if a.startswith("CVE")]
    print(f"  CVE: {cves}")
    severity = v.get("database_specific", {}).get("severity", "없음")
    print(f"  심각도: {severity}")
    print()