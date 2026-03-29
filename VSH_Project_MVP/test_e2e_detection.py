from dotenv import load_dotenv
load_dotenv()
from pipeline import PipelineFactory

pipeline = PipelineFactory.create()
result = pipeline.run("tests/e2e_target.py")

print(f"is_clean : {result['is_clean']}")
cwe_ids = [v['cwe_id'] for v in result['scan_results']]
print(f"탐지된 CWE 목록: {cwe_ids}")

assert "CWE-89" in cwe_ids, "CWE-89 탐지 실패. e2e_target.py 패턴 확인 필요"
assert "CWE-798" in cwe_ids, "CWE-798 탐지 실패. knowledge.json 패턴 확인 필요"

print("CWE-89, CWE-798 탐지 확인 완료")
