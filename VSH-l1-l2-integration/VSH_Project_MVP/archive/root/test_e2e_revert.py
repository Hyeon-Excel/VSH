from dotenv import load_dotenv
load_dotenv()
from pipeline import PipelineFactory

# 취약 파일 → CWE-89 탐지 확인
pipeline = PipelineFactory.create()
result = pipeline.run("tests/e2e_target.py")
cwe_ids = [v['cwe_id'] for v in result['scan_results']]
assert "CWE-89" in cwe_ids, "CWE-89 탐지 실패. e2e_target.py 패턴 확인 필요"
print(f"취약 파일 탐지된 CWE: {cwe_ids}")

# 수정된 파일 → CWE-89 미탐지 확인
pipeline2 = PipelineFactory.create()
result2 = pipeline2.run("tests/e2e_target_fixed.py")
cwe_ids2 = [v['cwe_id'] for v in result2['scan_results']]
assert "CWE-89" not in cwe_ids2, "CWE-89 오탐 발생. e2e_target_fixed.py 패턴 확인 필요"
assert "CWE-798" not in cwe_ids2, "CWE-798 오탐 발생. e2e_target_fixed.py 패턴 확인 필요"
print(f"수정 파일 탐지된 CWE: {cwe_ids2}")

print("knowledge.json 원래 패턴 유지 확인 완료")
