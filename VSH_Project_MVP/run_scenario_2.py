from dotenv import load_dotenv
load_dotenv()
from pipeline import PipelineFactory

print("--- Step 7. 수정된 파일 재스캔 ---")
pipeline = PipelineFactory.create()
result = pipeline.run("tests/e2e_target_fixed.py")

print(f"is_clean : {result['is_clean']}")
print(f"취약점 수: {len(result['scan_results'])}")

cwe_ids = [v['cwe_id'] for v in result['scan_results']]
print(f"탐지된 CWE: {cwe_ids}")

if "CWE-89" not in cwe_ids and "CWE-798" not in cwe_ids:
    print("[PASS] CWE-89 및 CWE-798이 제거됨을 확인했습니다.")
else:
    print("[FAIL] 취약점이 아직 남아있습니다.")
