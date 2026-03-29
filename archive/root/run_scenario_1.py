from dotenv import load_dotenv
load_dotenv()
from pipeline import PipelineFactory

pipeline = PipelineFactory.create()
result = pipeline.run("tests/e2e_target.py")

print(f"is_clean : {result['is_clean']}")
print(f"취약점 수: {len(result['scan_results'])}")
print(f"수정 제안 수: {len(result['fix_suggestions'])}")

cwe_ids = [v['cwe_id'] for v in result['scan_results']]
print(f"탐지된 CWE: {cwe_ids}")

print("\n--- LogRepo 상태 확인 ---")
logs = pipeline.log_repo.find_all()
for log in logs:
    print(f"issue_id: {log['issue_id']}")
    print(f"status  : {log['status']}")
    print(f"original_code: {log.get('original_code','')[:50]}...")
    print(f"fixed_code   : {log.get('fixed_code','')[:50]}...")
    print("---")
