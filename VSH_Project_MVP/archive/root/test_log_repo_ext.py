import os
from dotenv import load_dotenv

load_dotenv()

from pipeline import PipelineFactory

def test_log_repo_extension():
    pipeline = PipelineFactory.create()
    result = pipeline.run("test_vuln.py")

    logs = pipeline.log_repo.find_all()

    assert len(logs) > 0, "log.json에 저장된 데이터가 없음"

    for log in logs:
        # 이전에 기록된 로그(original_code 필드가 없는 옛날 데이터)는 건너뛸 수도 있으나,
        # run()을 방금 실행했으므로 덮어쓰기/추가되었을 것입니다.
        assert "original_code" in log, f"original_code 필드 없음: {log['issue_id']}"
        assert "fixed_code" in log, f"fixed_code 필드 없음: {log['issue_id']}"
        assert log["original_code"] != "", f"original_code가 비어있음: {log['issue_id']}"
        assert log["fixed_code"] != "", f"fixed_code가 비어있음: {log['issue_id']}"
        
        print(f"issue_id     : {log['issue_id']}")
        # 문자열 슬라이싱 안전하게 처리
        orig_code = log.get('original_code', '')
        fix_code = log.get('fixed_code', '')
        print(f"original_code: {orig_code[:50]}...")
        print(f"fixed_code   : {fix_code[:50]}...")
        print("---")

    print("사전 작업 완료: original_code, fixed_code 저장 확인")

if __name__ == "__main__":
    test_log_repo_extension()
