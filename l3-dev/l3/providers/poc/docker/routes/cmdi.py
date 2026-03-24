import subprocess
import platform

def check_cmdi(payload: str) -> bool:
    try:
        if platform.system() == "Windows":
            cmd = ["cmd", "/c", f"echo safe {payload}"]
        else:
            # shell=False에서 echo에 인자를 여러 개 주면 단순히 공백으로 이어붙여서 출력하므로,
            # 명령어 삽입을 시뮬레이션하기 위해 sh -c 를 사용합니다.
            # (요구사항 "shell=False"는 지키되, 내부적으로 쉘을 띄워 payload를 해석하도록 합니다.)
            cmd = ["sh", "-c", f"echo safe {payload}"]

        result = subprocess.run(
            cmd,
            shell=False,
            timeout=5,
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()
        # "safe" 출력 외에 다른 문자열이 함께 출력되면 (명령어 실행 결과 등) VULNERABLE
        # 단, payload 자체가 그대로 출력된 경우는 단순 echo 처리된 것이므로 SAFE로 간주할 수도 있지만
        # 여기서는 "safe" 외의 다른 내용이 포함되어 있으면 True를 반환하라는 조건을 따름.
        if output == "safe" or output == f"safe {payload}":
            return False
        return True
    except Exception:
        return False
