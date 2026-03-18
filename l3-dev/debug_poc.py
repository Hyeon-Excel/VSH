# debug_poc.py
import subprocess
import time

print("[1] 컨테이너 시작")
proc = subprocess.Popen(
    [
        'docker', 'run', '--rm', '-i',
        '--network', 'none',
        '--memory', '128m',
        '--cpus', '0.5',
        '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges',
        'vsh-poc-target'
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

print("[2] READY 신호 대기")
first_line = proc.stdout.readline().decode().strip()
print(f"    수신: '{first_line}'")

if first_line != 'READY':
    print(f"[오류] READY 아님: '{first_line}'")
    proc.kill()
    exit(1)

print("[3] 페이로드 전송")
payload = "' OR '1'='1\n"
proc.stdin.write(payload.encode())
proc.stdin.flush()
print(f"    전송: {repr(payload)}")

print("[4] 결과 수신 대기")
output = proc.stdout.readline().decode().strip()
print(f"    수신: '{output}'")

proc.wait()
print(f"[5] 종료 코드: {proc.returncode}")

stderr_output = proc.stderr.read().decode()
if stderr_output:
    print(f"[stderr]\n{stderr_output}")