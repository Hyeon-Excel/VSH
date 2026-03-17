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
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

proc.stdout.readline()
proc.stdin.write(b'admin\n')
proc.stdin.flush()

result = proc.stdout.readline().decode().strip()
print(f'정상 페이로드 결과: {result}')
assert result == 'SAFE', f'예상과 다름: {result}'

proc.wait()
print('SAFE 검증 성공')