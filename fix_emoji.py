with open('l3-dev/l3/pdf_generator.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_block = [
    '_EMOJI_RE = re.compile(\n',
    '    "["\n',
    '    "\\U0001F600-\\U0001F64F"\n',
    '    "\\U0001F300-\\U0001F5FF"\n',
    '    "\\U0001F680-\\U0001F6FF"\n',
    '    "\\U0001F900-\\U0001F9FF"\n',
    '    "\\U0001FA00-\\U0001FA6F"\n',
    '    "\\U0001FA70-\\U0001FAFF"\n',
    '    "\\u2705\\u274C\\u26A0\\u2714\\u2716\\u2753\\u2754\\u2755"\n',
    '    "\\u2640-\\u2642\\u2600-\\u26FF"\n',
    '    "]",\n',
    '    flags=re.UNICODE,\n',
    ')\n',
]

# _EMOJI_RE 블록 시작/끝 줄 번호 찾기
start_idx = None
end_idx = None
for i, line in enumerate(lines):
    if '_EMOJI_RE = re.compile(' in line:
        start_idx = i
    if start_idx is not None and i > start_idx and line.strip() == ')':
        end_idx = i
        break

if start_idx is None or end_idx is None:
    print('블록을 찾지 못했습니다.')
    print('start_idx:', start_idx, 'end_idx:', end_idx)
else:
    new_lines = lines[:start_idx] + new_block + lines[end_idx+1:]
    with open('l3-dev/l3/pdf_generator.py', 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    print('교체 완료')
    print('교체된 줄 범위:', start_idx+1, '~', end_idx+1)

# 검증
import re
with open('l3-dev/l3/pdf_generator.py', 'r', encoding='utf-8') as f:
    content = f.read()

exec(compile('import re\n' + content[content.find('_EMOJI_RE'):content.find('\n_EMOJI_RE')+50], '<test>', 'exec'))

test = '진단일시 : 2026-03-28 23:25'
result = _EMOJI_RE.sub('', test)
print('입력:', test)
print('출력:', result)
assert '진단일시' in result, '한글 제거됨 - 실패'
print('assert 통과 - 한글 보존됨')