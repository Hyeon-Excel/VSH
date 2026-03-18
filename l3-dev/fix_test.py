# fix_test.py
with open('tests/test_week1_e2e.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    '"VSH 보안 스캔 리포트" in content',
    '"VSH 보안 진단 리포트" in content'
)
content = content.replace(
    '"스캔 요약" in content',
    '"종합 보안 점수" in content'
)

with open('tests/test_week1_e2e.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('수정 완료')