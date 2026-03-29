#!/bin/bash
# VSH L3 — RULES.md 핵심 규칙 자동 검증 Hook
# BeforeTool: write_file / replace 직전에 실행
# 위반 감지 시 파일 저장 차단

# stdin에서 Gemini CLI가 보내는 JSON 읽기
INPUT=$(cat)

# 저장하려는 파일 내용 추출
CONTENT=$(echo "$INPUT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
args = data.get('tool_input', {})
print(args.get('content', args.get('new_str', '')))" 2>/dev/null)

# 저장 대상 파일 경로 추출
FILE_PATH=$(echo "$INPUT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
args = data.get('tool_input', {})
print(args.get('path', ''))" 2>/dev/null)

VIOLATIONS=""

# R3: severity를 cvss_score에서 파생 금지
if echo "$CONTENT" | grep -qE "cvss_score\s*>=|cvss_score\s*>|cvss_score\s*<="; then
    VIOLATIONS="${VIOLATIONS}\n[R3 위반] severity를 cvss_score에서 파생하고 있습니다."
fi

# R4: fss_ref 빈 문자열 직접 대입 금지
if echo "$CONTENT" | grep -qE 'fss_ref\s*=\s*""'; then
    VIOLATIONS="${VIOLATIONS}\n[R4 위반] fss_ref에 빈 문자열을 직접 대입하고 있습니다. None을 사용하거나 __post_init__에서 변환하세요."
fi

# R2: pipeline.py에서 구체 클래스 직접 import 금지
if echo "$FILE_PATH" | grep -q "pipeline.py"; then
    if echo "$CONTENT" | grep -qE "from l3.providers\.(sonarqube|sbom|poc)\.(mock|real) import"; then
        VIOLATIONS="${VIOLATIONS}\n[R2 위반] pipeline.py에서 구체 클래스를 직접 import하고 있습니다. DI 패턴을 사용하세요."
    fi
fi

# R7: exploit 코드 문자열을 DB 저장 금지
if echo "$CONTENT" | grep -qE "get_exploit_code\(\).*db\.|db\.write.*exploit"; then
    VIOLATIONS="${VIOLATIONS}\n[R7 위반] exploit 코드를 DB에 저장하려 하고 있습니다."
fi

# R10: PackageRecord source 고정값 변경 금지
if echo "$CONTENT" | grep -qE 'class PackageRecord' ; then
    if echo "$CONTENT" | grep -qE 'source\s*=\s*"(?!L3_SBOM)'; then
        VIOLATIONS="${VIOLATIONS}\n[R10 위반] PackageRecord의 source는 'L3_SBOM' 고정값입니다."
    fi
fi

# 위반 있으면 차단
if [ -n "$VIOLATIONS" ]; then
    echo $(python3 -c "
import json
msg = '''RULES.md 위반이 감지되어 파일 저장을 차단합니다:
$(echo -e "$VIOLATIONS")

수정 후 다시 시도해주세요. RULES.md를 참조하세요.'''
print(json.dumps({'decision': 'block', 'reason': msg}))
")
    exit 0
fi

# 위반 없으면 통과
echo '{"decision": "allow"}'
exit 0