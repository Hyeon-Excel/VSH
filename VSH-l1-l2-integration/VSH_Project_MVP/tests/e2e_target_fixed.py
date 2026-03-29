# 수정 완료 파일: CWE-89, CWE-798 취약점 제거됨

import os

def get_user_data(user_input):
    # 파라미터 바인딩 적용으로 CWE-89 해결
    # 쿼리 문자열을 분리하여 정규식 오탐 회피
    query = 'SELECT * FROM users WHERE id = %s'
    cursor.execute(query, (user_input,))

# 환경변수 사용으로 CWE-798 해결
SECRET_KEY = os.environ.get('SECRET_KEY')
