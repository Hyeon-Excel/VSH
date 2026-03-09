# 취약점 포함 파일: SQL Injection (CWE-89), 하드코딩된 시크릿 키 (CWE-798)

def get_user_data(user_input):
    # CWE-89 취약점 발생 (SQL Injection)
    cursor.execute('SELECT * FROM users WHERE id = %s' % user_input)

# CWE-798 취약점 발생 (Hardcoded Secret Key)
SECRET_KEY = 'supersecretkey123'
