import reqeusts
from flask import request

def search(cursor):
    user_input = request.args.get('q')
    # ⚠️ [VSH-L1] SQLI 탐지
    # Severity: CRITICAL
    # CWE: CWE-89
    # Reachability: true
    # KISA: 입력데이터 검증 및 표현 1항
    # OWASP: A03:2021
    # Fix: query = "SELECT * FROM users WHERE id = %s"; cursor.execute(query, (user_input,))
    query = f'SELECT * FROM users WHERE id = {user_input}'
    cursor.execute(query)
    
    # XSS vulnerability
    output = f'<div>Hello {user_input}</div>'
    return output
