# test_vuln.py
import sqlite3

def get_user(username):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # 문자열 연결 방식 - SonarQube SQLi 규칙에 탐지됨
    cursor.execute(
        "SELECT * FROM users WHERE username='" + username + "'"
    )
    return cursor.fetchall()