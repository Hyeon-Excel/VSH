# 보안 테스트 파일
import sqlite3

# 하드코딩된 API 키
API_KEY = "sk_test_1234567890abcdef"

# 평문 비밀번호
password = "admin123"

def test_weakness():
    """SQL injection 취약점이 있는 함수"""
    user_input = "'; DROP TABLE users; --"
    query = "SELECT * FROM users WHERE id = " + user_input
    return query
