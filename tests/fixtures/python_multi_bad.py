import sqlite3

API_KEY = "sk_test_1234567890abcdef"


def search_user(conn: sqlite3.Connection, username: str):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()
