import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()
