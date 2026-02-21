import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    query = "SELECT * FROM users WHERE username = ?"
    return conn.execute(query, (username,)).fetchall()
