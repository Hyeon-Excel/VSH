import sqlite3
import subprocess

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout
