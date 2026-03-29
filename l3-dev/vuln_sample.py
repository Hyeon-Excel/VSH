# vuln_sample.py
# 포함된 취약점:
#   CWE-89: SQL Injection     (SonarQube 규칙: python:S3649)
#   CWE-78: OS Cmd Injection  (SonarQube 규칙: python:S2076)

import sqlite3
import os

def get_user(username):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username='" + username + "'"
    )
    return cursor.fetchall()

def run_command(user_input):
    os.system(user_input)