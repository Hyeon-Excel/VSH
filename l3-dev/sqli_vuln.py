# sqli_vuln.py — SonarQube CWE-89 탐지용 취약 코드
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE id=" + user_id
    )
    return str(cursor.fetchall())

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username='"
    query += username + "' AND password='" + password + "'"
    cursor.execute(query)
    return str(cursor.fetchone())