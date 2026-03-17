import sys
import sqlite3
from routes.sqli import check_sqli

def init_db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'secret123')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'pass456')")
    conn.commit()
    return conn

def main():
    conn = init_db()
    
    sys.stdout.write("READY\n")
    sys.stdout.flush()
    
    payload = sys.stdin.readline().strip()
    result = check_sqli(conn, payload)
    
    if result:
        sys.stdout.write("VULNERABLE\n")
    else:
        sys.stdout.write("SAFE\n")
    sys.stdout.flush()
    
    conn.close()

if __name__ == "__main__":
    main()