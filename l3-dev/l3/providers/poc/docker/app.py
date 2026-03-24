import sys
import sqlite3
import functools
from routes.sqli import check_sqli
from routes.cmdi import check_cmdi
from routes.xss import check_xss

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

    DISPATCHER = {
        "CWE-89": functools.partial(check_sqli, conn),
        "CWE-78": check_cmdi,
        "CWE-79": check_xss,
    }

    sys.stdout.write("READY\n")
    sys.stdout.flush()

    line = sys.stdin.readline().strip()
    if "|" in line:
        cwe_id, payload = line.split("|", 1)
    else:
        cwe_id = "UNKNOWN"
        payload = line

    check_func = DISPATCHER.get(cwe_id)

    if check_func:
        result = check_func(payload)
    else:
        result = False

    if result:
        sys.stdout.write("VULNERABLE\n")
    else:
        sys.stdout.write("SAFE\n")
    sys.stdout.flush()

    conn.close()

if __name__ == "__main__":
    main()
