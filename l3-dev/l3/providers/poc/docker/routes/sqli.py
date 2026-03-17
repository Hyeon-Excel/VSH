def check_sqli(conn, payload: str) -> bool:
    try:
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{payload}'"
        cursor.execute(query)
        results = cursor.fetchall()
        
        if len(results) >= 2:
            return True
        return False
    except Exception:
        return False