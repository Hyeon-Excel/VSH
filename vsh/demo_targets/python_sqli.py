from flask import request

def search(cursor):
    user_input = request.args.get("q")
    query = f"SELECT * FROM users WHERE id={user_input}"
    cursor.execute(query)
