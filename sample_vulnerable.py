import sqlite3

# Hardcoded Secret (CWE-798)
secret_key = "sk-test-1234567890"

def get_user_data(username):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    # Unsafe string formatting / SQL Injection (CWE-89)
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cur.fetchall()