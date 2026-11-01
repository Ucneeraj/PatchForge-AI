# sample_vulnerable.py
#
# Guaranteed to trigger PatchForge-AI's two currently-supported rules.
# Use this to confirm the pipeline itself works before testing against
# real-world repos, which may use vulnerability patterns outside the
# current rule set (e.g. string concatenation instead of f-strings,
# or a query built in a separate variable before .execute()) -- those
# correctly return zero findings right now; that's a detection-scope
# limitation, not a bug. Widening the rule set is future work.

import sqlite3

secret = "sk-test-1234567890"

def get_user(conn, username):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cur.fetchone()
