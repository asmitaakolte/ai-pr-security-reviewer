"""
sample-app/app.py  --  INTENTIONALLY VULNERABLE demo code.

This file exists ONLY so the security scanners (Bandit + Trivy) have real
findings to report, which the AI reviewer then explains. Every issue below is a
deliberate, classic example. Do NOT deploy or reuse any of this code.
"""
import hashlib
import subprocess

# Deliberate finding: hardcoded secret (Bandit B105 / B106).
API_KEY = "sk_live_hardcoded_secret_do_not_do_this_123456"


def hash_password(password: str) -> str:
    # Deliberate finding: weak hashing algorithm for passwords (Bandit B324).
    return hashlib.md5(password.encode()).hexdigest()


def get_user(conn, username: str):
    # Deliberate finding: SQL injection via string formatting (Bandit B608).
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return conn.execute(query).fetchall()


def run_report(filename: str):
    # Deliberate finding: shell=True with concatenated input (Bandit B602).
    return subprocess.call("cat " + filename, shell=True)
# trigger security review

