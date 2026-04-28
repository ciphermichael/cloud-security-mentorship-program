"""
Deliberately Vulnerable Python Web App — for DevSecOps pipeline testing.
This file INTENTIONALLY contains security vulnerabilities for educational purposes.
NEVER deploy this to production.

Vulnerabilities included (for pipeline to detect):
  - SQL injection (Bandit B608)
  - Command injection (Bandit B602, B605)
  - MD5 password hashing (Bandit B303)
  - Hardcoded secret (Bandit B105, Gitleaks)
  - Use of eval() (Bandit B307)
  - XML External Entity (Bandit B313)
"""
import sqlite3
import subprocess
import hashlib
import os

from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILITY: Hardcoded secret key — Gitleaks / detect-secrets will catch this
SECRET_KEY = "hardcoded-secret-key-do-not-use-in-prod-12345"
DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route('/users')
def get_users():
    # VULNERABILITY: SQL injection — Bandit B608, Semgrep sql-injection
    username = request.args.get('username', '')
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())


@app.route('/ping')
def ping():
    # VULNERABILITY: OS command injection — Bandit B602
    host = request.args.get('host', 'localhost')
    output = subprocess.check_output(f'ping -c 1 {host}', shell=True)
    return output.decode()


@app.route('/register', methods=['POST'])
def register():
    # VULNERABILITY: MD5 for password hashing — Bandit B303
    data = request.get_json()
    password = data.get('password', '')
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({'hash': hashed})


@app.route('/calculate')
def calculate():
    # VULNERABILITY: eval() — Bandit B307
    expr = request.args.get('expr', '1+1')
    result = eval(expr)
    return jsonify({'result': result})


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'version': '1.0.0'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
