from flask import Flask, request, redirect
import sqlite3
import subprocess
import os

app = Flask(__name__)

# VULN-001: Hardcoded credentials
DB_PASSWORD = "admin123"
SECRET_KEY = "hardcoded_secret_key_123"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    # VULN-002: SQL injection via string concatenation
    conn = sqlite3.connect('users.db')
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    conn.execute(query)
    conn.close()
    return 'Login attempted'

@app.route('/run', methods=['POST'])
def run_command():
    cmd = request.form['cmd']
    # VULN-003: OS command injection via shell=True
    result = subprocess.call(cmd, shell=True)
    return str(result)

@app.route('/evaluate', methods=['POST'])
def evaluate():
    expression = request.form['expr']
    # VULN-004: Use of eval() on user input
    result = eval(expression)
    return str(result)

@app.route('/redirect')
def unsafe_redirect():
    # VULN-005: Unvalidated redirect
    next_url = request.args.get('next')
    return redirect(next_url)

@app.route('/file')
def read_file():
    filename = request.args.get('name')
    # VULN-006: Path traversal
    with open(os.path.join('/var/data', filename)) as f:
        return f.read()

if __name__ == '__main__':
    app.run(debug=True)