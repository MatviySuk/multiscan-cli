import subprocess
import sqlite3

def run_cmd(cmd):
    # CWE-78: OS Command Injection
    subprocess.call(cmd, shell=True) 

def get_user(db, user_id):
    cursor = db.cursor()
    # CWE-89: SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'") 
