
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "database" / "security_logs.db"

conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

# Create users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
)
""")

# Create audit logs table
cursor.execute("""
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    activity TEXT NOT NULL,
    ip_address TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    details TEXT
)
""")

conn.commit()
conn.close()

print("Users and audit_logs tables created successfully.")
