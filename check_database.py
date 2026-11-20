import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "database" / "security_logs.db"

conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
""")

print("Database tables:")

for table in cursor.fetchall():
    print("-", table[0])

cursor.execute("PRAGMA table_info(users)")

print("\nUsers table columns:")

for column in cursor.fetchall():
    print(column)

conn.close()