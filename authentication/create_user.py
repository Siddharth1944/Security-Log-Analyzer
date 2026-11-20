
import sqlite3
from pathlib import Path
from getpass import getpass
from werkzeug.security import generate_password_hash

# Correct database location
BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "database" / "security_logs.db"

# Get user details
username = input("Enter username: ").strip()
password = getpass("Enter password: ")
role = input("Enter role (admin/analyst/viewer): ").strip().lower()

allowed_roles = ["admin", "analyst", "viewer"]

if not username or not password:
    print("Username and password are required.")

elif role not in allowed_roles:
    print("Invalid role.")

else:
    password_hash = generate_password_hash(password)

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        """, (username, password_hash, role))

        conn.commit()

        print("User created successfully!")

    except sqlite3.IntegrityError:
        print("Username already exists.")

    finally:
        conn.close()
