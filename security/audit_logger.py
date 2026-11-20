
from pathlib import Path
import sqlite3
from datetime import datetime, timezone

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Database location
DATABASE = BASE_DIR / "database" / "security_logs.db"

def log_activity(username, activity, ip_address, details=""):

    conn = None

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO audit_logs
            (username, activity, ip_address, timestamp, details)
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            activity,
            ip_address,
            datetime.now(timezone.utc).isoformat(),
            details
        ))

        conn.commit()

    except sqlite3.Error:
        if conn:
            conn.rollback()
        raise

    finally:
        if conn:
            conn.close()