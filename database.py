
import sqlite3
import csv
from pathlib import Path


# ==========================================
# DATABASE PATHS
# ==========================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE = BASE_DIR / "database" / "security_logs.db"

CSV_FILE = BASE_DIR / "logs" / "login_logs.csv"


# ==========================================
# DATABASE CONNECTION
# ==========================================

def connect_database():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


# ==========================================
# CREATE LOGIN LOGS TABLE
# ==========================================

def create_table():

    with connect_database() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (

                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                username TEXT,
                ip_address TEXT,
                status TEXT,

                UNIQUE(timestamp, username, ip_address, status)

            )
        """)

    print("Login logs table ready!")


# ==========================================
# CREATE SECURITY ALERTS TABLE
# ==========================================

def create_alerts_table():

    with connect_database() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                alert_key TEXT NOT NULL UNIQUE,

                alert_type TEXT NOT NULL,

                username TEXT DEFAULT '',

                ip_address TEXT NOT NULL,

                severity TEXT NOT NULL
                    CHECK(severity IN ('HIGH', 'MEDIUM', 'LOW')),

                status TEXT NOT NULL DEFAULT 'OPEN'
                    CHECK(status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),

                description TEXT,

                occurrence_count INTEGER DEFAULT 1,

                first_detected TEXT NOT NULL,

                last_detected TEXT NOT NULL,

                resolved_at TEXT

            )
        """)

    print("Security alerts table ready!")


# ==========================================
# CREATE ALERT INVESTIGATION HISTORY TABLE
# ==========================================

def create_alert_history_table():

    with connect_database() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alert_history (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                alert_id INTEGER NOT NULL,

                username TEXT NOT NULL,

                old_status TEXT,

                new_status TEXT NOT NULL,

                changed_at TEXT NOT NULL,

                details TEXT,

                FOREIGN KEY (alert_id)
                    REFERENCES security_alerts(id)

            )
        """)

    print("Alert history table ready!")


# ==========================================
# IMPORT LOGIN LOGS FROM CSV
# ==========================================

def import_logs():

    if not CSV_FILE.exists():

        print("CSV file not found:", CSV_FILE)
        return

    imported = 0
    duplicates = 0

    with connect_database() as connection:

        with CSV_FILE.open(
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            required = {
                "timestamp",
                "username",
                "ip_address",
                "status"
            }

            if not required.issubset(reader.fieldnames or []):
                raise ValueError("CSV headers are incorrect.")

            for row in reader:

                cursor = connection.execute("""
                    INSERT OR IGNORE INTO login_logs
                    (timestamp, username, ip_address, status)
                    VALUES (?, ?, ?, ?)
                """, (
                    row["timestamp"],
                    row["username"],
                    row["ip_address"],
                    row["status"]
                ))

                if cursor.rowcount == 1:
                    imported += 1
                else:
                    duplicates += 1

    print("\nLogin log import completed.")
    print("New records imported:", imported)
    print("Duplicate records skipped:", duplicates)


# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":

    # Ensure database directory exists
    DATABASE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Create all database tables
    create_table()

    create_alerts_table()

    create_alert_history_table()

    # Import login logs
    import_logs()
