
import csv
import random
import shutil
import sqlite3

from pathlib import Path
from datetime import datetime, timedelta


# Project paths
BASE_DIR = Path(__file__).resolve().parent
CSV_FILE = BASE_DIR / "logs" / "login_logs.csv"
DATABASE = BASE_DIR / "database" / "security_logs.db"

random.seed(42)

records = []

# Use recent timestamps
start_time = datetime.now().replace(
    hour=8, minute=0, second=0, microsecond=0
)


# ------------------------------------------------
# 1. Generate normal login activity
# ------------------------------------------------

users = [
    "siddharth", "rahul", "priya", "rohit",
    "amit", "neha", "admin", "employee1",
    "employee2", "guest1", "guest2", "manager"
]

ips = [
    f"192.168.1.{i}" for i in range(10, 40)
]

for i in range(200):
    timestamp = start_time + timedelta(
        minutes=random.randint(0, 300),
        seconds=random.randint(0, 59)
    )

    records.append({
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "username": random.choice(users),
        "ip_address": random.choice(ips),
        "status": random.choices(
            ["SUCCESS", "FAILED"],
            weights=[85, 15]
        )[0]
    })


# ------------------------------------------------
# 2. Brute-force attack simulation
# ------------------------------------------------

attack_ip = "45.142.120.10"

for i in range(10):
    timestamp = start_time + timedelta(minutes=30, seconds=i * 20)

    records.append({
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "username": "admin",
        "ip_address": attack_ip,
        "status": "FAILED"
    })


# ------------------------------------------------
# 3. Password spraying simulation
# ------------------------------------------------

spray_ip = "103.25.80.45"

spray_users = [
    "user01", "user02", "user03", "user04",
    "user05", "user06", "user07", "user08",
    "user09", "user10", "finance", "hr"
]

for i, username in enumerate(spray_users):
    timestamp = start_time + timedelta(
        minutes=90, seconds=i * 25
    )

    records.append({
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "ip_address": spray_ip,
        "status": "FAILED"
    })


# ------------------------------------------------
# 4. Multiple failed attempts against one user
# ------------------------------------------------

target_user = "finance"

for i in range(8):
    timestamp = start_time + timedelta(
        minutes=150, seconds=i * 30
    )

    records.append({
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "username": target_user,
        "ip_address": f"172.20.0.{50 + i}",
        "status": "FAILED"
    })


# ------------------------------------------------
# 5. Normal successful login after failed attempts
# ------------------------------------------------

for i in range(5):
    timestamp = start_time + timedelta(
        minutes=200, seconds=i * 60
    )

    records.append({
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "username": "siddharth",
        "ip_address": "192.168.1.10",
        "status": "SUCCESS"
    })



# ------------------------------------------------
# 6. Medium-risk brute-force simulation
# ------------------------------------------------

medium_attack_ip = "185.220.101.25"

for i in range(6):

    timestamp = start_time + timedelta(
        minutes=250,
        seconds=i * 30
    )

    records.append({
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "username": "test_account",
        "ip_address": medium_attack_ip,
        "status": "FAILED"
    })


# Sort records by timestamp
records.sort(key=lambda x: x["timestamp"])


# ------------------------------------------------
# 6. Write CSV file
# ------------------------------------------------

CSV_FILE.parent.mkdir(parents=True, exist_ok=True)

with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "timestamp",
            "username",
            "ip_address",
            "status"
        ]
    )

    writer.writeheader()
    writer.writerows(records)


# ------------------------------------------------
# 7. Backup existing database
# ------------------------------------------------

if not DATABASE.exists():
    raise FileNotFoundError(
        f"Database not found: {DATABASE}"
    )

backup_file = DATABASE.with_name(
    f"security_logs_backup_{datetime.now():%Y%m%d_%H%M%S}.db"
)

shutil.copy2(DATABASE, backup_file)

print(f"Database backup created: {backup_file.name}")


# ------------------------------------------------
# 8. Import CSV records into SQLite
# ------------------------------------------------

conn = sqlite3.connect(DATABASE)

try:
    cursor = conn.cursor()

    # Confirm the table exists
    cursor.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type='table' AND name='login_logs'
    """)

    if cursor.fetchone() is None:
        raise RuntimeError(
            "login_logs table does not exist. "
            "Check your database schema first."
        )

    # Replace only login activity records
    cursor.execute("DELETE FROM login_logs")

    with open(CSV_FILE, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required_columns = {
            "timestamp", "username", "ip_address", "status"
        }

        if not required_columns.issubset(reader.fieldnames or []):
            raise ValueError("CSV columns do not match expected format.")

        imported = 0

        for row in reader:
            cursor.execute("""
                INSERT INTO login_logs
                (timestamp, username, ip_address, status)
                VALUES (?, ?, ?, ?)
            """, (
                row["timestamp"],
                row["username"],
                row["ip_address"],
                row["status"]
            ))

            imported += 1

    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM login_logs")
    total = cursor.fetchone()[0]

    print("\nImport completed successfully!")
    print(f"CSV records generated: {len(records)}")
    print(f"Records imported: {imported}")
    print(f"Total records in database: {total}")

except Exception:
    conn.rollback()
    raise

finally:
    conn.close()
