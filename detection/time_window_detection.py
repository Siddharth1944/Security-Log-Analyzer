
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE = BASE_DIR / "database" / "security_logs.db"


def detect_time_based_attacks():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            ip_address,
            timestamp,
            COUNT(*) AS failed_attempts

        FROM login_logs

        WHERE UPPER(status) = 'FAILED'

        GROUP BY ip_address, timestamp

        ORDER BY timestamp
    """)

    records = cursor.fetchall()
    conn.close()

    ip_records = {}

    for ip, timestamp, count in records:

        try:
            event_time = datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

        except ValueError:
            continue

        ip_records.setdefault(ip, []).append(
            (event_time, count)
        )

    alerts = []

    for ip, events in ip_records.items():

        for current_time, _ in events:

            window_start = current_time - timedelta(minutes=5)

            total = sum(
                count
                for event_time, count in events
                if window_start <= event_time <= current_time
            )

            if total >= 5:

                alerts.append({
                    "type": "Time-Based Brute Force",
                    "ip": ip,
                    "count": total,
                    "severity": "HIGH",
                    "status": "OPEN",
                    "description": (
                        f"{total} failed login attempts "
                        f"within 5 minutes from {ip}"
                    )
                })

                break

    return alerts


if __name__ == "__main__":

    results = detect_time_based_attacks()

    if results:
        for alert in results:
            print(alert)

    else:
        print("No time-based attacks detected.")
