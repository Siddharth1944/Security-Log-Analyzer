
import sqlite3
import json
from datetime import datetime, timezone


def connect_database():

    return sqlite3.connect(
        "database/security_logs.db"
    )


def create_alerts():

    connection = connect_database()
    cursor = connection.cursor()

    alerts = []

    detected_at = datetime.now(
        timezone.utc
    ).isoformat()

    # Rule 1: Repeated failed logins
    cursor.execute("""
    SELECT ip_address, COUNT(*)
    FROM login_logs
    WHERE status = 'FAILED'
    GROUP BY ip_address
    HAVING COUNT(*) >= 3
    """)

    results = cursor.fetchall()

    for ip, count in results:

        severity = "HIGH" if count >= 5 else "MEDIUM"

        alert = {
            "alert_type": "Repeated Failed Logins",
            "source_ip": ip,
            "failed_attempts": count,
            "severity": severity,
            "status": "OPEN",
            "detected_at": detected_at,
            "description": "Multiple failed login attempts detected"
        }

        alerts.append(alert)

    # Rule 2: Multiple accounts targeted
    cursor.execute("""
    SELECT ip_address, COUNT(DISTINCT username)
    FROM login_logs
    WHERE status = 'FAILED'
    GROUP BY ip_address
    HAVING COUNT(DISTINCT username) >= 3
    """)

    results = cursor.fetchall()

    for ip, account_count in results:

        alert = {
            "alert_type": "Multiple Account Targeting",
            "source_ip": ip,
            "targeted_accounts": account_count,
            "severity": "HIGH",
            "status": "OPEN",
            "detected_at": detected_at,
            "description": "One IP attempted access to multiple accounts"
        }

        alerts.append(alert)

    # Rule 3: Repeated failures against a username
    cursor.execute("""
    SELECT username, COUNT(*)
    FROM login_logs
    WHERE status = 'FAILED'
    GROUP BY username
    HAVING COUNT(*) >= 3
    """)

    results = cursor.fetchall()

    for username, count in results:

        alert = {
            "alert_type": "Targeted User Activity",
            "username": username,
            "failed_attempts": count,
            "severity": "MEDIUM",
            "status": "OPEN",
            "detected_at": detected_at,
            "description": "Repeated failed logins against one account"
        }

        alerts.append(alert)

    connection.close()

    return alerts


def save_alerts(alerts):

    with open("security_alerts.json", "w") as file:

        json.dump(
            alerts,
            file,
            indent=4
        )

    print("Security alerts saved successfully!")


def main():

    alerts = create_alerts()

    save_alerts(alerts)

    print("Total Alerts Generated:", len(alerts))


if __name__ == "__main__":

    main()
