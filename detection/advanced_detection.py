
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE = BASE_DIR / "database" / "security_logs.db"


# ==========================================
# AUTOMATIC SEVERITY CLASSIFICATION
# ==========================================

def calculate_severity(count):

    if count >= 8:
        return "HIGH"

    elif count >= 5:
        return "MEDIUM"

    elif count >= 3:
        return "LOW"

    return None


# ==========================================
# BRUTE FORCE DETECTION
# ==========================================

def detect_brute_force():

    alerts = []

    with sqlite3.connect(DATABASE) as conn:

        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                username,
                ip_address,
                COUNT(*) AS failed_attempts

            FROM login_logs

            WHERE UPPER(status) = 'FAILED'

            GROUP BY username, ip_address

            HAVING COUNT(*) >= 3
        """)

        results = cursor.fetchall()

    for username, ip, count in results:

        severity = calculate_severity(count)

        if severity is None:
            continue

        alerts.append({

            "type": "Brute Force Attack",

            "username": username,

            "ip": ip,

            "count": count,

            "severity": severity,

            "status": "OPEN",

            "description": (
                f"{count} failed login attempts "
                f"against {username} from {ip}"
            )
        })

    return alerts


# ==========================================
# PASSWORD SPRAYING DETECTION
# ==========================================

def detect_password_spraying():

    alerts = []

    with sqlite3.connect(DATABASE) as conn:

        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                ip_address,
                COUNT(DISTINCT username) AS targeted_accounts,
                COUNT(*) AS failed_attempts

            FROM login_logs

            WHERE UPPER(status) = 'FAILED'

            GROUP BY ip_address

            HAVING COUNT(DISTINCT username) >= 3
        """)

        results = cursor.fetchall()

    for ip, accounts, count in results:

        severity = calculate_severity(accounts)

        if severity is None:
            continue

        alerts.append({

            "type": "Possible Password Spraying",

            "ip": ip,

            "count": count,

            "targeted_accounts": accounts,

            "severity": severity,

            "status": "OPEN",

            "description": (
                f"{ip} attempted logins against "
                f"{accounts} different accounts "
                f"with {count} failed attempts"
            )
        })

    return alerts


# ==========================================
# RUN DETECTION TEST
# ==========================================

if __name__ == "__main__":

    brute_force = detect_brute_force()

    password_spraying = detect_password_spraying()

    print("\n========== BRUTE FORCE ALERTS ==========")

    for alert in brute_force:
        print(alert)

    print("\n========== PASSWORD SPRAYING ALERTS ==========")

    for alert in password_spraying:
        print(alert)

    print("\n========== DETECTION SUMMARY ==========")

    all_alerts = brute_force + password_spraying

    for severity in ["HIGH", "MEDIUM", "LOW"]:

        count = sum(
            1 for alert in all_alerts
            if alert["severity"] == severity
        )

        print(f"{severity}: {count}")
