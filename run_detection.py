
import json
import hashlib

from pathlib import Path
from datetime import datetime, timezone

from database import connect_database

from detection.advanced_detection import (
    detect_brute_force,
    detect_password_spraying
)

from detection.time_window_detection import (
    detect_time_based_attacks
)


# ==========================================
# PROJECT PATHS
# ==========================================

BASE_DIR = Path(__file__).resolve().parent

ALERT_FILE = BASE_DIR / "reports" / "security_alerts.json"

SEVERITY_PRIORITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3
}


# ==========================================
# DATABASE SCHEMA MIGRATION
# ==========================================

def prepare_alert_database():

    with connect_database() as connection:

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(security_alerts)"
            ).fetchall()
        }

        if not columns:
            raise RuntimeError(
                "security_alerts table not found. "
                "Run database.py first."
            )

        # Preserve the original number of attack attempts
        if "attempt_count" not in columns:

            connection.execute("""
                ALTER TABLE security_alerts
                ADD COLUMN attempt_count INTEGER DEFAULT 1
            """)


# ==========================================
# GENERATE UNIQUE ALERT IDENTIFIER
# ==========================================

def generate_alert_key(alert):

    alert_type = str(
        alert.get("type", alert.get("alert_type", "Unknown"))
    ).strip().lower()

    ip = str(
        alert.get("ip", alert.get("ip_address", "Unknown"))
    ).strip()

    username = str(
        alert.get("username") or ""
    ).strip().lower()

    identity = f"{alert_type}|{ip}|{username}"

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


# ==========================================
# SAVE ALERTS TO SQLITE
# ==========================================

def save_alerts_to_database(alerts):

    prepare_alert_database()

    detected_at = datetime.now(
        timezone.utc
    ).isoformat()

    with connect_database() as connection:

        for alert in alerts:

            severity = str(
                alert.get("severity", "")
            ).upper()

            if severity not in SEVERITY_PRIORITY:
                raise ValueError(
                    f"Invalid severity: {severity}"
                )

            alert_type = str(
                alert.get("type", alert.get("alert_type", "Unknown"))
            )

            ip = str(
                alert.get("ip", alert.get("ip_address", "Unknown"))
            )

            username = str(
                alert.get("username") or ""
            )

            description = str(
                alert.get("description", "")
            )

            attempt_count = int(
                alert.get("count", alert.get("attempts", 1))
            )

            if attempt_count < 1:
                attempt_count = 1

            alert_key = generate_alert_key(alert)

            connection.execute("""
                INSERT INTO security_alerts (

                    alert_key,
                    alert_type,
                    username,
                    ip_address,
                    severity,
                    status,
                    description,
                    occurrence_count,
                    first_detected,
                    last_detected,
                    resolved_at,
                    attempt_count

                )

                VALUES (?, ?, ?, ?, ?, 'OPEN', ?, 1, ?, ?, NULL, ?)

                ON CONFLICT(alert_key) DO UPDATE SET

                    severity = CASE

                        WHEN excluded.severity = 'HIGH'
                            THEN 'HIGH'

                        WHEN security_alerts.severity = 'HIGH'
                            THEN 'HIGH'

                        WHEN excluded.severity = 'MEDIUM'
                            THEN 'MEDIUM'

                        WHEN security_alerts.severity = 'MEDIUM'
                            THEN 'MEDIUM'

                        ELSE 'LOW'

                    END,

                    description = excluded.description,

                    occurrence_count =
                        security_alerts.occurrence_count + 1,

                    attempt_count = excluded.attempt_count,

                    last_detected = excluded.last_detected,

                    status = CASE

                        WHEN security_alerts.status = 'RESOLVED'
                            THEN 'OPEN'

                        ELSE security_alerts.status

                    END,

                    resolved_at = CASE

                        WHEN security_alerts.status = 'RESOLVED'
                            THEN NULL

                        ELSE security_alerts.resolved_at

                    END

            """, (
                alert_key,
                alert_type,
                username,
                ip,
                severity,
                description,
                detected_at,
                detected_at,
                attempt_count
            ))


# ==========================================
# LOAD ALL STORED ALERTS
# ==========================================

def load_stored_alerts():

    with connect_database() as connection:

        rows = connection.execute("""
            SELECT *
            FROM security_alerts
            ORDER BY last_detected DESC
        """).fetchall()

    alerts = []

    for row in rows:

        alerts.append({

            "id": row["id"],

            "type": row["alert_type"],

            "username": row["username"],

            "ip": row["ip_address"],

            "count": row["attempt_count"],

            "occurrence_count": row["occurrence_count"],

            "severity": row["severity"],

            "status": row["status"],

            "description": row["description"],

            "detected_at": row["last_detected"],

            "first_detected": row["first_detected"],

            "last_detected": row["last_detected"],

            "resolved_at": row["resolved_at"]

        })

    return alerts


# ==========================================
# SAVE JSON REPORT
# ==========================================

def save_json_report(alerts):

    ALERT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary_file = ALERT_FILE.with_suffix(".tmp")

    try:

        with temporary_file.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                alerts,
                file,
                indent=4
            )

        temporary_file.replace(ALERT_FILE)

    except Exception:

        if temporary_file.exists():
            temporary_file.unlink()

        raise


# ==========================================
# RUN ALL DETECTIONS
# ==========================================

def run_all_detections():

    print("\n================================")
    print(" SECURITY LOG DETECTION ENGINE")
    print("================================")

    alerts = []

    print("\nRunning brute-force detection...")
    alerts.extend(detect_brute_force())

    print("Running password-spraying detection...")
    alerts.extend(detect_password_spraying())

    print("Running time-based detection...")
    alerts.extend(detect_time_based_attacks())

    # Save new detections to SQLite
    save_alerts_to_database(alerts)

    # Load complete alert history
    stored_alerts = load_stored_alerts()

    # Update JSON for existing dashboard compatibility
    save_json_report(stored_alerts)

    # Severity summary
    high = sum(
        1 for alert in stored_alerts
        if alert["severity"] == "HIGH"
    )

    medium = sum(
        1 for alert in stored_alerts
        if alert["severity"] == "MEDIUM"
    )

    low = sum(
        1 for alert in stored_alerts
        if alert["severity"] == "LOW"
    )

    print("\n================================")
    print(" ALERT MANAGEMENT SUMMARY")
    print("================================")

    print("New detection results:", len(alerts))
    print("Total stored alerts:", len(stored_alerts))

    print("HIGH:", high)
    print("MEDIUM:", medium)
    print("LOW:", low)

    print("\nJSON report updated:", ALERT_FILE)

    return stored_alerts


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    run_all_detections()
