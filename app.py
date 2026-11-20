import os
import sqlite3
from pathlib import Path
from functools import wraps
from datetime import datetime, timezone

from flask import (
    Flask,
    jsonify,
    request,
    session,
    redirect,
    send_from_directory
)
from werkzeug.security import check_password_hash

from run_detection import run_all_detections
from security.audit_logger import log_activity


# --------------------------------------------------
# 1. APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "database" / "security_logs.db"
FRONTEND_DIR = BASE_DIR / "frontend"

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY is not configured. "
        "Set it in your environment before starting Flask."
    )

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # Local HTTP development only


# --------------------------------------------------
# 2. DATABASE CONNECTION
# --------------------------------------------------

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# --------------------------------------------------
# 3. AUTHENTICATION AND ROLE-BASED ACCESS
# --------------------------------------------------

def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if "username" not in session:
                if request.path.startswith("/api/"):
                    return jsonify({
                        "error": "Authentication required"
                    }), 401

                return redirect("/login")

            if session.get("role") not in allowed_roles:
                if request.path.startswith("/api/"):
                    return jsonify({
                        "error": "Access denied"
                    }), 403

                return "Access Denied", 403

            return function(*args, **kwargs)

        return wrapper

    return decorator



@app.route(
    "/api/alerts/<int:alert_id>/status",
    methods=["PATCH"]
)
@role_required("admin", "analyst")
def update_alert_status(alert_id):

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request"}), 400

    new_status = str(data.get("status", "")).strip().upper()

    if new_status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
        return jsonify({"error": "Invalid alert status"}), 400

    timestamp = datetime.now(timezone.utc).isoformat()
    connection = None

    try:
        connection = get_db_connection()

        alert = connection.execute("""
            SELECT alert_type, ip_address, status
            FROM security_alerts
            WHERE id = ?
        """, (alert_id,)).fetchone()

        if alert is None:
            return jsonify({"error": "Alert not found"}), 404

        old_status = alert["status"]

        if old_status == new_status:
            return jsonify({
                "message": "Alert already has this status"
            }), 200

        resolved_at = timestamp if new_status == "RESOLVED" else None

        connection.execute("""
            UPDATE security_alerts
            SET status = ?, resolved_at = ?
            WHERE id = ?
        """, (new_status, resolved_at, alert_id))

        connection.execute("""
            INSERT INTO alert_history (
                alert_id, username, old_status,
                new_status, changed_at, details
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            session["username"],
            old_status,
            new_status,
            timestamp,
            f"Alert status changed from {old_status} to {new_status}"
        ))

        connection.commit()

        try:
            log_activity(
                username=session["username"],
                activity="ALERT_STATUS_CHANGED",
                ip_address=request.remote_addr,
                details=f"Alert {alert_id}: {old_status} -> {new_status}"
            )
        except Exception:
            app.logger.exception("Audit logging failed")

        return jsonify({
            "message": "Alert status updated successfully",
            "alert_id": alert_id,
            "old_status": old_status,
            "new_status": new_status
        }), 200

    except sqlite3.Error:
        if connection:
            connection.rollback()

        app.logger.exception("Alert status update failed")
        return jsonify({"error": "Unable to update alert status"}), 500

    finally:
        if connection:
            connection.close()



# --------------------------------------------------
# 4. HOME ROUTE
# --------------------------------------------------

@app.route("/")
def home():

    if "username" in session:
        return redirect("/dashboard")

    return redirect("/login")


# --------------------------------------------------
# 5. LOGIN ROUTE
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":

        if "username" in session:
            return redirect("/dashboard")

        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Log Analyzer - Login</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
        </head>

        <body style="
            font-family: Arial;
            background: #111827;
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        ">

            <div style="
                background: #1f2937;
                padding: 35px;
                border-radius: 12px;
                width: 320px;
            ">

                <h2>Security Log Analyzer</h2>
                <p>Login to your account</p>

                <form method="POST">

                    <input
                        name="username"
                        placeholder="Username"
                        required
                        style="width: 100%; padding: 12px; margin-bottom: 15px; box-sizing: border-box;"
                    >

                    <input
                        name="password"
                        type="password"
                        placeholder="Password"
                        required
                        style="width: 100%; padding: 12px; margin-bottom: 15px; box-sizing: border-box;"
                    >

                    <button
                        type="submit"
                        style="width: 100%; padding: 12px; cursor: pointer;"
                    >
                        Login
                    </button>

                </form>

            </div>

        </body>
        </html>
        """

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return "Username and password are required", 400

    connection = None

    try:
        connection = get_db_connection()

        user = connection.execute("""
            SELECT username, password_hash, role
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):

            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]

            try:
                log_activity(
                    username=user["username"],
                    activity="LOGIN_SUCCESS",
                    ip_address=request.remote_addr,
                    details="User logged in successfully"
                )
            except Exception:
                app.logger.exception("Login success audit logging failed")

            return redirect("/dashboard")

        try:
            log_activity(
                username=username,
                activity="LOGIN_FAILED",
                ip_address=request.remote_addr,
                details="Invalid login credentials"
            )
        except Exception:
            app.logger.exception("Failed login audit logging failed")

        return "Invalid username or password", 401

    except sqlite3.Error:
        app.logger.exception("Login database error")
        return "Unable to process login", 500

    finally:
        if connection:
            connection.close()


# --------------------------------------------------
# 6. LOGOUT ROUTE
# --------------------------------------------------

@app.route("/logout")
def logout():

    username = session.get("username")

    if username:
        try:
            log_activity(
                username=username,
                activity="LOGOUT",
                ip_address=request.remote_addr,
                details="User logged out"
            )
        except Exception:
            app.logger.exception("Logout audit logging failed")

    session.clear()
    return redirect("/login")


# --------------------------------------------------
# 7. DASHBOARD ROUTE
# --------------------------------------------------

@app.route("/dashboard")
@role_required("admin", "analyst", "viewer")
def dashboard():

    return send_from_directory(
        str(FRONTEND_DIR),
        "index.html"
    )


# --------------------------------------------------
# 8. RUN DETECTION API
# --------------------------------------------------

@app.route("/api/run-detection", methods=["POST"])
@role_required("admin", "analyst")
def trigger_detection():

    try:
        alerts = run_all_detections()

        return jsonify({
            "message": "Detection completed successfully",
            "total_alerts": len(alerts),
            "alerts": alerts
        })

    except Exception:
        app.logger.exception("Detection engine failed")

        return jsonify({
            "error": "Unable to run detection engine"
        }), 500


# --------------------------------------------------
# 9. FRONTEND STATIC FILES
# --------------------------------------------------

@app.route("/<path:filename>")
def frontend_files(filename):

    return send_from_directory(
        str(FRONTEND_DIR),
        filename
    )


# --------------------------------------------------
# 10. APPLICATION STATUS API
# --------------------------------------------------

@app.route("/api/status")
@role_required("admin", "analyst", "viewer")
def status():

    return jsonify({
        "status": "online",
        "application": "Security Log Analyzer"
    })


# --------------------------------------------------
# 11. SECURITY ALERTS API
# --------------------------------------------------

@app.route("/api/alerts")
@role_required("admin", "analyst", "viewer")
def get_alerts():

    connection = None

    try:
        connection = get_db_connection()

        rows = connection.execute("""
            SELECT
                id,
                alert_type,
                username,
                ip_address,
                severity,
                status,
                description,
                occurrence_count,
                attempt_count,
                first_detected,
                last_detected,
                resolved_at
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
                "severity": row["severity"],
                "status": row["status"],
                "description": row["description"],
                "count": row["attempt_count"],
                "occurrence_count": row["occurrence_count"],
                "detected_at": row["last_detected"],
                "first_detected": row["first_detected"],
                "last_detected": row["last_detected"],
                "resolved_at": row["resolved_at"]
            })

        return jsonify(alerts)

    except sqlite3.Error:
        app.logger.exception("Unable to retrieve security alerts")

        return jsonify({
            "error": "Unable to retrieve security alerts"
        }), 500

    finally:
        if connection:
            connection.close()



# --------------------------------------------------
# 13. ALERT INVESTIGATION HISTORY API
# --------------------------------------------------

@app.route(
    "/api/alerts/<int:alert_id>/history",
    methods=["GET"]
)
@role_required("admin", "analyst", "viewer")
def get_alert_history(alert_id):

    connection = None

    try:
        connection = get_db_connection()

        alert = connection.execute("""
            SELECT id
            FROM security_alerts
            WHERE id = ?
        """, (alert_id,)).fetchone()

        if alert is None:
            return jsonify({
                "error": "Alert not found"
            }), 404

        history_rows = connection.execute("""
            SELECT
                id,
                alert_id,
                username,
                old_status,
                new_status,
                changed_at,
                details
            FROM alert_history
            WHERE alert_id = ?
            ORDER BY id DESC
        """, (alert_id,)).fetchall()

        return jsonify([
            dict(row) for row in history_rows
        ]), 200

    except sqlite3.Error:
        app.logger.exception(
            "Unable to retrieve alert investigation history"
        )

        return jsonify({
            "error": "Unable to retrieve alert history"
        }), 500

    finally:
        if connection:
            connection.close()

# --------------------------------------------------
# 14. DASHBOARD STATISTICS API
# --------------------------------------------------

@app.route("/api/stats")
@role_required("admin", "analyst", "viewer")
def get_stats():

    connection = None

    try:
        connection = get_db_connection()

        stats = connection.execute("""
            SELECT
                COUNT(*) AS total_events,

                SUM(
                    CASE
                        WHEN UPPER(status) = 'SUCCESS'
                        THEN 1 ELSE 0
                    END
                ) AS successful_logins,

                SUM(
                    CASE
                        WHEN UPPER(status) = 'FAILED'
                        THEN 1 ELSE 0
                    END
                ) AS failed_logins

            FROM login_logs
        """).fetchone()

        return jsonify({
            key: value if value is not None else 0
            for key, value in dict(stats).items()
        })

    except sqlite3.Error:
        app.logger.exception("Unable to calculate statistics")

        return jsonify({
            "error": "Unable to calculate statistics"
        }), 500

    finally:
        if connection:
            connection.close()


# --------------------------------------------------
# 15. ADMIN ROUTE
# --------------------------------------------------

@app.route("/admin")
@role_required("admin")
def admin_panel():

    return "Welcome Admin"


# --------------------------------------------------
# 16. ANALYST ROUTE
# --------------------------------------------------

@app.route("/analyst")
@role_required("admin", "analyst")
def analyst_panel():

    return "Welcome Security Analyst"


# --------------------------------------------------
# 17. VIEWER ROUTE
# --------------------------------------------------

@app.route("/viewer")
@role_required("admin", "analyst", "viewer")
def viewer_panel():

    return "Welcome Viewer"


# --------------------------------------------------
# 18. AUDIT LOGS API
# --------------------------------------------------

@app.route("/api/audit-logs")
@role_required("admin", "analyst")
def get_audit_logs():

    connection = None

    try:
        connection = get_db_connection()

        logs = connection.execute("""
            SELECT
                id,
                username,
                activity,
                ip_address,
                timestamp,
                details
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

        return jsonify([
            dict(row) for row in logs
        ])

    except sqlite3.Error:
        app.logger.exception("Unable to retrieve audit logs")

        return jsonify({
            "error": "Unable to retrieve audit logs"
        }), 500

    finally:
        if connection:
            connection.close()


# --------------------------------------------------
# 19. RUN FLASK APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
