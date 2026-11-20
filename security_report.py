
import sqlite3

def generate_report():

    connection = sqlite3.connect(
        "database/security_logs.db"
    )

    cursor = connection.cursor()

    # Total login records
    cursor.execute("""
    SELECT COUNT(*) FROM login_logs
    """)

    total = cursor.fetchone()[0]

    # Successful logins
    cursor.execute("""
    SELECT COUNT(*)
    FROM login_logs
    WHERE status = 'SUCCESS'
    """)

    successful = cursor.fetchone()[0]

    # Failed logins
    cursor.execute("""
    SELECT COUNT(*)
    FROM login_logs
    WHERE status = 'FAILED'
    """)

    failed = cursor.fetchone()[0]

    # Suspicious IP addresses
    cursor.execute("""
    SELECT ip_address, COUNT(*)
    FROM login_logs
    WHERE status = 'FAILED'
    GROUP BY ip_address
    HAVING COUNT(*) >= 3
    """)

    suspicious_ips = cursor.fetchall()

    print("\n===== SECURITY MONITORING REPORT =====")

    print("Total Events:", total)
    print("Successful Logins:", successful)
    print("Failed Logins:", failed)

    print("\n===== SUSPICIOUS IP ADDRESSES =====")

    for ip, count in suspicious_ips:

        print("IP Address:", ip)
        print("Failed Attempts:", count)
        print("Status: Requires Investigation")

    connection.close()


generate_report()
