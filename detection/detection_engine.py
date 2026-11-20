
import sqlite3


def connect_database():

    return sqlite3.connect(
        "database/security_logs.db"
    )


def detect_repeated_failures():

    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("""
    SELECT ip_address, COUNT(*)
    FROM login_logs
    WHERE status = 'FAILED'
    GROUP BY ip_address
    HAVING COUNT(*) >= 3
    """)

    results = cursor.fetchall()

    print("\n===== REPEATED FAILURE ALERTS =====")

    for ip, count in results:

        if count >= 5:
            severity = "HIGH"

        else:
            severity = "MEDIUM"

        print("IP Address:", ip)
        print("Failed Attempts:", count)
        print("Severity:", severity)
        print("------------------------")

    connection.close()


def detect_multiple_accounts():

    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("""
    SELECT ip_address, COUNT(DISTINCT username)
    FROM login_logs
    WHERE status = 'FAILED'
    GROUP BY ip_address
    HAVING COUNT(DISTINCT username) >= 3
    """)

    results = cursor.fetchall()

    print("\n===== MULTIPLE ACCOUNT ALERTS =====")

    for ip, account_count in results:

        print("IP Address:", ip)
        print("Targeted Accounts:", account_count)
        print("Severity: HIGH")
        print("------------------------")

    connection.close()


def detect_targeted_users():

    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("""
    SELECT username, COUNT(*)
    FROM login_logs
    WHERE status = 'FAILED'
    GROUP BY username
    HAVING COUNT(*) >= 3
    """)

    results = cursor.fetchall()

    print("\n===== TARGETED USER ALERTS =====")

    for username, count in results:

        print("Username:", username)
        print("Failed Attempts:", count)
        print("Severity: MEDIUM")
        print("------------------------")

    connection.close()


def run_detection():

    detect_repeated_failures()

    detect_multiple_accounts()

    detect_targeted_users()


if __name__ == "__main__":

    run_detection()
