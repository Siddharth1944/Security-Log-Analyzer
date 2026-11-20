
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict


def detect_time_based_failures():

    connection = sqlite3.connect(
        "database/security_logs.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT timestamp, username, ip_address
    FROM login_logs
    WHERE status = 'FAILED'
    ORDER BY timestamp
    """)

    records = cursor.fetchall()

    connection.close()

    # Group events by IP
    ip_events = defaultdict(list)

    for timestamp, username, ip in records:

        event_time = datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

        ip_events[ip].append(
            (event_time, username)
        )

    print("\n===== TIME-BASED DETECTION =====")

    threshold = 3
    time_window = timedelta(minutes=5)

    for ip, events in ip_events.items():

        for index, (current_time, username) in enumerate(events):

            window_start = current_time - time_window

            matching_events = [
                event for event in events
                if window_start <= event[0] <= current_time
            ]

            if len(matching_events) >= threshold:

                print("Suspicious IP:", ip)
                print("Failed Attempts:", len(matching_events))
                print("Time Window: 5 minutes")
                print("Severity: HIGH")
                print("Status: Requires Investigation")
                print("------------------------")

                # Report only the first matching window
                break


if __name__ == "__main__":

    detect_time_based_failures()
