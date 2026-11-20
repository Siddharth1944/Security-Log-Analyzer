
import csv


# Function to analyze security logs
def analyze_logs():

    total_logs = 0
    successful_logins = 0
    failed_logins = 0

    failed_attempts = {}
    user_activity = {}

    # Read CSV file
    with open("logs/login_logs.csv", "r") as file:

        reader = csv.DictReader(file)

        for row in reader:

            total_logs += 1

            username = row["username"]
            ip = row["ip_address"]
            status = row["status"]

            # Initialize username
            if username not in user_activity:

                user_activity[username] = {
                    "SUCCESS": 0,
                    "FAILED": 0
                }

            # Count login activity
            if status == "SUCCESS":

                successful_logins += 1
                user_activity[username]["SUCCESS"] += 1

            elif status == "FAILED":

                failed_logins += 1
                user_activity[username]["FAILED"] += 1

                # Count failed attempts by IP
                if ip in failed_attempts:
                    failed_attempts[ip] += 1

                else:
                    failed_attempts[ip] = 1

    # Generate report
    print("\n===== SECURITY LOG REPORT =====")

    print("Total Logs:", total_logs)
    print("Successful Logins:", successful_logins)
    print("Failed Logins:", failed_logins)

    # User activity report
    print("\n===== USER ACTIVITY REPORT =====")

    for username, activity in user_activity.items():

        print("\nUsername:", username)
        print("Successful:", activity["SUCCESS"])
        print("Failed:", activity["FAILED"])

    # Suspicious IP report
    print("\n===== SUSPICIOUS IP REPORT =====")

    threshold = 3

    for ip, count in failed_attempts.items():

        if count >= threshold:

            print("IP Address:", ip)
            print("Failed Attempts:", count)
            print("Status: Requires Investigation")


# Run the analyzer
analyze_logs()
