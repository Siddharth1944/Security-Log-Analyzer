
import sqlite3

# Connect to database
connection = sqlite3.connect("database/security_logs.db")

cursor = connection.cursor()

# Find suspicious IP addresses
cursor.execute("""
SELECT ip_address, COUNT(*) AS failed_attempts
FROM login_logs
WHERE status = 'FAILED'
GROUP BY ip_address
HAVING COUNT(*) >= 3
""")

results = cursor.fetchall()

print("\n===== SUSPICIOUS IP REPORT =====")

for row in results:

    print("IP Address:", row[0])
    print("Failed Attempts:", row[1])
    print("Status: Requires Investigation")
    print("------------------------")

connection.close()
