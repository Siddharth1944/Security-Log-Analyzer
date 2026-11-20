import logging

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logging.info("Security Log Analyzer started")
logging.warning("Multiple failed login attempts detected")
logging.error("Database connection failed")

print("Logging completed. Check app.log")