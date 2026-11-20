import logging

from detection.detection_engine import detect_security_threats
from test.alert_manager import generate_alerts

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def main():

    try:
        print("================================")
        print(" SECURITY LOG ANALYZER")
        print("================================")

        logging.info("Application started")

        print("Running security detection...")

        detect_security_threats()

        print("Generating security alerts...")

        generate_alerts()

        logging.info("Application completed")

        print("Security analysis completed!")

    except Exception as error:

        logging.error("Application failed: %s", error)

        print("An error occurred:", error)


if __name__ == "__main__":
    main()