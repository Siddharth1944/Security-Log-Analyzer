# Security Log Analyzer & Monitoring Dashboard

A Python-based security monitoring application designed to analyze login activity, detect suspicious authentication patterns, generate security alerts, and monitor incidents through a web dashboard.

## Project Overview

The Security Log Analyzer helps identify potentially malicious login activities from authentication logs. It uses Python-based detection logic, SQLite database storage, and a Flask web application to provide security monitoring and alert management.

## Key Features

- **Log Analysis:** Processes login records and identifies suspicious activity.
- **Brute-Force Detection:** Detects repeated failed login attempts.
- **Password-Spraying Detection:** Identifies suspicious authentication patterns across multiple accounts.
- **Time-Based Detection:** Detects unusual login activity based on time patterns.
- **Alert Management:** Supports Open, Acknowledged, and Resolved alert statuses.
- **Alert History:** Maintains a record of alert status changes.
- **Security Dashboard:** Displays alert statistics and visual charts.
- **Role-Based Access Control:** Supports Admin, Analyst, and Viewer roles.
- **Audit Logging:** Records important application activities.
- **Authentication Security:** Uses password hashing and protected application routes.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Log analysis and detection logic |
| Flask | Web application and API |
| SQLite | Database management |
| HTML, CSS, JavaScript | Dashboard frontend |
| Chart.js | Data visualization |
| Git and GitHub | Version control |

## Project Structure

```text
Security-Log-Analyzer/
├── authentication/
├── database/
├── detection/
├── frontend/
├── logs/
├── reports/
├── security/
├── tests/
├── alert_manager.py
├── analyzer.py
├── app.py
├── auth_database.py
├── database.py
├── main.py
├── run_detection.py
└── README.md
```

## Detection Capabilities

The application includes detection modules for:

1. Brute-force login attempts
2. Password spraying
3. Time-based suspicious login activity

Detected events are converted into security alerts with severity levels:

- HIGH
- MEDIUM
- LOW

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/Security-Log-Analyzer.git
cd Security-Log-Analyzer
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

Install the packages listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 4. Configure the Flask secret key

PowerShell:

```powershell
$env:FLASK_SECRET_KEY = "replace-with-a-long-random-secret"
```

### 5. Initialize the database

Follow the database initialization procedure in the project setup.

### 6. Run the application

```bash
python app.py
```

Open the dashboard at:

```text
http://127.0.0.1:5000
```

## Running Tests

Run the automated tests using:

```bash
python -m pytest -v
```

## Security Considerations

- Passwords should be stored using secure password hashing.
- Application secrets should be stored in environment variables.
- Database files and credentials should not be committed to GitHub.
- Only authorized users should be able to modify alert statuses.
- Audit logs help track important application activities.

## Project Purpose

This project was developed to gain practical experience in security log analysis, threat detection, incident monitoring, Python development, database integration, and SOC Analyst workflows.

## Future Improvements

- Integration with external threat intelligence sources.
- Email notifications for high-severity alerts.
- Additional detection rules.
- Real-time log monitoring.
- Advanced dashboard filtering and reporting.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes. Use only with logs and systems you are authorized to monitor.

## Author

**Siddharth Kadam**

Cybersecurity Enthusiast | Computer Engineering Graduate

Interests: SOC Operations, Security Monitoring, Network Analysis, and Vulnerability Assessment.
