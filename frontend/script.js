
"use strict";

// =============================================
// SECURITY LOG ANALYZER & MONITORING DASHBOARD
// =============================================

// GLOBAL VARIABLES

let alerts = [];
let severityChart = null;
let ipChart = null;


// DOM ELEMENTS

const tableBody = document.getElementById("alertTableBody");
const searchInput = document.getElementById("searchInput");
const severityFilter = document.getElementById("severityFilter");
const statusFilter = document.getElementById("statusFilter");
const errorMessage = document.getElementById("errorMessage");


// =============================================
// ERROR HANDLING
// =============================================

function showError(message) {

    if (!errorMessage) {
        console.error(message);
        return;
    }

    errorMessage.textContent = message;
    errorMessage.hidden = false;
}

function clearError() {

    if (!errorMessage) return;

    errorMessage.textContent = "";
    errorMessage.hidden = true;
}


// =============================================
// CHECK CHART.JS
// =============================================

function checkChartLibrary() {

    if (typeof window.Chart === "undefined") {
        showError("Chart.js could not load.");
        return false;
    }

    return true;
}


// =============================================
// LOAD SECURITY ALERTS
// =============================================

async function loadAlerts() {

    try {

        clearError();

        const response = await fetch("/api/alerts", {
            credentials: "same-origin"
        });

        if (!response.ok) {
            throw new Error("Unable to load alerts. HTTP " + response.status);
        }

        const data = await response.json();

        if (!Array.isArray(data)) {
            throw new Error("Invalid alert API response.");
        }

        alerts = data;

        updateStatistics();
        displayAlerts();
        updateCharts();

        console.log("Alerts loaded:", alerts.length);

    } catch (error) {

        console.error("Alert loading error:", error);
        showError(error.message);

        if (tableBody) {
            tableBody.textContent = "Unable to load alerts.";
        }
    }
}


// =============================================
// UPDATE DASHBOARD STATISTICS
// =============================================

function updateStatistics() {

    const total = alerts.length;

    const high = alerts.filter(
        alert => String(alert.severity).toUpperCase() === "HIGH"
    ).length;

    const medium = alerts.filter(
        alert => String(alert.severity).toUpperCase() === "MEDIUM"
    ).length;

    const open = alerts.filter(
        alert => String(alert.status).toUpperCase() === "OPEN"
    ).length;

    const totalElement = document.getElementById("totalAlerts");
    const highElement = document.getElementById("highAlerts");
    const mediumElement = document.getElementById("mediumAlerts");
    const openElement = document.getElementById("openAlerts");

    if (totalElement) totalElement.textContent = total;
    if (highElement) highElement.textContent = high;
    if (mediumElement) mediumElement.textContent = medium;
    if (openElement) openElement.textContent = open;
}


// =============================================
// UPDATE ALERT STATUS
// =============================================

async function updateAlertStatus(alertId, newStatus, button) {

    const originalText = button.textContent;

    button.disabled = true;
    button.textContent = "Updating...";

    try {

        const response = await fetch(
            `/api/alerts/${encodeURIComponent(alertId)}/status`,
            {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json"
                },
                credentials: "same-origin",
                body: JSON.stringify({
                    status: newStatus
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to update alert.");
        }

        console.log("Status updated:", data);

        await loadAlerts();

    } catch (error) {

        console.error("Status update error:", error);
        alert(error.message);

        button.disabled = false;
        button.textContent = originalText;
    }
}


// =============================================
// SHOW INVESTIGATION HISTORY
// =============================================

async function showAlertHistory(alertId) {

    const panel = document.getElementById("alertDetails");

    if (!panel) {
        showError("Alert details panel is missing in index.html.");
        return;
    }

    panel.replaceChildren();
    panel.hidden = false;
    panel.style.display = "block";

    const heading = document.createElement("h3");
    heading.textContent = "Investigation History - Alert #" + alertId;

    panel.appendChild(heading);

    const loading = document.createElement("p");
    loading.textContent = "Loading investigation history...";

    panel.appendChild(loading);

    const closeButton = document.createElement("button");
    closeButton.textContent = "Close";
    closeButton.className = "action-button";

    closeButton.addEventListener("click", function () {
        panel.hidden = true;
        panel.style.display = "none";
    });

    panel.appendChild(closeButton);

    try {

        const response = await fetch(
            `/api/alerts/${encodeURIComponent(alertId)}/history`,
            {
                method: "GET",
                credentials: "same-origin"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || "Unable to load history."
            );
        }

        if (!Array.isArray(data)) {
            throw new Error("Invalid history API response.");
        }

        loading.remove();

        if (data.length === 0) {

            const emptyMessage = document.createElement("p");

            emptyMessage.textContent =
                "No investigation history available yet.";

            panel.appendChild(emptyMessage);

            return;
        }

        data.forEach(function (record) {

            const item = document.createElement("div");
            item.className = "history-item";

            const title = document.createElement("h4");

            title.textContent =
                (record.old_status || "NEW") +
                " → " +
                (record.new_status || "UNKNOWN");

            const username = document.createElement("p");

            username.textContent =
                "Changed by: " + (record.username || "Unknown");

            const timestamp = document.createElement("p");

            timestamp.textContent =
                "Time: " + (record.changed_at || "Not available");

            const details = document.createElement("p");

            details.textContent =
                record.details || "No additional details.";

            item.appendChild(title);
            item.appendChild(username);
            item.appendChild(timestamp);
            item.appendChild(details);

            panel.appendChild(item);
        });

        panel.scrollIntoView({
            behavior: "smooth",
            block: "nearest"
        });

    } catch (error) {

        console.error("History loading error:", error);

        loading.textContent = error.message;
        loading.style.color = "#dc2626";
    }
}


// =============================================
// DISPLAY SECURITY ALERTS
// =============================================

function displayAlerts() {

    if (!tableBody) return;

    const search = searchInput
        ? searchInput.value.toLowerCase().trim()
        : "";

    const selectedSeverity = severityFilter
        ? severityFilter.value
        : "ALL";

    const selectedStatus = statusFilter
        ? statusFilter.value
        : "ALL";

    const filteredAlerts = alerts.filter(function (alert) {

        const ip = String(
            alert.ip ?? alert.ip_address ?? ""
        ).toLowerCase();

        const severity = String(
            alert.severity ?? ""
        ).toUpperCase();

        const status = String(
            alert.status ?? ""
        ).toUpperCase();

        return (
            ip.includes(search) &&
            (selectedSeverity === "ALL" ||
                severity === selectedSeverity) &&
            (selectedStatus === "ALL" ||
                status === selectedStatus)
        );
    });

    tableBody.replaceChildren();

    if (filteredAlerts.length === 0) {

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.textContent = "No matching security alerts found.";

        row.appendChild(cell);
        tableBody.appendChild(row);

        return;
    }

    filteredAlerts.forEach(function (alert) {

        const row = document.createElement("tr");

        // Alert information columns

        const values = [
            alert.ip ?? alert.ip_address ?? "Unknown",
            alert.type ?? alert.alert_type ?? "Unknown",
            alert.count ?? alert.attempt_count ?? 0,
            alert.severity ?? "UNKNOWN",
            alert.status ?? "UNKNOWN"
        ];

        values.forEach(function (value, index) {

            const cell = document.createElement("td");

            cell.textContent = String(value);

            if (index === 3 || index === 4) {
                cell.className = String(value).toLowerCase();
            }

            row.appendChild(cell);
        });


        // ACTION COLUMN

        const actionCell = document.createElement("td");


        // VIEW BUTTON

        const viewButton = document.createElement("button");

        viewButton.textContent = "View";
        viewButton.className = "action-button";

        viewButton.addEventListener("click", function () {
            showAlertDetails(alert);
        });

        actionCell.appendChild(viewButton);


        // HISTORY BUTTON

        const historyButton = document.createElement("button");

        historyButton.textContent = "History";
        historyButton.className = "action-button";
        historyButton.style.marginLeft = "6px";

        historyButton.addEventListener("click", function () {
            showAlertHistory(alert.id);
        });

        actionCell.appendChild(historyButton);


        // STATUS MANAGEMENT BUTTON

        const currentStatus = String(
            alert.status ?? "OPEN"
        ).toUpperCase();

        let nextStatus = null;
        let buttonText = "";

        if (currentStatus === "OPEN") {

            nextStatus = "ACKNOWLEDGED";
            buttonText = "Acknowledge";

        } else if (currentStatus === "ACKNOWLEDGED") {

            nextStatus = "RESOLVED";
            buttonText = "Resolve";

        } else if (currentStatus === "RESOLVED") {

            nextStatus = "OPEN";
            buttonText = "Reopen";
        }


        if (nextStatus) {

            const statusButton = document.createElement("button");

            statusButton.textContent = buttonText;
            statusButton.className = "action-button";
            statusButton.style.marginLeft = "6px";

            statusButton.addEventListener("click", function () {

                updateAlertStatus(
                    alert.id,
                    nextStatus,
                    statusButton
                );

            });

            actionCell.appendChild(statusButton);
        }

        row.appendChild(actionCell);

        tableBody.appendChild(row);
    });
}


// =============================================
// VIEW ALERT DETAILS
// =============================================

function showAlertDetails(alert) {

    const panel = document.getElementById("alertDetails");

    if (!panel) {
        showError("Alert details panel not found.");
        return;
    }

    panel.replaceChildren();

    panel.hidden = false;
    panel.style.display = "block";

    const heading = document.createElement("h3");

    heading.textContent = "Security Alert Details";

    panel.appendChild(heading);

    const details = [
        ["Alert ID", alert.id],
        ["IP Address", alert.ip ?? alert.ip_address],
        ["Alert Type", alert.type ?? alert.alert_type],
        ["Attempts", alert.count ?? alert.attempts ?? alert.attempt_count],
        ["Severity", alert.severity],
        ["Status", alert.status],
        ["Description", alert.description],
        ["Username", alert.username],
        ["Detected At", alert.detected_at ?? alert.last_detected]
    ];

    details.forEach(function ([label, value]) {

        const paragraph = document.createElement("p");

        const strong = document.createElement("strong");

        strong.textContent = label + ": ";

        paragraph.appendChild(strong);

        paragraph.appendChild(
            document.createTextNode(
                String(value ?? "Not available")
            )
        );

        panel.appendChild(paragraph);
    });


    // CLOSE BUTTON

    const closeButton = document.createElement("button");

    closeButton.textContent = "Close Details";
    closeButton.className = "action-button";

    closeButton.addEventListener("click", function () {

        panel.hidden = true;
        panel.style.display = "none";

    });

    panel.appendChild(closeButton);

    panel.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });
}


// =============================================
// CREATE DASHBOARD CHARTS
// =============================================

function updateCharts() {

    if (!checkChartLibrary()) return;


    // COUNT SEVERITY

    const highCount = alerts.filter(
        alert => String(alert.severity).toUpperCase() === "HIGH"
    ).length;

    const mediumCount = alerts.filter(
        alert => String(alert.severity).toUpperCase() === "MEDIUM"
    ).length;

    const lowCount = alerts.filter(
        alert => String(alert.severity).toUpperCase() === "LOW"
    ).length;


    // SEVERITY DOUGHNUT CHART

    const severityCanvas =
        document.getElementById("severityChart");

    if (severityChart) {
        severityChart.destroy();
        severityChart = null;
    }

    if (severityCanvas) {

        severityChart = new Chart(severityCanvas, {

            type: "doughnut",

            data: {

                labels: ["HIGH", "MEDIUM", "LOW"],

                datasets: [{

                    data: [
                        highCount,
                        mediumCount,
                        lowCount
                    ],

                    backgroundColor: [
                        "#ef4444",
                        "#f59e0b",
                        "#22c55e"
                    ],

                    borderWidth: 2,
                    borderColor: "#1e293b"
                }]
            },

            options: {

                responsive: true,
                maintainAspectRatio: false,

                plugins: {

                    legend: {
                        display: true,
                        position: "bottom"
                    },

                    tooltip: {
                        enabled: true
                    }
                }
            }
        });
    }


    // TOP SUSPICIOUS IP CHART

    const ipCounts = {};

    alerts.forEach(function (alert) {

        const ip = alert.ip ?? alert.ip_address ?? "Unknown";

        const count = Number(
            alert.count ?? alert.attempts ?? alert.attempt_count ?? 1
        );

        ipCounts[ip] = (ipCounts[ip] || 0) + count;
    });

    const topIPs = Object.entries(ipCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);


    const ipCanvas = document.getElementById("ipChart");

    if (ipChart) {
        ipChart.destroy();
        ipChart = null;
    }

    if (ipCanvas) {

        ipChart = new Chart(ipCanvas, {

            type: "bar",

            data: {

                labels: topIPs.map(item => item[0]),

                datasets: [{

                    label: "Login Attempts",

                    data: topIPs.map(item => item[1]),

                    backgroundColor: "#3b82f6"
                }]
            },

            options: {

                indexAxis: "y",

                responsive: true,
                maintainAspectRatio: false,

                plugins: {

                    legend: {
                        display: true
                    }
                }
            }
        });
    }
}


// =============================================
// LOAD LOGIN ACTIVITY
// =============================================

async function loadLoginLogs() {

    const loginTableBody =
        document.getElementById("loginTableBody");

    if (!loginTableBody) return;

    try {

        const response = await fetch("/api/logs", {
            credentials: "same-origin"
        });

        if (!response.ok) {
            throw new Error("Login API unavailable.");
        }

        const logs = await response.json();

        loginTableBody.replaceChildren();

        if (!Array.isArray(logs) || logs.length === 0) {

            loginTableBody.textContent =
                "No login records found.";

            return;
        }

        logs.forEach(function (log) {

            const row = document.createElement("tr");

            const values = [
                log.timestamp,
                log.username,
                log.ip_address,
                log.status
            ];

            values.forEach(function (value) {

                const cell = document.createElement("td");

                cell.textContent = String(value ?? "");

                row.appendChild(cell);
            });

            loginTableBody.appendChild(row);
        });

    } catch (error) {

        console.error("Login logs error:", error);

        loginTableBody.textContent =
            "Login records could not be loaded.";
    }
}


// =============================================
// SEARCH AND FILTER EVENTS
// =============================================

if (searchInput) {
    searchInput.addEventListener("input", displayAlerts);
}

if (severityFilter) {
    severityFilter.addEventListener("change", displayAlerts);
}

if (statusFilter) {
    statusFilter.addEventListener("change", displayAlerts);
}


// =============================================
// REFRESH DASHBOARD
// =============================================

const refreshButton =
    document.getElementById("refreshButton");

if (refreshButton) {

    refreshButton.addEventListener("click", async function () {

        await loadAlerts();

        await loadLoginLogs();

    });
}


// =============================================
// RUN SECURITY DETECTION
// =============================================

const runDetectionBtn =
    document.getElementById("runDetectionBtn");

if (runDetectionBtn) {

    runDetectionBtn.addEventListener("click", async function () {

        const message =
            document.getElementById("detectionMessage");

        runDetectionBtn.disabled = true;

        runDetectionBtn.textContent = "Running Detection...";

        if (message) {

            message.textContent = "Analyzing security logs...";

            message.style.color = "#2563eb";
        }

        try {

            const response = await fetch("/api/run-detection", {

                method: "POST",

                credentials: "same-origin"
            });

            const data = await response.json();

            if (!response.ok) {

                throw new Error(
                    data.error || "Detection failed."
                );
            }

            if (message) {

                message.textContent =
                    "Detection completed successfully! " +
                    data.total_alerts +
                    " security risks detected.";

                message.style.color = "#16a34a";
            }

            await loadAlerts();

            await loadLoginLogs();

        } catch (error) {

            console.error("Detection error:", error);

            if (message) {

                message.textContent = error.message;

                message.style.color = "#dc2626";
            }

        } finally {

            runDetectionBtn.disabled = false;

            runDetectionBtn.textContent = "Run Detection";
        }
    });
}


// =============================================
// INITIALIZE DASHBOARD
// =============================================

async function initializeDashboard() {

    console.log("Security Dashboard initializing...");

    await loadAlerts();

    await loadLoginLogs();

    console.log("Security Dashboard initialized.");
}

initializeDashboard();
