# 📘 Technical Report: Python Network Monitor

## 1. Introduction
This document details the technical implementation of the **Network Monitor**, a defensive security tool designed to detect, analyze, and log active network connections in real-time.

### The Problem
Traditional antivirus solutions are often heavy and opaque. The goal was to build a lightweight, transparent tool that provides immediate visibility into **what** is connecting to the internet and **why**, answering three key questions:
1.  Which process is connecting?
2.  Where is it connecting to? (GeoIP)
3.  Is the process malicious? (VirusTotal Analysis)

---

## 2. System Architecture

The tool operates in a continuous loop with four main components:

### A. Connection Discovery (`netstat`)
Instead of using heavy packet sniffing libraries like `scapy` for everything (which can be slow on Windows), the tool parses the output of the native `netstat -ano` command.
*   **Why Netstat?** It's built-in, fast, and provides the PID (Process ID) for every connection.
*   **Filtering:** The script specifically filters for `ESTABLISHED` connections to focus on active data transfer.

### B. Process Mapping (PID to Path)
A critical challenge was mapping a PID (e.g., `1234`) to the actual executable path (e.g., `C:\Users\Malware.exe`).
*   **Solution:** The script uses a PowerShell subprocess (`Get-Process`) to fetch the full path of running processes.
*   **Optimization:** Since querying PowerShell is expensive, this mapping is cached and only refreshed every 60 seconds.

### C. Threat Intelligence (VirusTotal API)
Once the executable path is known, the tool calculates its **SHA-256 hash**.
*   **API Integration:** This hash is sent to the VirusTotal v3 API.
*   **Rate Limiting Protection:** To avoid hitting API limits (4 requests/minute for free accounts), the script implements a local `VT_CACHE`. If a file hash has been checked once, it is never checked again during the session.

### D. Geo-Location
The remote IP address is queried against `ip-api.com` to determine the hosting country and organization (ISP).

---

## 3. Key Technical Challenges & Solutions

### Challenge 1: Performance vs. Rate Limits
*   **Issue:** Checking every connection against VirusTotal would instantly ban the API key.
*   **Solution:** Implemented a double-layer cache:
    1.  **Connection Cache:** Known `Process:IP` pairs are ignored after the first alert.
    2.  **Hash Cache:** File hashes are stored in memory so the same executable (e.g., `chrome.exe`) is only scanned once.

### Challenge 2: Windows Permissions
*   **Issue:** Python cannot always read the path of system processes (like `svchost.exe`) due to permissions.
*   **Solution:** The script handles `PermissionError` gracefully. If the path cannot be read, it reports "Path Not Found" rather than crashing, maintaining stability.

---

## 4. Future Improvements
*   [ ] **GUI Interface:** Move from CLI to a graphical dashboard (Tkinter/PyQt).
*   [ ] **Database Storage:** Replace CSV logging with SQLite for better querying.
*   [ ] **Automatic Blocking:** Integrate with Windows Firewall to block malicious IPs automatically.

---

## 5. Usage
To run the monitor with full analysis capabilities:

```bash
# Set API Key (Optional but recommended)
$env:VIRUSTOTAL_API_KEY = "your_api_key"

# Run
python network_monitor.py
```
