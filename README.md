# 🛡️ Python Network Monitor

A lightweight, real-time network monitoring tool for Windows. It detects new connections, identifies the process responsible, resolves the destination country (GeoIP), and checks the file hash against **VirusTotal** to detect potential malware.

## Features

*   **Real-Time Monitoring**: Continuously scans for new established connections.
*   **Process Identification**: Maps connections to the specific process (PID and Name) and executable path.
*   **GeoIP Lookup**: Identifies the country and organization of the remote IP address.
*   **Malware Detection**: Automatically calculates the SHA-256 hash of the process and queries the **VirusTotal API** to check if it's a known threat.
*   **Smart Caching**: Caches API results to respect rate limits and improve performance.
*   **Logging**: Saves a detailed history of all connections to `network_log.csv`.

## Requirements

*   Windows OS
*   Python 3.x
*   No external Python libraries required (uses standard library only).
*   A free **VirusTotal API Key** (optional but recommended).

## Installation

1.  Clone this repository:
    ```bash
    git clone https://github.com/yourusername/network-monitor.git
    cd network-monitor
    ```

2.  (Optional) Get a free API Key from [VirusTotal](https://www.virustotal.com/).

## Usage

### 1. Set your API Key (Recommended)
For security, do not hardcode your key. Set it as an environment variable:

**PowerShell:**
```powershell
$env:VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"
```

**CMD:**
```cmd
set VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE
```

### 2. Run the Script
```bash
python network_monitor.py
```

The script will start monitoring. Keep the terminal window open. Press `Ctrl+C` to stop.

## Logs
All activity is saved to `network_log.csv` in the same directory as the script.

## 📚 Technical Documentation
Interested in how this tool works under the hood?
[Read the full Technical Report here](./TECHNICAL_REPORT.md)

## Disclaimer
This tool is for educational and defensive purposes only. Use responsibly.
