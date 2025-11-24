import subprocess
import re
import json
import urllib.request
import time
import csv
import os
import hashlib
from datetime import datetime
from collections import defaultdict

# --- CONFIGURATION ---
# Get API Key from environment variable for security
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
if not VIRUSTOTAL_API_KEY:
    print("[!] WARNING: VIRUSTOTAL_API_KEY environment variable not set.")
    print("    VirusTotal checks will fail. Please set it before running.")
    # You can also hardcode it here for local testing, but DO NOT commit it to GitHub.
    # VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"

# Determine the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "network_log.csv")

# Caches
IP_CACHE = {}
VT_CACHE = {} # Hash -> VT Result
PID_PATH_MAP = {} # PID -> Executable Path

def get_process_paths():
    """
    Refreshes the PID -> Path mapping using PowerShell.
    """
    global PID_PATH_MAP
    try:
        cmd = 'powershell "Get-Process | Select-Object Id, Path | ConvertTo-Csv -NoTypeInformation"'
        output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
        
        for line in output.splitlines():
            if not line.strip() or "Id" in line:
                continue
            # CSV format: "1234","C:\Path\To\File.exe"
            parts = line.split('","')
            if len(parts) >= 2:
                pid = parts[0].replace('"', '').strip()
                path = parts[1].replace('"', '').strip()
                if path:
                    PID_PATH_MAP[pid] = path
    except Exception as e:
        # print(f"Warning: Could not fetch process paths: {e}")
        pass

def get_process_map():
    """
    Returns a dictionary mapping PID (str) to Process Name (str).
    """
    process_map = {}
    try:
        cmd = 'tasklist /fo CSV /nh'
        output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
        
        for line in output.splitlines():
            if not line.strip():
                continue
            parts = line.split(',')
            if len(parts) >= 2:
                p_name = parts[0].strip('"')
                pid = parts[1].strip('"')
                process_map[pid] = p_name
    except Exception as e:
        print(f"Warning: Could not fetch process list: {e}")
    
    return process_map

def get_file_hash(filepath):
    """
    Calculates SHA-256 hash of a file.
    """
    if not filepath or not os.path.exists(filepath):
        return None
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            # Read in chunks to avoid memory issues with large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def check_virustotal(file_hash):
    """
    Queries VirusTotal API for a file hash.
    Returns a summary string (e.g., "0/70 Clean" or "5/70 MALICIOUS").
    """
    if not file_hash:
        return "No Hash"
    
    if not VIRUSTOTAL_API_KEY:
        return "No API Key"

    if file_hash in VT_CACHE:
        return VT_CACHE[file_hash]

    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        req = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            total = sum(stats.values())
            
            if malicious > 0:
                result = f"[!] {malicious}/{total} MALICIOUS"
            else:
                result = f"[OK] {malicious}/{total} Clean"
            
            VT_CACHE[file_hash] = result
            return result
            
    except urllib.error.HTTPError as e:
        if e.code == 404:
            res = "❓ Unknown to VT"
            VT_CACHE[file_hash] = res
            return res
        elif e.code == 429:
            return "⏳ Rate Limit"
        else:
            return f"❌ API Error {e.code}"
    except Exception as e:
        return f"❌ Error: {e}"

def get_ip_details(ip):
    # Skip local IPs
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip == "0.0.0.0" or ip == "[::1]":
        return {"country": "Local Network", "org": "-"}
    
    if ip in IP_CACHE:
        return IP_CACHE[ip]

    try:
        time.sleep(0.1) 
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url, timeout=2) as response:
            data = json.loads(response.read().decode())
            if data['status'] == 'success':
                info = {
                    "country": data.get("country", "Unknown"),
                    "org": data.get("org", data.get("isp", "Unknown"))
                }
            else:
                info = {"country": "Unknown", "org": "Unknown"}
            IP_CACHE[ip] = info
            return info
    except Exception:
        return {"country": "Lookup Failed", "org": "-"}

def get_connections():
    connections = []
    process_map = get_process_map()
    
    try:
        cmd = 'netstat -ano'
        output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
        
        for line in output.splitlines():
            if "ESTABLISHED" in line:
                parts = line.split()
                if len(parts) >= 5:
                    remote_full = parts[2]
                    if "]:" in remote_full:
                        remote_ip = remote_full.split("]:")[0].replace("[", "")
                    elif ":" in remote_full:
                        remote_ip = remote_full.split(":")[0]
                    else:
                        remote_ip = remote_full

                    conn = {
                        "proto": parts[0],
                        "local": parts[1],
                        "remote": remote_full,
                        "remote_ip": remote_ip,
                        "pid": parts[4],
                        "process_name": process_map.get(parts[4], "Unknown")
                    }
                    connections.append(conn)
    except Exception as e:
        print(f"Error running netstat: {e}")
        
    return connections

def log_connection(conn, vt_result, status):
    file_exists = os.path.isfile(LOG_FILE)
    geo_info = get_ip_details(conn['remote_ip'])
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Process", "PID", "Remote IP", "Country", "Organization", "Status", "VirusTotal"])
        
        writer.writerow([
            timestamp,
            conn['process_name'],
            conn['pid'],
            conn['remote_ip'],
            geo_info['country'],
            geo_info['org'],
            status,
            vt_result
        ])

def monitor_loop():
    print("\n" + "="*80)
    print("   NETWORK MONITOR - GITHUB EDITION")
    print("   Press Ctrl+C to stop")
    print("="*80)
    print(f"[*] Logging to: {os.path.abspath(LOG_FILE)}")
    
    if not VIRUSTOTAL_API_KEY:
        print("[!] NO API KEY DETECTED. VirusTotal checks will be skipped.")
    
    print("[*] Updating process paths...")
    get_process_paths()
    print("[*] Monitoring for NEW connections...\n")

    known_connections = set()
    initial_conns = get_connections()
    for c in initial_conns:
        sig = f"{c['process_name']}:{c['remote_ip']}"
        known_connections.add(sig)
    
    print(f"[*] Baseline established: {len(known_connections)} active connections ignored.")
    
    last_path_refresh = time.time()

    try:
        while True:
            # Refresh paths every 60 seconds to catch new processes
            if time.time() - last_path_refresh > 60:
                get_process_paths()
                last_path_refresh = time.time()

            current_conns = get_connections()
            
            for c in current_conns:
                sig = f"{c['process_name']}:{c['remote_ip']}"
                
                if sig not in known_connections:
                    known_connections.add(sig)
                    
                    # Analysis
                    geo = get_ip_details(c['remote_ip'])
                    
                    # VirusTotal Check (Always check, relying on Cache)
                    pid = c['pid']
                    path = PID_PATH_MAP.get(pid)
                    
                    if path:
                        file_hash = get_file_hash(path)
                        if file_hash:
                            # Check VT (will use cache if available)
                            if file_hash not in VT_CACHE:
                                print(f"    > Analyzing {c['process_name']} ({file_hash[:8]}...)...")
                            vt_result = check_virustotal(file_hash)
                        else:
                            vt_result = "Hash Failed"
                    else:
                        vt_result = "Path Not Found"

                    # Determine Status based on VT result
                    if "MALICIOUS" in vt_result:
                        status = "DANGER"
                        alert_symbol = "[!!!]"
                    elif "Clean" in vt_result:
                        status = "SAFE"
                        alert_symbol = "[+]"
                    else:
                        status = "UNKNOWN"
                        alert_symbol = "[?]"
                    
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    
                    print(f"{timestamp} {alert_symbol} NEW: {c['process_name']:<20} -> {c['remote_ip']:<15} ({geo['country']})")
                    print(f"         VT: {vt_result}")
                    print("-" * 60)
                    
                    log_connection(c, vt_result, status)
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped.")

if __name__ == "__main__":
    monitor_loop()
