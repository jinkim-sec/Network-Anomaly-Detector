# anomaly_detector.py
# Network Anomaly Detector
# Day 3: Added off-hours access detection logic

import csv
from datetime import datetime
from collections import defaultdict


# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────

# Threshold for large data transfer detection (bytes)
# 500MB default
LARGE_TRANSFER_THRESHOLD = 500 * 1024 * 1024

# Off-hours definition (24hr format)
# Connections outside 08:00 - 18:00 are flagged
OFF_HOURS_START = 18
OFF_HOURS_END = 8

# Port scan detection threshold
# Flag if same source IP connects to this many different ports within the log
PORT_SCAN_THRESHOLD = 5


# ─────────────────────────────────────────
# Load and parse CSV traffic log
# ─────────────────────────────────────────

def load_traffic_log(filepath):
    """
    Load network traffic data from a CSV file.
    Expected columns: timestamp, src_ip, dst_ip,
    src_port, dst_port, protocol, bytes_transferred
    Returns a list of traffic record dicts.
    """
    records = []

    try:
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert data types for later analysis
                row["src_port"] = int(row["src_port"])
                row["dst_port"] = int(row["dst_port"])
                row["bytes_transferred"] = int(row["bytes_transferred"])
                row["timestamp"] = datetime.strptime(
                    row["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
                records.append(row)

        print(f"[✓] Loaded {len(records)} traffic records from {filepath}")
        return records

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return []
    except Exception as e:
        print(f"[ERROR] Failed to load traffic log: {e}")
        return []


# ─────────────────────────────────────────
# Detection: Port Scan
# ─────────────────────────────────────────

def detect_port_scans(records):
    """
    Detect potential port scanning activity.
    Flags any source IP that connects to more unique destination
    ports than the PORT_SCAN_THRESHOLD within the traffic log.
    Returns a list of anomaly dicts.
    """
    anomalies = []

    # Track unique destination ports per source IP
    # Key: src_ip, Value: set of destination ports
    ip_port_map = defaultdict(set)

    for record in records:
        src_ip = record["src_ip"]
        dst_port = record["dst_port"]
        ip_port_map[src_ip].add(dst_port)

    # Flag IPs that exceed the port scan threshold
    for src_ip, ports in ip_port_map.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            anomalies.append({
                "type": "PORT SCAN",
                "src_ip": src_ip,
                "dst_ip": "Multiple",
                "timestamp": "Multiple",
                "detail": f"Connected to {len(ports)} unique ports: "
                          f"{sorted(ports)}",
                "severity": "HIGH"
            })

    return anomalies


# ─────────────────────────────────────────
# Detection: Off-Hours Access
# ─────────────────────────────────────────

def detect_off_hours_access(records):
    """
    Detect network connections made outside of business hours.
    Business hours are defined in configuration as 08:00 - 18:00.
    Any connection outside this window is flagged as suspicious.
    Returns a list of anomaly dicts.
    """
    anomalies = []

    for record in records:
        hour = record["timestamp"].hour

        # Check if connection falls outside business hours
        # Flags connections before OFF_HOURS_END or after OFF_HOURS_START
        is_off_hours = (
            hour >= OFF_HOURS_START or hour < OFF_HOURS_END
        )

        if is_off_hours:
            anomalies.append({
                "type": "OFF-HOURS ACCESS",
                "src_ip": record["src_ip"],
                "dst_ip": record["dst_ip"],
                "timestamp": record["timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "detail": f"Connection detected at "
                          f"{record['timestamp'].strftime('%H:%M')} "
                          f"— outside business hours "
                          f"({OFF_HOURS_END:02d}:00 - "
                          f"{OFF_HOURS_START:02d}:00) "
                          f"on port {record['dst_port']}",
                "severity": "MEDIUM"
            })

    return anomalies


# ─────────────────────────────────────────
# Print anomalies to terminal
# ─────────────────────────────────────────

def print_anomalies(anomalies):
    """
    Display detected anomalies in a formatted terminal output.
    Includes a summary count of total anomalies detected.
    """
    print("\n" + "="*60)
    print("        NETWORK ANOMALY DETECTION REPORT")
    print("="*60)

    if not anomalies:
        print("\n[✓] No anomalies detected.")
    else:
        for anomaly in anomalies:
            print(f"\n[🔴 {anomaly['severity']}] {anomaly['type']}")
            print(f"  Source IP : {anomaly['src_ip']}")
            print(f"  Dest IP   : {anomaly['dst_ip']}")
            print(f"  Time      : {anomaly['timestamp']}")
            print(f"  Detail    : {anomaly['detail']}")

    print(f"\n{'='*60}")
    print(f"  SUMMARY: {len(anomalies)} anomaly(s) detected")
    print("="*60 + "\n")


# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────

if __name__ == "__main__":
    # Load traffic log
    records = load_traffic_log("sample_data/sample_traffic.csv")

    if records:
        all_anomalies = []

        # Run port scan detection
        print("\n[*] Running port scan detection...")
        port_scan_anomalies = detect_port_scans(records)
        all_anomalies.extend(port_scan_anomalies)

        # Run off-hours access detection
        print("[*] Running off-hours access detection...")
        off_hours_anomalies = detect_off_hours_access(records)
        all_anomalies.extend(off_hours_anomalies)

        # Display all results
        print_anomalies(all_anomalies)
```
