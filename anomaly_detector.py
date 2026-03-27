# anomaly_detector.py
# Network Anomaly Detector
# Day 1: Project setup and CSV traffic log parser

import csv
from datetime import datetime


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
# Entry point
# ─────────────────────────────────────────

if __name__ == "__main__":
    # Load sample traffic log for testing
    records = load_traffic_log("sample_data/sample_traffic.csv")

    # Preview first 3 records
    print("\n[*] Preview of loaded records:")
    for record in records[:3]:
        print(f"  {record['timestamp']} | "
              f"{record['src_ip']} → {record['dst_ip']} | "
              f"Port: {record['dst_port']} | "
              f"Bytes: {record['bytes_transferred']}")
```

