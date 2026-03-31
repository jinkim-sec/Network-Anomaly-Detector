# Network Anomaly Detector

A Python tool that analyses network traffic logs to detect
suspicious patterns including port scans, off-hours access,
and large data transfers. Built as part of a cybersecurity
learning portfolio to demonstrate network traffic analysis
concepts used in real-world SOC environments.

## Features
- Detects potential port scanning activity
- Flags network connections made outside business hours
- Identifies unusually large data transfers (potential exfiltration)
- Sorts anomalies by severity (CRITICAL → HIGH → MEDIUM)
- Exports results to a timestamped CSV report
- All detection thresholds are configurable

## Requirements
- Python 3.x
- No external libraries required

## Usage
```bash
python anomaly_detector.py
```

Place your network traffic log at:
```
sample_data/sample_traffic.csv
```

## Input Format
CSV file with the following columns:
```
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes_transferred
2025-11-01 09:15:23,192.168.1.10,10.0.0.5,54321,80,TCP,1500
```

## Configuration
Edit the configuration section in `anomaly_detector.py`
to adjust detection thresholds:
```python
# Flag transfers above this size (bytes) — default 500MB
LARGE_TRANSFER_THRESHOLD = 500 * 1024 * 1024

# Business hours definition (24hr format)
OFF_HOURS_START = 18
OFF_HOURS_END = 8

# Flag IPs connecting to this many unique ports
PORT_SCAN_THRESHOLD = 5
```

## Example Output
```
[✓] Loaded 11 traffic records from sample_data/sample_traffic.csv

[*] Running port scan detection...
[*] Running off-hours access detection...
[*] Running large transfer detection...

============================================================
        NETWORK ANOMALY DETECTION REPORT
============================================================

[🔴 CRITICAL] LARGE DATA TRANSFER
  Source IP : 192.168.1.20
  Dest IP   : 10.0.0.8
  Time      : 2025-11-01 14:22:05
  Detail    : Transferred 0.88 GB (950,500,000 bytes)
              to 10.0.0.8 on port 21 via TCP

[🔴 HIGH] PORT SCAN
  Source IP : 192.168.1.30
  Dest IP   : Multiple
  Time      : Multiple
  Detail    : Connected to 6 unique ports:
              [22, 23, 80, 443, 3389, 8080]

[🟡 MEDIUM] OFF-HOURS ACCESS
  Source IP : 192.168.1.15
  Dest IP   : 10.0.0.5
  Time      : 2025-11-01 02:33:10
  Detail    : Connection detected at 02:33 — outside
              business hours (08:00 - 18:00) on port 22

============================================================
  SUMMARY: 3 anomaly(s) detected
  🔴 CRITICAL: 1 | HIGH: 1 | 🟡 MEDIUM: 1
============================================================

[✓] Report saved: anomaly_report_20251101_142305.csv
```

## Project Structure
```
network-anomaly-detector/
│
├── anomaly_detector.py    # Main detection script
├── requirements.txt       # Dependencies
├── README.md
├── .gitignore
├── LICENSE
└── sample_data/
    └── sample_traffic.csv # Sample network traffic log
```

## Detection Modules

### Port Scan Detection
Tracks the number of unique destination ports each source
IP connects to. Flags any IP exceeding the configured
threshold as a potential port scan.

### Off-Hours Access Detection
Flags any network connection made outside defined business
hours. Useful for detecting unauthorised after-hours access
or compromised credentials being used at unusual times.

### Large Transfer Detection
Flags any single connection that transfers data above the
configured threshold. Helps identify potential data
exfiltration or unauthorised bulk data movement.

## Key Concepts Demonstrated
- Network traffic log analysis
- Anomaly detection using threshold-based rules
- Port scan identification
- Data exfiltration pattern recognition
- Automated CSV report generation

## Disclaimer
This tool is for educational purposes only.
Only use on network logs you own or have explicit
permission to analyse.

## Author
Jin Hyuck Kim
github.com/[jinkim-sec]
```
