# alerthub
SIEM-style Python log analyzer that reads CSV files to detect port scans, failed logins, and malware patterns for SecOps training and SOC alerting.
# 🚨 AlertHub – SecOps Log Analyzer (CSV-Based)

**AlertHub** is a Python-based command-line tool that simulates SIEM-style behavior by reading CSV logs and detecting suspicious patterns such as:
- Failed login attempts
- Port scans
- Malware-related keywords

Perfect for SecOps, SOC Analysts, and cybersecurity learners.

## 🚀 Features

- Reads CSV logs (syslog, firewall, IDS exports)
- Tags events with known alert signatures
- Extracts high-frequency IPs
- Saves report to file

## 🛠️ Usage

```bash
python alerthub.py -f logs.csv -o alert_report.txt
