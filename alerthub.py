import csv
import argparse
from collections import defaultdict

alert_signatures = {
    "Failed Login": ["failed login", "authentication failure", "invalid password"],
    "Port Scan": ["SYN", "port scan", "masscan"],
    "Malware": ["malware", "trojan", "exploit"],
}

ip_events = defaultdict(int)
alerts = []

def scan_csv(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            line = " ".join(row).lower()

            for tag, keywords in alert_signatures.items():
                if any(keyword in line for keyword in keywords):
                    alerts.append((tag, row))
                    ip = row[0] if row else "unknown"
                    ip_events[ip] += 1
                    break

def generate_report(output_file=None):
    print(f"\n🚨 Total Alerts: {len(alerts)}")
    for tag, row in alerts[:10]:
        print(f"[{tag}] {' | '.join(row)[:100]}...")

    print("\n📊 Top IPs by Events:")
    for ip, count in sorted(ip_events.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip} → {count} events")

    if output_file:
        with open(output_file, "w") as f:
            f.write("Alert Summary:\n")
            for tag, row in alerts:
                f.write(f"[{tag}] {' | '.join(row)}\n")
            f.write("\nTop IPs:\n")
            for ip, count in sorted(ip_events.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{ip} → {count} events\n")
        print(f"\n📁 Report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="🚨 AlertHub - SecOps Log Analyzer")
    parser.add_argument("-f", "--file", required=True, help="CSV log file path")
    parser.add_argument("-o", "--output", help="Optional file to save alert report")
    args = parser.parse_args()

    scan_csv(args.file)
    generate_report(args.output)

if __name__ == "__main__":
    main()
