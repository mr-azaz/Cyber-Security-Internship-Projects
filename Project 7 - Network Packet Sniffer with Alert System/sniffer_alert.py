import argparse
import sqlite3
import time
import threading
from collections import Counter

from scapy.all import sniff, IP, TCP, UDP, wrpcap
import matplotlib.pyplot as plt
import smtplib
from email.mime.text import MIMEText

# === Email Alert Config ===
EMAIL_ENABLED = True
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your_email@gmail.com"
SENDER_PASSWORD = "your_app_password"   # Use an App Password, not your normal one
RECEIVER_EMAIL = "receiver_email@gmail.com"

# === Database Setup ===
def init_db(db_name):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS traffic (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        protocol TEXT,
                        length INTEGER,
                        info TEXT)""")
    conn.commit()
    return conn

# === Alert Logging ===
def log_alert(message):
    timestamped = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    # Log to file
    with open("alerts.log", "a") as f:
        f.write(timestamped + "\n")
    print(f"[ALERT] {message}")

    # Send Email Alert
    if EMAIL_ENABLED:
        try:
            msg = MIMEText(message)
            msg["Subject"] = "🚨 Network Alert"
            msg["From"] = SENDER_EMAIL
            msg["To"] = RECEIVER_EMAIL

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

            print("[*] Email alert sent successfully!")
        except Exception as e:
            print(f"[!] Failed to send email: {e}")

# === Global Counter for Live GUI ===
traffic_counter = Counter()

def live_plot():
    plt.ion()
    fig, ax = plt.subplots()
    while True:
        ax.clear()
        protocols = list(traffic_counter.keys())
        counts = list(traffic_counter.values())
        ax.bar(protocols, counts, color='skyblue')
        ax.set_title("Live Traffic by Protocol")
        ax.set_xlabel("Protocol")
        ax.set_ylabel("Packets")
        plt.pause(2)

# === Packet Handler ===
def process_packet(packet, conn, alert_threshold=50):
    cursor = conn.cursor()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        protocol = "OTHER"
        info = ""

        if TCP in packet:
            protocol = "TCP"
            info = f"Sport={packet[TCP].sport}, Dport={packet[TCP].dport}, Flags={packet[TCP].flags}"
        elif UDP in packet:
            protocol = "UDP"
            info = f"Sport={packet[UDP].sport}, Dport={packet[UDP].dport}"

        # Insert into DB
        cursor.execute("INSERT INTO traffic (timestamp, src_ip, dst_ip, protocol, length, info) VALUES (?, ?, ?, ?, ?, ?)",
                       (timestamp, src_ip, dst_ip, protocol, length, info))
        conn.commit()

        # Update counter for GUI
        traffic_counter[protocol] += 1

        # === Simple Anomaly Detection ===
        if length > 1200:
            log_alert(f"Possible DoS attack detected from {src_ip} (Packet length={length})")

# === Sniffer ===
def start_sniffer(iface, db_name, pcap_out=None, packet_count=0):
    conn = init_db(db_name)
    print(f"[*] Starting sniffer on {iface}...")

    # Start GUI thread
    threading.Thread(target=live_plot, daemon=True).start()

    packets = sniff(iface=iface, prn=lambda pkt: process_packet(pkt, conn), store=True, count=packet_count)

    if pcap_out:
        wrpcap(pcap_out, packets)
        print(f"[*] Packets saved to {pcap_out}")

    conn.close()

# === Report Generation ===
def generate_report(db_name):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("SELECT protocol, COUNT(*) FROM traffic GROUP BY protocol")
    data = cursor.fetchall()
    conn.close()

    if data:
        protocols = [row[0] for row in data]
        counts = [row[1] for row in data]

        plt.figure(figsize=(6, 6))
        plt.pie(counts, labels=protocols, autopct='%1.1f%%')
        plt.title("Traffic Summary by Protocol")
        plt.savefig("traffic_summary.png")
        print("[*] Traffic summary chart saved as traffic_summary.png")
    else:
        print("[!] No traffic data available to generate report.")

# === Main ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Packet Sniffer with Alerts")
    subparsers = parser.add_subparsers(dest="command")

    sniff_parser = subparsers.add_parser("sniff", help="Start packet sniffer")
    sniff_parser.add_argument("--iface", required=True, help="Network interface")
    sniff_parser.add_argument("--db", default="traffic.db", help="SQLite database file")
    sniff_parser.add_argument("--pcap-out", help="Save captured packets to pcap file")
    sniff_parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")

    report_parser = subparsers.add_parser("report", help="Generate traffic report")
    report_parser.add_argument("--db", default="traffic.db", help="SQLite database file")

    args = parser.parse_args()

    if args.command == "sniff":
        start_sniffer(args.iface, args.db, args.pcap_out, args.count)
    elif args.command == "report":
        generate_report(args.db)
    else:
        parser.print_help()
