# 🛡️ Network Packet Sniffer with Alert System

A **real-time network traffic sniffer** built in Python.  
It captures packets, detects anomalies like **DoS attacks** and **port scans**, logs them in a database, and optionally sends **email alerts**.

---

## ✨ Features
- 🖧 Capture live network packets and log headers: **IP, Port, Length, Flags**
- 🚨 Detect anomalies: DoS attacks, Port scanning, and more
- 💾 Store captured data in **SQLite** for historical analysis
- 📧 Optional **email alerts** on anomaly detection
- 📊 Optional live **traffic graph** using **Matplotlib**

---

## 🛠 Tools & Technologies
- **Python 3**
- **Scapy** – Packet sniffing
- **SQLite** – Database storage
- **Matplotlib** – Traffic visualization

---

## 🏃 How to Run

1. **Activate the virtual environment:**

```bash
source ~/project7_venv/bin/activate
Run the sniffer:

~/project7_venv/bin/python sniffer_alert.py sniff --iface eth0 --db traffic.db --pcap-out capture.pcap

"Replace eth0 with your network interface, and traffic.db / capture.pcap with your preferred filenames."

⚡ Setup Git & Upload to GitHub
Initialize Git and commit:


git init
git add .
git commit -m "Initial commit - Network Packet Sniffer with Alert System"
Create a repository on GitHub (e.g., Network-Packet-Sniffer)

Leave it public or private

Do not initialize with README

Link local repo to GitHub and push:


git remote add origin https://github.com/yourusername/Network-Packet-Sniffer.git
git branch -M main
git push -u origin main


⚠ Notes
❌ Do not include real Gmail credentials in the repository.

Replace placeholders in sniffer_alert.py with your local credentials if using email alerts:


SENDER_EMAIL = "your_email@gmail.com"
SENDER_PASSWORD = "YOUR_APP_PASSWORD"
RECEIVER_EMAIL = "receiver_email@gmail.com"
Optional: Upgrade the project later with more anomalies and a GUI interface.

📜 License
This project is for educational purposes only.
