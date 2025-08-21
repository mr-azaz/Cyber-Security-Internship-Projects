# 🔥 Personal Firewall using Python

A lightweight **personal firewall** built with **Python + Scapy** that can sniff packets, apply rules, log decisions, and optionally block traffic using **iptables**.  
It also includes a simple **Tkinter GUI** for live monitoring.  

---

## 🚀 Features
- ✅ Packet sniffing using **Scapy**
- ✅ Rule-based filtering (IP, port, protocol, direction)
- ✅ Logging of ALLOW/BLOCK events (`firewall.log`)
- ✅ Optional **iptables enforcement** for real blocking
- ✅ Simple **GUI (Tkinter)** for monitoring

---

## 🛠️ Project Structure
📂 personal-firewall-python
├── firewall.py # CLI firewall
├── rules.yaml # Firewall rules (config file)
├── gui.py # Optional Tkinter GUI
