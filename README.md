# Cyber Security Internship Projects

This repository contains projects completed during my Cyber Security Internship. Each project is organized in its own folder.

---

## Project 1: Web Application Vulnerability Scanner

A Python-based web application vulnerability scanner built with **Flask**, capable of detecting common web security issues such as:

- **Cross-Site Scripting (XSS)**
- **SQL Injection (SQLi)**
- **Missing Security Headers**

### Features

- Web interface to input target URLs.
- Crawls forms on the target website automatically.
- Logs detected vulnerabilities in an SQLite database.
- Displays scan results with timestamp and type.
- Color-coded results for better readability.

### Folder Structure

web-vulnerability-scanner/
├── app.py # Main Flask application
├── scanner.py # Core vulnerability scanning logic
├── templates/ # HTML templates
├── static/ # CSS/JS for UI
└── README.md # Setup and usage guide

---

## 📌 Project 2: Personal Firewall in Python

A lightweight **personal firewall** built using Python.  
It captures, analyzes, and filters network packets in real-time.

### ⚙️ Features
- Sniffs packets using **Scapy**.
- Applies **rules** (allow/block by IP, port, protocol, direction).
- Logs every decision to `firewall.log`.
- Optional **iptables enforcement** for real packet blocking.
- Simple **Tkinter GUI** for starting/stopping and live log view.

### 🛠️ How It Works
1. **Sniff** → Capture packets from a chosen interface.  
2. **Extract** → Gather metadata (protocol, IPs, ports, length).  
3. **Decide** → Match against ordered rules in `rules.yaml`.  
4. **Log** → Record ALLOW/BLOCK decision.  
5. **Enforce (optional)** → Append DROP rules via iptables.

### 📂 Folder Structure

personal-firewall-python/
├── firewall.py # Main CLI firewall program
├── gui.py # Optional Tkinter GUI
├── rules.yaml # Rulebook (first-match-wins)
└── README.md # Setup and usage guide
