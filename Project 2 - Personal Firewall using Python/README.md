# 🔥 Personal Firewall using Python (scapy + iptables + optional GUIs)

A lightweight personal firewall that:

* Sniffs packets with **scapy**
* Applies **rule-based allow/block decisions**
* Logs events to file/console
* Can optionally enforce rules via **iptables**
* Provides both **desktop (Tkinter)** and **web (Flask)** dashboards

> ⚠️ Packet sniffing & iptables require **root** (Linux only).

---

## ✨ Features

* ✅ Rule engine (first-match-wins)
* ✅ Match by **direction, protocol, IP, ports**
* ✅ Default action (`allow` / `block`)
* ✅ Structured logging (file + console)
* ✅ GUIs:

  * 🖥️ Tkinter desktop monitor
  * 🌐 Flask web dashboard
* ✅ Optional iptables enforcement (`--enforce-iptables`)

---

## 🚀 Quick Start (CLI)

```bash
# 1) Install dependencies
sudo apt update
sudo apt install -y python3-pip
pip3 install scapy pyyaml flask

# 2) Clone / copy this project
cd personal-firewall-python

# 3) Edit rules.yaml as needed

# 4) Run (needs root for sniffing)
sudo python3 firewall.py --iface eth0 --config rules.yaml --log-file firewall.log --verbose

# Enforce system-level blocks via iptables:
sudo python3 firewall.py --iface eth0 --config rules.yaml --log-file firewall.log --enforce-iptables --verbose
```

---

## 🖥️ Tkinter GUI

```bash
sudo python3 gui.py
```

* Choose interface (e.g., `eth0`, `wlan0`)
* Select rules file
* Start/Stop firewall from a simple window

---

## 🌐 Flask Web Dashboard

```bash
python3 flask_gui.py
```

* Open: [http://127.0.0.1:5000](http://127.0.0.1:5000)
* View & manage rules (add/delete)
* Live log viewer with ✅ ALLOW / ❌ BLOCK highlights

---

## 📜 Rules File

* **action**: `allow` | `block`
* **direction**: `in` | `out` | `any`
* **protocol**: `tcp` | `udp` | `icmp` | `any`
* **src\_ip** / **dst\_ip**: IP / CIDR / `*` / `any`
* **src\_port** / **dst\_port**: single (80), list (`80,443`), or range (`1000-2000`)
* **description**: free text

> `default_action`: `allow` (default) or `block` for default-deny.

---

## ⚡ Notes & Limitations

* Direction detection = heuristic (for full control, use **nfqueue + iptables**).
* `--enforce-iptables` appends DROP rules to INPUT/OUTPUT.

  * List: `sudo iptables -S`
  * Clear: `sudo iptables -F` ⚠️ use carefully!
* Tested on **Linux only** (macOS/Windows need pf/wfp).
* Recommended: run inside **VM/lab environment** first.

---

## 📝 Logging

Example log (`firewall.log`):

```
2025-08-21 10:15:22,533 | INFO | BLOCK tcp 10.1.2.3:55000 -> 203.0.113.8:23 out eth0 len=60 | rule: Block Telnet
```

---

## 📂 Project Structure

```
personal-firewall-python/
├── firewall.py        # CLI firewall
├── gui.py             # Tkinter GUI
├── flask_gui.py       # Flask Web Dashboard
├── templates/
│   └── index.html     # Flask UI template
├── rules.yaml         # Sample rules
└── README.md
```

