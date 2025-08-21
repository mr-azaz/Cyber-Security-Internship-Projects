# Personal Firewall using Python (scapy + iptables + optional GUI)

A lightweight personal firewall that sniffs packets with [scapy], applies rule-based
allow/block decisions, logs events, and (optionally) enforces blocks via `iptables`.

> **Note**: Packet sniffing and iptables changes require **root** on Linux.

## Features
- Rule engine with first-match-wins semantics
- Match by direction (in/out), protocol (tcp/udp/icmp/any), IP (CIDR supported), and ports (single, list, or range)
- Default action (allow/deny) when no rule matches
- Structured logging to file (and console with `--verbose`)
- Optional GUI (Tkinter) for live monitoring and start/stop
- Optional system-level blocking with `--enforce-iptables`

## Quick Start (CLI)
```bash
# 1) Install deps
sudo apt update
sudo apt install -y python3-pip
pip3 install scapy pyyaml

# 2) Clone / copy this project, then:
cd personal-firewall-python

# 3) Edit rules.yaml to your needs

# 4) Run (requires root for sniffing)
sudo python3 firewall.py --iface eth0 --config rules.yaml --log-file firewall.log --verbose
# To enforce system-level blocks via iptables:
sudo python3 firewall.py --iface eth0 --config rules.yaml --log-file firewall.log --enforce-iptables --verbose
```

## Optional GUI
```bash
sudo python3 gui.py
```
Select your interface (e.g., `eth0` or `wlan0`), choose your rules file, and click **Start**.

## Rules File
See `rules.yaml` for examples. Order matters, first match wins. Fields:
- `action`: `allow` | `block`
- `direction`: `in` | `out` | `any`
- `protocol`: `tcp` | `udp` | `icmp` | `any`
- `src_ip` / `dst_ip`: single IP, CIDR (e.g., `192.168.1.0/24`), `*`, or `any`
- `src_port` / `dst_port`: single (80), list (`80,443`), or range (`1000-2000`)
- `description`: free text

`default_action`: `allow` (default) or `block` if you want default-deny.

## Notes & Limitations
- Direction detection is heuristic in this demo. For precise control, consider integrating `nfqueue`/`iptables -j NFQUEUE` and deciding in userspace.
- `--enforce-iptables` appends targeted DROP rules to INPUT/OUTPUT. You can list them with `sudo iptables -S` and clear with `sudo iptables -F` (be careful!).
- Tested on Linux only. macOS/Windows require different backends (pf/wfp) and are not supported in this template.
- Run in a lab or VM first to avoid accidentally blocking yourself.

## Logging
Events are appended to `firewall.log`, e.g.:
```
2025-08-21 10:15:22,533 | INFO | BLOCK tcp 10.1.2.3:55000 -> 203.0.113.8:23 out eth0 len=60 | rule: Block Telnet
```

## Project Structure
```
personal-firewall-python/
├── firewall.py       # CLI firewall
├── gui.py            # Optional Tkinter GUI
├── rules.yaml        # Sample rule set
└── README.md
```

## License
MIT
