#!/usr/bin/env python3
"""
Personal Firewall in Python (CLI)
- Sniffs packets using scapy
- Applies rule-based allow/block decisions
- Optionally enforces blocks at the OS level via iptables
- Logs events to a file

Requires: Linux, Python 3.8+, scapy, root privileges
"""
import argparse
import ipaddress
import logging
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except Exception as e:
    print("Error: scapy is required. Install with: pip install scapy", file=sys.stderr)
    raise

try:
    import yaml
except Exception as e:
    yaml = None  # We'll allow JSON too

# -------------------- Rule Model --------------------
@dataclass
class Rule:
    action: str  # "allow" or "block"
    direction: str  # "in", "out", or "any"
    protocol: str  # "tcp", "udp", "icmp", "any"
    src_ip: str = "any"
    dst_ip: str = "any"
    src_port: str = "any"
    dst_port: str = "any"
    description: str = ""

    def matches(self, pkt_meta: Dict[str, Any]) -> bool:
        # Direction
        if self.direction != "any" and pkt_meta["direction"] != self.direction:
            return False
        # Protocol
        if self.protocol != "any" and pkt_meta["protocol"] != self.protocol:
            return False
        # IPs
        if not _ip_match(self.src_ip, pkt_meta["src_ip"]):
            return False
        if not _ip_match(self.dst_ip, pkt_meta["dst_ip"]):
            return False
        # Ports (if applicable)
        if self.protocol in ("tcp", "udp"):
            if not _port_match(self.src_port, pkt_meta.get("src_port")):
                return False
            if not _port_match(self.dst_port, pkt_meta.get("dst_port")):
                return False
        return True

def _ip_match(rule_ip: str, value_ip: Optional[str]) -> bool:
    if rule_ip == "any" or value_ip is None:
        return True if rule_ip == "any" else False
    # Support single IP or CIDR
    try:
        network = ipaddress.ip_network(rule_ip, strict=False)
        return ipaddress.ip_address(value_ip) in network
    except ValueError:
        # Not a CIDR, try exact match or wildcard "*"
        if rule_ip == "*" or rule_ip.lower() == value_ip:
            return True
    return False

def _port_match(rule_port: str, value_port: Optional[int]) -> bool:
    if rule_port == "any":
        return True
    if value_port is None:
        return False
    # Support single port "80" or range "1000-2000" or list "80,443,8080"
    rule_port = str(rule_port)
    if "," in rule_port:
        return str(value_port) in {p.strip() for p in rule_port.split(",")}
    if "-" in rule_port:
        lo, hi = rule_port.split("-", 1)
        try:
            return int(lo) <= value_port <= int(hi)
        except ValueError:
            return False
    try:
        return int(rule_port) == value_port
    except ValueError:
        return False

# -------------------- Rule Engine --------------------
class RuleEngine:
    def __init__(self, rules: List[Rule], default_action: str = "allow"):
        self.rules = rules
        self.default_action = default_action

    def decide(self, pkt_meta: Dict[str, Any]) -> Rule:
        for r in self.rules:
            if r.matches(pkt_meta):
                return r
        # No match -> default action
        return Rule(action=self.default_action, direction="any", protocol="any", description="default")

# -------------------- iptables Manager --------------------
class IptablesManager:
    def __init__(self, enabled: bool = False, table: str = "filter"):
        self.enabled = enabled
        self.table = table

    def ensure_block_rule(self, pkt_meta: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        # Build a conservative iptables command to drop matching packets
        cmd = ["iptables", "-A", "INPUT" if pkt_meta["direction"] == "in" else "OUTPUT", "-j", "DROP"]
        # Protocol
        proto = pkt_meta["protocol"]
        if proto in ("tcp", "udp", "icmp"):
            cmd = ["iptables", "-A", "INPUT" if pkt_meta["direction"] == "in" else "OUTPUT", "-p", proto, "-j", "DROP"]
        # Src/Dst IP
        if pkt_meta["src_ip"]:
            cmd.extend(["-s", pkt_meta["src_ip"]])
        if pkt_meta["dst_ip"]:
            cmd.extend(["-d", pkt_meta["dst_ip"]])
        # Ports for TCP/UDP
        if proto in ("tcp", "udp"):
            if pkt_meta.get("src_port"):
                cmd.extend(["--sport", str(pkt_meta["src_port"])])
            if pkt_meta.get("dst_port"):
                cmd.extend(["--dport", str(pkt_meta["dst_port"])])

        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            logging.error("Failed to apply iptables rule: %s", e)

# -------------------- Packet Utilities --------------------
def extract_meta(packet, iface: str) -> Dict[str, Any]:
    meta = {
        "iface": iface,
        "direction": "any",
        "protocol": "any",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "length": len(packet)
    }
    if IP in packet:
        ip = packet[IP]
        meta["src_ip"] = ip.src
        meta["dst_ip"] = ip.dst
        # Direction heuristic: if packet was captured on iface and destination is not local, assume "out"
        # scapy doesn't easily provide direction; you can customize via separate sniffers on INPUT/OUTPUT chains with NFQUEUE for precision.
        meta["direction"] = "out" if packet.haslayer(TCP) or packet.haslayer(UDP) else "in"
        if TCP in packet:
            tcp = packet[TCP]
            meta["protocol"] = "tcp"
            meta["src_port"] = int(tcp.sport)
            meta["dst_port"] = int(tcp.dport)
        elif UDP in packet:
            udp = packet[UDP]
            meta["protocol"] = "udp"
            meta["src_port"] = int(udp.sport)
            meta["dst_port"] = int(udp.dport)
        elif ICMP in packet:
            meta["protocol"] = "icmp"
    return meta

# -------------------- Sniffer --------------------
class FirewallSniffer:
    def __init__(self, iface: str, engine: RuleEngine, ipt: IptablesManager, log_suspicious: bool = True):
        self.iface = iface
        self.engine = engine
        self.ipt = ipt
        self.log_suspicious = log_suspicious
        self.running = False

    def start(self):
        self.running = True
        sniff(iface=self.iface, prn=self._handle_packet, store=False, stop_filter=lambda x: not self.running)

    def stop(self, *args):
        self.running = False

    def _handle_packet(self, packet):
        meta = extract_meta(packet, self.iface)
        rule = self.engine.decide(meta)
        decision = rule.action
        # Log
        logging.info("%s %s %s -> %s %s %s %s | rule: %s",
                     decision.upper(),
                     meta["protocol"],
                     f'{meta["src_ip"]}:{meta["src_port"]}' if meta["src_port"] else meta["src_ip"],
                     f'{meta["dst_ip"]}:{meta["dst_port"]}' if meta["dst_port"] else meta["dst_ip"],
                     meta["direction"],
                     self.iface,
                     f'len={meta["length"]}',
                     (rule.description or "").strip())

        # If blocked, optionally enforce with iptables
        if decision == "block":
            self.ipt.ensure_block_rule(meta)

# -------------------- Config Loader --------------------
def load_rules(config_path: str) -> (List[Rule], str):
    with open(config_path, "r") as f:
        text = f.read()
    try:
        if config_path.endswith((".yml", ".yaml")):
            if yaml is None:
                raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
    except Exception:
        # Try YAML as fallback
        if yaml is not None:
            data = yaml.safe_load(text)
        else:
            raise

    default_action = data.get("default_action", "allow").lower()
    rules = []
    for r in data.get("rules", []):
        rules.append(Rule(
            action=r.get("action", "allow").lower(),
            direction=r.get("direction", "any").lower(),
            protocol=r.get("protocol", "any").lower(),
            src_ip=str(r.get("src_ip", "any")).lower(),
            dst_ip=str(r.get("dst_ip", "any")).lower(),
            src_port=str(r.get("src_port", "any")).lower(),
            dst_port=str(r.get("dst_port", "any")).lower(),
            description=r.get("description", ""),
        ))
    return rules, default_action

# -------------------- CLI --------------------
def parse_args():
    p = argparse.ArgumentParser(description="Personal Firewall using Python + scapy")
    p.add_argument("--iface", required=True, help="Network interface to sniff (e.g., eth0, wlan0)")
    p.add_argument("--config", default="rules.yaml", help="Path to rules.yaml or rules.json")
    p.add_argument("--log-file", default="firewall.log", help="Log file path")
    p.add_argument("--enforce-iptables", action="store_true", help="Apply DROP rules with iptables for blocked packets")
    p.add_argument("--verbose", action="store_true", help="Also log to console")
    return p.parse_args()

def setup_logging(log_file: str, verbose: bool):
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    handlers = [logging.FileHandler(log_file, mode="a")]
    if verbose:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=handlers
    )

def main():
    args = parse_args()
    setup_logging(args.log_file, args.verbose)
    try:
        rules, default_action = load_rules(args.config)
    except Exception as e:
        print(f"Failed to load rules from {args.config}: {e}", file=sys.stderr)
        sys.exit(2)

    engine = RuleEngine(rules, default_action=default_action)
    ipt = IptablesManager(enabled=args.enforce_iptables)
    sniffer = FirewallSniffer(args.iface, engine, ipt)

    # Graceful shutdown
    signal.signal(signal.SIGINT, sniffer.stop)
    signal.signal(signal.SIGTERM, sniffer.stop)

    logging.info("Starting firewall on %s with default_action=%s, iptables=%s", args.iface, default_action, args.enforce_iptables)
    try:
        sniffer.start()
    finally:
        logging.info("Firewall stopped.")

if __name__ == "__main__":
    main()
