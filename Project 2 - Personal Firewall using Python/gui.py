#!/usr/bin/env python3
"""
Optional GUI for live monitoring using Tkinter.
This wraps the CLI firewall in a thread and streams the log file into the UI.
"""
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import sys

class FirewallGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Personal Firewall (Python + scapy)")
        self.geometry("900x600")
        self.firewall_proc = None
        self.log_path = "firewall.log"

        # Controls
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="x")

        ttk.Label(frm, text="Interface:").grid(row=0, column=0, sticky="w")
        self.iface_var = tk.StringVar(value="eth0")
        ttk.Entry(frm, textvariable=self.iface_var, width=15).grid(row=0, column=1, sticky="w", padx=6)

        ttk.Label(frm, text="Rules file:").grid(row=0, column=2, sticky="w")
        self.rules_var = tk.StringVar(value="rules.yaml")
        ttk.Entry(frm, textvariable=self.rules_var, width=30).grid(row=0, column=3, sticky="we", padx=6)
        ttk.Button(frm, text="Browse", command=self.browse_rules).grid(row=0, column=4, sticky="w")

        self.iptables_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Enforce iptables", variable=self.iptables_var).grid(row=0, column=5, sticky="w", padx=12)

        ttk.Button(frm, text="Start", command=self.start_fw).grid(row=1, column=0, pady=8)
        ttk.Button(frm, text="Stop", command=self.stop_fw).grid(row=1, column=1, pady=8)

        # Log viewer
        self.text = tk.Text(self, wrap="none")
        self.text.pack(fill="both", expand=True)
        self.after(1000, self.tail_log)

    def browse_rules(self):
        path = filedialog.askopenfilename(title="Select rules file", filetypes=[("YAML/JSON", "*.yaml *.yml *.json")])
        if path:
            self.rules_var.set(path)

    def start_fw(self):
        if self.firewall_proc and self.firewall_proc.poll() is None:
            messagebox.showinfo("Running", "Firewall is already running.")
            return
        iface = self.iface_var.get().strip()
        rules = self.rules_var.get().strip()
        cmd = [sys.executable, "firewall.py", "--iface", iface, "--config", rules, "--log-file", self.log_path, "--verbose"]
        if self.iptables_var.get():
            cmd.append("--enforce-iptables")
        try:
            self.firewall_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start firewall: {e}")
            return
        self.text.insert("end", f"Started firewall: {' '.join(cmd)}\n")
        self.text.see("end")

    def stop_fw(self):
        if self.firewall_proc and self.firewall_proc.poll() is None:
            self.firewall_proc.terminate()
            try:
                self.firewall_proc.wait(timeout=3)
            except Exception:
                self.firewall_proc.kill()
        self.text.insert("end", "Firewall stopped.\n")
        self.text.see("end")

    def tail_log(self):
        # Periodically read the log file and append to text widget
        try:
            if os.path.exists(self.log_path):
                with open(self.log_path, "r") as f:
                    lines = f.readlines()[-500:]  # last 500 lines
                self.text.delete("1.0", "end")
                self.text.insert("end", "".join(lines))
                self.text.see("end")
        except Exception:
            pass
        self.after(1000, self.tail_log)

if __name__ == "__main__":
    app = FirewallGUI()
    app.mainloop()
