#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
import yaml

app = Flask(__name__)

RULES_FILE = "rules.yaml"
LOG_FILE = "firewall.log"

def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r") as f:
            data = yaml.safe_load(f) or {}
            rules = data.get("rules", [])
            default_action = data.get("default_action", "allow")
            return {"default_action": default_action, "rules": rules}
    return {"default_action": "allow", "rules": []}

def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        yaml.safe_dump(rules, f)

@app.route("/")
def index():
    rules = load_rules()
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()[-50:]  # show last 50 lines
    return render_template("index.html", rules=rules, logs=logs)

@app.route("/logs")
def get_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()[-50:]
    return jsonify(logs)

@app.route("/add_rule", methods=["POST"])
def add_rule():
    rules = load_rules()
    new_rule = {
        "action": request.form.get("action"),
        "direction": request.form.get("direction"),
        "protocol": request.form.get("protocol"),
        "src_ip": request.form.get("src_ip"),
        "dst_port": request.form.get("dst_port"),
        "description": request.form.get("description")
    }
    rules["rules"].append(new_rule)
    save_rules(rules)
    return redirect(url_for("index"))

@app.route("/delete_rule/<desc>")
def delete_rule(desc):
    rules = load_rules()
    rules["rules"] = [r for r in rules["rules"] if r.get("description") != desc]
    save_rules(rules)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
