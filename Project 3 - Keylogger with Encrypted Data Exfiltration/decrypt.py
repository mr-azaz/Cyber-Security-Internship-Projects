from cryptography.fernet import Fernet
import os
import sys

# Load the encryption key
KEY_FILE = "encryption_key.key"
if not os.path.exists(KEY_FILE):
    print("[-] Error: encryption_key.key not found.")
    sys.exit(1)

with open(KEY_FILE, "rb") as f:
    key = f.read()
cipher_suite = Fernet(key)

# Decrypt logs
def decrypt_file(filename):
    try:
        with open(filename, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)

        # Save the decrypted log into the shared folder
        shared_dir = "/media/sf_Project_3_-_Keylogger_with_Encrypted_Data_Exfiltration"
        os.makedirs(shared_dir, exist_ok=True)

        output_file = os.path.join(shared_dir, "keystrokes.log.decrypted")
        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        print(f"[+] Logs decrypted to '{output_file}'.")
    except Exception as e:
        print(f"[-] Error decrypting logs: {e}")

if __name__ == "__main__":
    if not os.path.exists("keystrokes.log.enc"):
        print("[-] Error: keystrokes.log.enc not found.")
    else:
        decrypt_file("keystrokes.log.enc")
