# 🔐 Secure File Storage System with AES

A **Flask-based web application** for securely encrypting, decrypting, and verifying files using **AES-256 encryption**.
It includes a modern **Bootstrap-powered GUI** with metadata display, tamper detection, and easy file downloads.

---

## 🚀 Features

* 🔒 **AES-256 Encryption** – Secure file storage using strong cryptography.
* 🔑 **Password-based protection** – Files are encrypted and decrypted using user-supplied passwords.
* 🖥️ **Flask Web GUI** – Stylish, responsive web interface with Bootstrap 5.
* 📄 **Metadata display** – Shows filename, timestamp, and file hash after decryption.
* ⚠️ **Tamper Detection** – Detects if a file has been modified after encryption.
* ⬇️ **Download Support** – Easily download decrypted files from the GUI.

---

## 📂 Project Structure

```
Project-5-Secure-File-Storage/
│── app.py              # Flask web application
│── secure_store.py     # AES encryption & decryption logic
│── templates/          # HTML templates (Bootstrap styled)
│   │── index.html
│   │── encrypt.html
│   │── decrypt.html
│── uploads/            # Stores uploaded and processed files
│── README.md           # Project documentation
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/mr-azaz/Cyber-Security-Internship-Projects/Project 5 Secure File Storage System with AES.git
cd Project 5 Secure File Storage System with AES
```

### 2️⃣ Create a Virtual Environment

```bash
python3 -m venv project5_venv
source project5_venv/bin/activate   # Linux/Mac
project5_venv\Scripts\activate      # Windows
```

### 3️⃣ Install Dependencies

```bash
pip install flask cryptography
```

### 4️⃣ Run the Application

```bash
export FLASK_APP=app.py
export FLASK_ENV=development
flask run
```

Go to 👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

---

## 🛠️ Usage

1. **Encrypt a File**

   * Navigate to the **Encrypt** page.
   * Upload a file and enter a password.
   * Download the encrypted `.enc` file.

2. **Decrypt a File**

   * Go to the **Decrypt** page.
   * Upload the encrypted file and enter the password.
   * View metadata (filename, timestamp, hash).
   * If tampered, a **red warning alert** is shown.
   * If valid, you can **download the decrypted file**.

---

## 🎨 User Interface

* ✅ Clean & modern design with **Bootstrap 5**
* ✅ File actions grouped in **cards** for clarity
* ✅ **Icons** (Bootstrap Icons) for Encrypt, Decrypt, Warning, and Download
* ✅ **Alerts** for success, error, and tampering detection

---

## 📌 Example Screens

* **Homepage** – Choose to Encrypt or Decrypt
* **Encrypt Form** – Upload file + enter password
* **Decrypt Form** – Upload encrypted file + enter password + tamper detection + download

---

## 🔮 Future Improvements

* 📦 Add file compression before encryption
* 🗄️ Store metadata in a lightweight database
* 🔑 Enable password reset & key management
* ☁️ Add cloud storage integration (AWS S3, Google Drive)

---


