#!/usr/bin/env python3
"""
secure_store.py
AES-256-GCM file encryption/decryption with metadata & integrity check
Requires: cryptography
"""

import argparse
import os
import json
import struct
import hashlib
import getpass
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode

VERSION = "1.0"
KDF_ITERS = 200_000

def derive_key(password: bytes, salt: bytes, iterations:int=KDF_ITERS, length: int=32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def make_encrypted_file(in_path: str, password: str, out_path: str = None):
    if out_path is None:
        out_path = in_path + ".enc"
    with open(in_path, "rb") as f:
        plaintext = f.read()
    salt = os.urandom(16)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    header = {
        "version": VERSION,
        "orig_filename": os.path.basename(in_path),
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "plaintext_sha256": sha256_bytes(plaintext),
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_salt_b64": urlsafe_b64encode(salt).decode("ascii"),
        "kdf_iterations": KDF_ITERS,
        "nonce_b64": urlsafe_b64encode(nonce).decode("ascii")
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    header_len = len(header_bytes)
    with open(out_path, "wb") as out:
        out.write(struct.pack(">I", header_len))
        out.write(header_bytes)
        out.write(ciphertext)
    print(f"Encrypted -> {out_path}")
    return out_path

def read_encrypted_file(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    header_len = struct.unpack(">I", raw[:4])[0]
    header_bytes = raw[4:4+header_len]
    header = json.loads(header_bytes.decode("utf-8"))
    ciphertext = raw[4+header_len:]
    return header, ciphertext

def decrypt_file(enc_path: str, password: str, out_dir: str = None):
    header, ciphertext = read_encrypted_file(enc_path)
    salt = urlsafe_b64decode(header["kdf_salt_b64"].encode("ascii"))
    nonce = urlsafe_b64decode(header["nonce_b64"].encode("ascii"))
    iterations = header.get("kdf_iterations", KDF_ITERS)
    key = derive_key(password.encode("utf-8"), salt, iterations)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError("Decryption failed — wrong password or tampering.") from e
    actual_hash = sha256_bytes(plaintext)
    ok = (actual_hash == header.get("plaintext_sha256"))
    orig_name = header.get("orig_filename", "recovered_file")
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, orig_name)
    else:
        out_path = orig_name
    if os.path.exists(out_path):
        base, ext = os.path.splitext(out_path)
        out_path = f"{base}_recovered_{int(datetime.utcnow().timestamp())}{ext}"
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"Decrypted -> {out_path}  (hash match: {ok})")
    return out_path, ok

def info_encrypted_file(enc_path: str, password: str = None):
    header, ciphertext = read_encrypted_file(enc_path)
    print("----- Encrypted file metadata -----")
    for k,v in header.items():
        print(f"{k}: {v}")
    if password:
        try:
            salt = urlsafe_b64decode(header["kdf_salt_b64"].encode("ascii"))
            nonce = urlsafe_b64decode(header["nonce_b64"].encode("ascii"))
            iterations = header.get("kdf_iterations", KDF_ITERS)
            key = derive_key(password.encode("utf-8"), salt, iterations)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            actual_hash = sha256_bytes(plaintext)
            ok = (actual_hash == header.get("plaintext_sha256"))
            print(f"Password verified: YES. Plaintext hash match: {ok}")
        except Exception:
            print("Password verification: FAILED (wrong password or tampered file).")
    else:
        print("Pass a password to attempt verification.")

def main():
    parser = argparse.ArgumentParser(description="Secure AES-256-GCM file storage CLI")
    sub = parser.add_subparsers(dest="cmd")
    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("infile", help="Path to file to encrypt")
    p_enc.add_argument("--out", help="Output path (defaults to infile.enc)")
    p_dec = sub.add_parser("decrypt", help="Decrypt an .enc file")
    p_dec.add_argument("infile", help="Path to .enc file")
    p_dec.add_argument("--out-dir", help="Output directory")
    p_info = sub.add_parser("info", help="Show metadata for .enc file (optionally verify with password)")
    p_info.add_argument("infile", help="Path to .enc file")
    p_info.add_argument("--verify", action="store_true", help="Prompt for password and verify decryption & hash")
    args = parser.parse_args()
    if args.cmd == "encrypt":
        pw = getpass.getpass("Password to protect file: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print("Passwords do not match. Aborting.")
            return
        make_encrypted_file(args.infile, pw, args.out)
    elif args.cmd == "decrypt":
        pw = getpass.getpass("Password to decrypt file: ")
        try:
            decrypt_file(args.infile, pw, args.out_dir)
        except ValueError as e:
            print(str(e))
    elif args.cmd == "info":
        pw = None
        if args.verify:
            pw = getpass.getpass("Password (for verification): ")
        try:
            info_encrypted_file(args.infile, pw)
        except Exception as e:
            print("Error reading file:", e)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
