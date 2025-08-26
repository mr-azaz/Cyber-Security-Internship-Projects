from flask import Flask, render_template, request, redirect, url_for, send_file, flash
import os
from secure_store import make_encrypted_file, decrypt_file, read_encrypted_file
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('password')
        if not file or not password:
            flash("File and password are required.", "danger")
            return redirect(request.url)
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        enc_path = make_encrypted_file(filepath, password)
        flash(f'File encrypted: {os.path.basename(enc_path)}', "success")
        return redirect(url_for('index'))
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    metadata = None
    decrypted_filename = None
    tamper_warning = None
    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('password')
        if not file or not password:
            flash("File and password are required.", "danger")
            return redirect(request.url)
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        # Read metadata
        try:
            header, ciphertext = read_encrypted_file(filepath)
            metadata = header
        except Exception as e:
            flash("Failed to read metadata: " + str(e), "danger")
            return redirect(request.url)
        # Attempt decryption
        try:
            out_path, ok = decrypt_file(filepath, password, app.config['UPLOAD_FOLDER'])
            decrypted_filename = os.path.basename(out_path)
            if not ok:
                tamper_warning = "WARNING: File hash mismatch! Possible tampering detected."
        except Exception as e:
            flash("Decryption failed: " + str(e), "danger")
            return redirect(request.url)
    return render_template('decrypt.html', metadata=metadata, decrypted_filename=decrypted_filename, tamper_warning=tamper_warning)

@app.route('/tamper-test', methods=['POST'])
def tamper_test():
    file = request.files.get('file')
    password = request.form.get('password')
    if not file or not password:
        flash("File and password are required.", "danger")
        return redirect(url_for('index'))
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Simulate tampering by modifying the last byte
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())
    data[-1] ^= 0x01  # flip last bit
    tampered_path = os.path.join(app.config['UPLOAD_FOLDER'], 'tampered_' + filename)
    with open(tampered_path, 'wb') as f:
        f.write(data)

    # Attempt decryption
    try:
        out_path, ok = decrypt_file(tampered_path, password, app.config['UPLOAD_FOLDER'])
        tamper_warning = None
        if not ok:
            tamper_warning = "WARNING: File hash mismatch! Tampering detected!"
    except Exception as e:
        tamper_warning = str(e)

    metadata = None
    try:
        header, _ = read_encrypted_file(tampered_path)
        metadata = header
    except:
        pass

    return render_template('decrypt.html',
                           metadata=metadata,
                           decrypted_filename=None,
                           tamper_warning=tamper_warning)

@app.route('/download/<filename>')
def download(filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    flash("File not found.", "danger")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
