from flask import Flask, request, session, redirect, jsonify
import hashlib
import time
import json
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Change this!

DATA_FILE = 'data/packages.json'
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w') as f:
        json.dump({}, f)

BOT_TOKEN = '7812958174:AAHYNIsCspdrWmOGSqTyV9W3TzUDB42a_9c'

def verify_telegram_auth(data):
    check_hash = data.pop('hash')
    sorted_data = sorted([f"{k}={v}" for k, v in data.items()])
    data_string = "\n".join(sorted_data)

    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    calculated_hash = hashlib.sha256(data_string.encode()).hexdigest()

    return check_hash == calculated_hash

@app.route('/auth')
def auth():
    data = request.args.to_dict()
    if not verify_telegram_auth(data):
        return "Invalid Telegram login.", 403

    session['user'] = {
        'id': data['id'],
        'username': data.get('username', ''),
        'first_name': data.get('first_name', ''),
        'photo_url': data.get('photo_url', '')
    }

    return redirect('/dashboard.html')

@app.route('/get_user_data')
def get_user_data():
    if 'user' in session:
        return jsonify(session['user'])
    return jsonify({'error': 'Not logged in'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/add_package', methods=['POST'])
def add_package():
    content = request.json
    username = content.get("username")  # e.g., @user1
    package = content.get("package")    # e.g., funny v500

    if not username or not package:
        return jsonify({'error': 'Invalid data'}), 400

    username = username.lstrip('@')

    with open(DATA_FILE, 'r') as f:
        data = json.load(f)

    if username not in data:
        data[username] = []

    data[username].append(package)

    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

    return jsonify({'status': 'success'})

@app.route('/get_packages')
def get_packages():
    if 'user' not in session:
        return jsonify([])

    username = session['user'].get('username', '')
    if not username:
        return jsonify([])

    with open(DATA_FILE, 'r') as f:
        data = json.load(f)

    return jsonify(data.get(username, []))

if __name__ == '__main__':
    app.run(debug=True)
