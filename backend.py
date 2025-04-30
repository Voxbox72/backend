import os
from flask import Flask, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')
CORS(app, supports_credentials=True)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            is_active BOOLEAN,
            start_date TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        conn.commit()

class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id, email FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        if user:
            return User(user[0], user[1])
        return None

if not os.path.exists(DB_PATH):
    init_db()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            password_hash = generate_password_hash(password)
            c.execute('INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)',
                      (email, password_hash, datetime.utcnow()))
            user_id = c.lastrowid
            c.execute('INSERT INTO subscriptions (user_id, is_active, start_date) VALUES (?, ?, ?)',
                      (user_id, False, datetime.utcnow()))
            conn.commit()
            user = User(user_id, email)
            login_user(user)
            return jsonify({'message': 'Registered successfully', 'user': {'email': email}}), 201
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Email already exists'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id, email, password_hash FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        if user and check_password_hash(user[2], password):
            user_obj = User(user[0], user[1])
            login_user(user_obj)
            return jsonify({'message': 'Logged in successfully', 'user': {'email': user[1]}}), 200
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/check_access', methods=['GET'])
def check_access():
    if not current_user.is_authenticated:
        return jsonify({'authenticated': False, 'subscribed': False}), 401
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT is_active FROM subscriptions WHERE user_id = ?', (current_user.id,))
        sub = c.fetchone()
        subscribed = sub and sub[0]
        return jsonify({'authenticated': True, 'subscribed': subscribed}), 200

@app.route('/api/subscription/activate', methods=['POST'])
@login_required
def activate_subscription():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('UPDATE subscriptions SET is_active = ?, start_date = ? WHERE user_id = ?',
                  (True, datetime.utcnow(), current_user.id))
        conn.commit()
        return jsonify({'message': 'Subscription activated'}), 200

if __name__ == '__main__':
    app.run(debug=True)