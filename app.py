import os
from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timedelta
import sqlite3
import re
from html import escape
from dotenv import load_dotenv
from captcha.image import ImageCaptcha
import random
import string
import io

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret')

# CORS configuration
CORS(app,
     supports_credentials=True,
     resources={r"/*": {"origins": "*"}},
     allow_headers=["Authorization", "Content-Type"],
     expose_headers=["Authorization"])

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

jwt = JWTManager(app)

ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=4)
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'secure_login.db')


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT CHECK (role IN ('Admin', 'User')) DEFAULT 'User',
            is_locked INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            last_login TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    cur.execute("SELECT id FROM users WHERE email = ?", ('admin@example.com',))
    if not cur.fetchone():
        hashed_pw = ph.hash('Admin@1234')
        cur.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                    ('admin', 'admin@example.com', hashed_pw, 'Admin'))
        conn.commit()
        print("✅ Default admin created: admin@example.com / Admin@1234")

    conn.close()
    print("✅ Database initialized successfully!")


def validate_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)


def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, ""


# --- Added simple CAPTCHA route ---
@app.route('/captcha')
def generate_captcha():
    token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    session['captcha_token'] = token
    image = ImageCaptcha(width=220, height=80)
    data = image.generate(token)
    return send_file(data, mimetype='image/png')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/register')
def register_page():
    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/admin')
def admin_page():
    return render_template('admin.html')


@app.route('/api/register', methods=['POST'])
def register_user():
    try:
        data = request.get_json()
        username = escape(data.get('username', '').strip())
        email = escape(data.get('email', '').strip())
        password = data.get('password', '')
        role = data.get('role', 'User')

        if not username or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400
        if not validate_email(email):
            return jsonify({'error': 'Invalid email'}), 400

        valid, msg = validate_password_strength(password)
        if not valid:
            return jsonify({'error': msg}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = ? OR username = ?", (email, username))
        if cur.fetchone():
            return jsonify({'error': 'Username or email already exists'}), 400

        hashed = ph.hash(password)
        cur.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                    (username, email, hashed, role))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = escape(data.get('email', '').strip())
    password = data.get('password', '')
    captcha_input = data.get('captcha', '').upper()

    # --- CAPTCHA validation check ---
    if 'captcha_token' not in session or captcha_input != session['captcha_token']:
        return jsonify({'error': 'Invalid CAPTCHA. Please try again.'}), 400

    session.pop('captcha_token', None)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    if user['is_locked']:
        if user['locked_until']:
            if datetime.fromisoformat(user['locked_until']) > datetime.utcnow():
                return jsonify({'error': 'Account locked. Try later.'}), 403
            else:
                cur.execute("UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?", (user['id'],))
                conn.commit()

    try:
        ph.verify(user['password'], password)
    except VerifyMismatchError:
        fails = user['failed_attempts'] + 1
        if fails >= 5:
            lock_time = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
            cur.execute("UPDATE users SET is_locked = 1, locked_until = ?, failed_attempts = ? WHERE id = ?",
                        (lock_time, fails, user['id']))
            conn.commit()
            return jsonify({'error': 'Account locked for 15 minutes'}), 403
        else:
            cur.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (fails, user['id']))
            conn.commit()
            return jsonify({'error': f'Invalid password. {5 - fails} attempts left'}), 401

    cur.execute("UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), user['id']))
    conn.commit()
    cur.close()
    conn.close()

    token = create_access_token(identity=str(user['id']), additional_claims={'role': user['role'], 'username': user['username']})
    return jsonify({'message': 'Login successful', 'access_token': token, 'role': user['role'], 'username': user['username']}), 200


@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, role, last_login, created_at FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(dict(user)), 200


@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def list_users():
    claims = get_jwt()
    if claims.get('role') != 'Admin':
        return jsonify({'error': 'Admin access required'}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, role, is_locked, failed_attempts, last_login, created_at FROM users")
    rows = cur.fetchall()
    users = [dict(row) for row in rows]
    conn.close()
    return jsonify(users), 200


@app.route('/api/admin/users/<int:user_id>/unlock', methods=['POST'])
@jwt_required()
def unlock_user(user_id):
    claims = get_jwt()
    if claims.get('role') != 'Admin':
        return jsonify({'error': 'Admin access required'}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User unlocked successfully'}), 200


@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@jwt_required()
def change_role(user_id):
    claims = get_jwt()
    if claims.get('role') != 'Admin':
        return jsonify({'error': 'Admin access required'}), 403

    new_role = request.get_json().get('role')
    if new_role not in ['Admin', 'User']:
        return jsonify({'error': 'Invalid role'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': f'Role updated to {new_role}'}), 200


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    claims = get_jwt()
    if claims.get('role') != 'Admin':
        return jsonify({'error': 'Admin access required'}), 403

    current_id = get_jwt_identity()
    if current_id == user_id:
        return jsonify({'error': 'Cannot delete yourself'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User deleted successfully'}), 200


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Try later'}), 429


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Server error'}), 500


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
