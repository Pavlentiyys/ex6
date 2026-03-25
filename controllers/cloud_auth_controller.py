import sqlite3

import bcrypt
from flask import Blueprint, jsonify, request

from models.cloud_database import get_db, log_audit
from services.cloud_auth import generate_token

cloud_auth_bp = Blueprint('cloud_auth', __name__)


@cloud_auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Ожидается JSON'}), 400

    email = data.get('email', '').strip()
    password = data.get('password', '')
    if not email or not password:
        return jsonify({'error': 'Обязательные поля: email, password'}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    db = get_db()
    try:
        db.execute(
            "INSERT INTO cloud_users (email, password_hash, role) VALUES (?, ?, 'user')",
            (email, pw_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email уже зарегистрирован'}), 409

    log_audit(email, 'register')
    return jsonify({'status': 'registered'}), 201


@cloud_auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Ожидается JSON'}), 400

    email = data.get('email', '').strip()
    password = data.get('password', '')

    db = get_db()
    row = db.execute("SELECT * FROM cloud_users WHERE email = ?", (email,)).fetchone()

    if row is None or not bcrypt.checkpw(password.encode(), bytes(row['password_hash'])):
        log_audit(email, 'login_failed')
        return jsonify({'error': 'Неверные учётные данные'}), 401

    token = generate_token(email, row['role'])
    log_audit(email, 'login_success')
    return jsonify({'token': token, 'role': row['role']}), 200
