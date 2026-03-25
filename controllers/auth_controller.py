"""
Controller — маршруты аутентификации.
POST /register, POST /login, GET /profile
"""

import re
import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

from extensions import limiter
from models.database import get_db, log_access
from services.auth import generate_token, require_auth
from services.security import (
    decrypt_phone,
    encrypt_phone,
    hash_iin,
    hash_password,
    sanitize_input,
    verify_password,
)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Этапы 1, 2, 3, 7.
    Принимает email, password, iin (обязательно) и phone (опционально).
    ИИН хешируется, пароль — bcrypt, телефон — Fernet.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Ожидается JSON'}), 400

    email = data.get('email', '')
    password = data.get('password', '')
    iin = data.get('iin', '')
    phone = data.get('phone', '')

    if not all([email, password, iin]):
        return jsonify({'error': 'Обязательные поля: email, password, iin'}), 400

    # Этап 7: санитизация от XSS
    email = sanitize_input(email)
    iin = sanitize_input(iin)
    if phone:
        phone = sanitize_input(phone)

    if not re.fullmatch(r'\d{12}', iin):
        return jsonify({'error': 'ИИН должен содержать ровно 12 цифр'}), 400

    iin_hash = hash_iin(iin)                          # Этап 1
    password_hash = hash_password(password)           # Этап 2
    phone_encrypted = encrypt_phone(phone) if phone else None  # Этап 3

    db = get_db()
    try:
        db.execute(
            """INSERT INTO users (email, password_hash, iin_hash, phone_encrypted, role, created_at)
               VALUES (?, ?, ?, ?, 'user', ?)""",
            (email, password_hash, iin_hash, phone_encrypted, datetime.now(timezone.utc).isoformat()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email уже зарегистрирован'}), 409

    log_access(email, 'register')  # Этап 6
    return jsonify({'status': 'registered', 'message': f'Пользователь {email} успешно зарегистрирован'}), 201


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Бонус 3: rate limiting
def login():
    """
    Этапы 2, 6. Бонус 1 (JWT), Бонус 3 (rate limit).
    Проверяет пароль через bcrypt, возвращает JWT-токен.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Ожидается JSON'}), 400

    email = sanitize_input(data.get('email', ''))  # Этап 7
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Обязательные поля: email, password'}), 400

    db = get_db()
    row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    # Одно сообщение для неверного email и пароля — защита от перебора
    if row is None or not verify_password(password, bytes(row['password_hash'])):
        log_access(email, 'login_failed')
        return jsonify({'error': 'Неверные учётные данные'}), 401

    db.execute(
        "UPDATE users SET last_login = ? WHERE email = ?",
        (datetime.now(timezone.utc).isoformat(), email),
    )
    db.commit()

    token = generate_token(email, row['role'])  # Бонус 1
    log_access(email, 'login_success')           # Этап 6
    return jsonify({'token': token, 'role': row['role']}), 200


@auth_bp.route('/profile', methods=['GET'])
@require_auth
def profile():
    """
    Этапы 3, 5, 6.
    Возвращает профиль текущего пользователя с расшифрованным телефоном.
    """
    email = g.current_user['email']
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if row is None:
        return jsonify({'error': 'Пользователь не найден'}), 404

    phone = None
    if row['phone_encrypted']:
        try:
            phone = decrypt_phone(bytes(row['phone_encrypted']))  # Этап 3
        except Exception:
            phone = '<не удалось расшифровать>'

    log_access(email, 'view_profile')  # Этап 6
    return jsonify({
        'email': row['email'],
        'role': row['role'],
        'phone': phone,
        'created_at': row['created_at'],
        'last_login': row['last_login'],
        # password_hash и iin_hash — никогда не возвращаем
    }), 200
