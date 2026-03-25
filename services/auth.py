"""
Service — аутентификация и авторизация.
Бонус 1: JWT-токены.
Этап 5: RBAC-декораторы (require_auth, check_role).
"""

from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request

import config
from models.database import log_access


# --- Бонус 1: JWT ---

def generate_token(email: str, role: str) -> str:
    """Генерирует JWT-токен с email, ролью и сроком жизни 1 час."""
    payload = {
        'email': email,
        'role': role,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=1),
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm='HS256')


def decode_token(token: str) -> dict:
    """Декодирует JWT-токен. Выбрасывает исключение при невалидном токене."""
    return jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'])


def _extract_token() -> str:
    return request.headers.get('Authorization', '').replace('Bearer ', '').strip()


# --- Этап 5: Контроль доступа (RBAC) ---

def require_auth(f):
    """Декоратор: проверяет JWT-токен, устанавливает g.current_user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({'error': 'Отсутствует токен авторизации'}), 401
        try:
            g.current_user = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Токен истёк'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Невалидный токен'}), 401
        return f(*args, **kwargs)
    return decorated


def check_role(required_role: str):
    """Декоратор-фабрика: проверяет JWT и роль. Возвращает 403, если роль не совпадает."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = _extract_token()
            if not token:
                return jsonify({'error': 'Отсутствует токен авторизации'}), 401
            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Токен истёк'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Невалидный токен'}), 401

            if payload.get('role') != required_role:
                log_access(payload.get('email', 'unknown'), f'DENIED:{f.__name__}')
                return jsonify({'error': 'Доступ запрещён'}), 403

            g.current_user = payload
            return f(*args, **kwargs)
        return decorated
    return decorator
