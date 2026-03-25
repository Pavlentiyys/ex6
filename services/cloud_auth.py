"""
Service — JWT-аутентификация и декораторы доступа для облачного хранилища (Этап 5).
"""

from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request

import cloud_config as config
from models.cloud_database import log_audit


def generate_token(email: str, role: str) -> str:
    payload = {
        'email': email,
        'role': role,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=1),
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm='HS256')


def _decode(token: str) -> dict:
    return jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'])


def _extract_token() -> str:
    return request.headers.get('Authorization', '').replace('Bearer ', '').strip()


def require_auth(f):
    """Этап 5: проверяет JWT-токен."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if not token:
            log_audit('unknown', 'token_missing', f'endpoint={request.path}')
            return jsonify({'error': 'Требуется авторизация'}), 401
        try:
            g.current_user = _decode(token)
        except jwt.ExpiredSignatureError:
            log_audit('unknown', 'token_expired', f'endpoint={request.path}')
            return jsonify({'error': 'Токен истёк'}), 401
        except jwt.InvalidTokenError:
            log_audit('unknown', 'token_invalid', f'endpoint={request.path}')
            return jsonify({'error': 'Невалидный токен'}), 401
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Этап 9: требует роль admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({'error': 'Требуется авторизация'}), 401
        try:
            payload = _decode(token)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Токен истёк'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Невалидный токен'}), 401
        if payload.get('role') != 'admin':
            log_audit(payload.get('email', ''), 'admin_access_denied', f'endpoint={request.path}')
            return jsonify({'error': 'Требуются права администратора'}), 403
        g.current_user = payload
        return f(*args, **kwargs)
    return decorated
