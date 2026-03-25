from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request

import config
from models.database import log_access


def generate_token(email: str, role: str) -> str:
    payload = {
        'email': email,
        'role': role,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=1),
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm='HS256')


def decode_token(token: str) -> dict:
    return jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'])


def _extract_token() -> str:
    return request.headers.get('Authorization', '').replace('Bearer ', '').strip()


def require_auth(f):
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
