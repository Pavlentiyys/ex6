"""
Controller — демо-эндпоинты для тестирования уязвимостей (Этап 8).
POST /test/sql-injection, POST /test/xss
"""

import html as html_lib

from flask import Blueprint, jsonify, request

from models.database import get_db
from services.security import sanitize_input

test_bp = Blueprint('test', __name__, url_prefix='/test')


@test_bp.route('/sql-injection', methods=['POST'])
def sql_injection_demo():
    """
    Этап 8: демонстрация защиты от SQL-инъекций.
    Параметризованный запрос делает инъекцию невозможной.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Ожидается JSON'}), 400

    email = data.get('email', '')

    # БЕЗОПАСНО: параметризованный запрос — строка не интерпретируется как SQL
    db = get_db()
    row = db.execute("SELECT email, role FROM users WHERE email = ?", (email,)).fetchone()

    if row:
        return jsonify({'found': True, 'email': row['email'], 'role': row['role']}), 200
    return jsonify({'found': False, 'message': f'Пользователь не найден: {html_lib.escape(email)}'}), 404


@test_bp.route('/xss', methods=['POST'])
def xss_demo():
    """
    Этап 8: демонстрация защиты от XSS.
    Показывает сырой ввод и экранированный результат.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Ожидается JSON'}), 400

    raw = data.get('input', '')
    sanitized = sanitize_input(raw)

    return jsonify({
        'raw': raw,
        'sanitized': sanitized,
        'protected': raw != sanitized,
    }), 200
