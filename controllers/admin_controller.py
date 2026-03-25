"""
Controller — административные маршруты.
GET /admin/users, POST /admin/promote, GET /admin/logs
Доступны только пользователям с ролью admin (Этап 5).
"""

from flask import Blueprint, g, jsonify, request

from models.database import get_db, log_access
from services.auth import check_role
from services.security import sanitize_input

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/users', methods=['GET'])
@check_role('admin')
def list_users():
    """
    Этапы 5, 6. Бонус 2 (автоочистка запускается before_request).
    Список всех пользователей без чувствительных полей.
    """
    db = get_db()
    rows = db.execute(
        "SELECT id, email, role, created_at, last_login FROM users ORDER BY created_at DESC"
    ).fetchall()

    log_access(g.current_user['email'], 'admin_list_users')
    return jsonify({'users': [dict(r) for r in rows], 'count': len(rows)}), 200


@admin_bp.route('/promote', methods=['POST'])
@check_role('admin')
def promote():
    """
    Этапы 5, 6.
    Повышает роль указанного пользователя до admin.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Ожидается JSON'}), 400

    target_email = sanitize_input(data.get('email', ''))
    if not target_email:
        return jsonify({'error': 'Обязательное поле: email'}), 400

    db = get_db()
    result = db.execute("UPDATE users SET role = 'admin' WHERE email = ?", (target_email,))
    db.commit()

    if result.rowcount == 0:
        return jsonify({'error': 'Пользователь не найден'}), 404

    log_access(g.current_user['email'], f'admin_promote:{target_email}')
    return jsonify({'status': 'promoted', 'email': target_email, 'new_role': 'admin'}), 200


@admin_bp.route('/logs', methods=['GET'])
@check_role('admin')
def view_logs():
    """
    Этапы 5, 6.
    Последние 100 записей из лога доступа к персональным данным.
    """
    db = get_db()
    rows = db.execute(
        "SELECT * FROM access_log ORDER BY timestamp DESC LIMIT 100"
    ).fetchall()

    log_access(g.current_user['email'], 'admin_view_logs')
    return jsonify({'logs': [dict(r) for r in rows]}), 200
