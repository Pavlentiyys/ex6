from flask import Blueprint, g, jsonify

import cloud_config as config
from models.cloud_database import get_db, log_audit
from services.cloud_auth import require_admin

cloud_admin_bp = Blueprint('cloud_admin', __name__, url_prefix='/admin')


@cloud_admin_bp.route('/files', methods=['GET'])
@require_admin
def all_files():
    db = get_db()
    rows = db.execute(
        "SELECT id, filename, owner, sha256_hash, uploaded_at, size FROM files ORDER BY uploaded_at DESC"
    ).fetchall()
    log_audit(g.current_user['email'], 'admin_list_all_files', f'count={len(rows)}')
    return jsonify({'files': [dict(r) for r in rows], 'count': len(rows)}), 200


@cloud_admin_bp.route('/users', methods=['GET'])
@require_admin
def all_users():
    db = get_db()
    rows = db.execute("SELECT id, email, role FROM cloud_users ORDER BY id").fetchall()
    log_audit(g.current_user['email'], 'admin_list_users')
    return jsonify({'users': [dict(r) for r in rows]}), 200


@cloud_admin_bp.route('/logs', methods=['GET'])
@require_admin
def view_logs():
    try:
        with open(config.AUDIT_LOG, 'r') as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        log_audit(g.current_user['email'], 'admin_view_logs')
        return jsonify({'logs': lines[-100:]}), 200
    except FileNotFoundError:
        return jsonify({'logs': []}), 200
