"""
Controller — загрузка и скачивание файлов.
POST /upload, GET /download/<file_id>, GET /files

Этапы: 1 (маршруты), 2+4 (гибридное шифрование), 5 (JWT), 7 (аудит),
        9 (RBAC), 10 (лимит размера, SHA-256, rate limit).
"""

import io
import os
import uuid
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request, send_file

import cloud_config as config
from extensions import limiter
from models.cloud_database import get_db, log_audit
from services.cloud_auth import require_auth
from services.encryption import decrypt_file, encrypt_file, sha256_hash

files_bp = Blueprint('files', __name__)


@files_bp.route('/upload', methods=['POST'])
@limiter.limit("20 per minute")   # Этап 10: rate limiting
@require_auth
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'Файл отсутствует в запросе (поле "file")'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Имя файла пустое'}), 400

    data = file.read()

    # Этап 10: ограничение размера
    if len(data) > config.MAX_FILE_SIZE:
        mb = config.MAX_FILE_SIZE // 1024 // 1024
        log_audit(g.current_user['email'], 'upload_rejected', f'size={len(data)} limit={mb}MB')
        return jsonify({'error': f'Файл превышает лимит {mb} МБ'}), 413

    # Этап 10: SHA-256 для проверки целостности
    file_hash = sha256_hash(data)

    # Этапы 2 + 4: гибридное шифрование (Fernet + RSA)
    encrypted_data, encrypted_key = encrypt_file(data)

    # Сохраняем зашифрованный файл на диск
    file_id = str(uuid.uuid4())
    os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
    encrypted_path = os.path.join(config.UPLOAD_FOLDER, f'{file_id}.enc')
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)

    # Сохраняем метаданные в БД
    db = get_db()
    db.execute(
        """INSERT INTO files
               (id, filename, owner, encrypted_path, encrypted_key, sha256_hash, uploaded_at, size)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            file_id, file.filename, g.current_user['email'],
            encrypted_path, encrypted_key, file_hash,
            datetime.now(timezone.utc).isoformat(), len(data),
        ),
    )
    db.commit()

    # Этап 7: аудит
    log_audit(g.current_user['email'], 'file_upload',
              f'file={file.filename} id={file_id} size={len(data)} sha256={file_hash[:16]}...')

    return jsonify({
        'status': 'uploaded',
        'file_id': file_id,
        'filename': file.filename,
        'sha256': file_hash,
        'size': len(data),
    }), 201


@files_bp.route('/download/<file_id>', methods=['GET'])
@require_auth
def download(file_id: str):
    """Этапы 5 (JWT), 4 (расшифровка), 9 (RBAC), 7 (аудит), 10 (SHA-256)."""
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if row is None:
        log_audit(g.current_user['email'], 'download_not_found', f'id={file_id}')
        return jsonify({'error': 'Файл не найден'}), 404

    # Этап 9: user видит только свои файлы
    if g.current_user['role'] != 'admin' and row['owner'] != g.current_user['email']:
        log_audit(g.current_user['email'], 'download_denied',
                  f'id={file_id} owner={row["owner"]}')
        return jsonify({'error': 'Нет доступа к этому файлу'}), 403

    # Читаем зашифрованный файл с диска
    try:
        with open(row['encrypted_path'], 'rb') as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        return jsonify({'error': 'Файл не найден на диске'}), 404

    # Этап 4: гибридная расшифровка (RSA → Fernet)
    decrypted_data = decrypt_file(encrypted_data, bytes(row['encrypted_key']))

    # Этап 10: проверка целостности
    if sha256_hash(decrypted_data) != row['sha256_hash']:
        log_audit(g.current_user['email'], 'integrity_check_failed', f'id={file_id}')
        return jsonify({'error': 'Нарушена целостность файла'}), 500

    log_audit(g.current_user['email'], 'file_download',
              f'file={row["filename"]} id={file_id}')

    return send_file(
        io.BytesIO(decrypted_data),
        download_name=row['filename'],
        as_attachment=True,
    )


@files_bp.route('/files', methods=['GET'])
@require_auth
def list_files():
    """Этап 9: user видит свои файлы, admin — все."""
    db = get_db()
    if g.current_user['role'] == 'admin':
        rows = db.execute(
            "SELECT id, filename, owner, sha256_hash, uploaded_at, size FROM files ORDER BY uploaded_at DESC"
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT id, filename, owner, sha256_hash, uploaded_at, size
               FROM files WHERE owner = ? ORDER BY uploaded_at DESC""",
            (g.current_user['email'],),
        ).fetchall()

    log_audit(g.current_user['email'], 'list_files', f'count={len(rows)}')
    return jsonify({'files': [dict(r) for r in rows]}), 200
