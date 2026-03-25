"""
Model — SQLite для облачного хранилища.
Таблицы: cloud_users, files.
Аудит-лог (Этап 7), автоудаление файлов (Этап 10).
"""

import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import g

import cloud_config as config

# Этап 7: аудит-лог
logging.basicConfig(
    filename=config.AUDIT_LOG,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)


def get_db() -> sqlite3.Connection:
    if 'cloud_db' not in g:
        g.cloud_db = sqlite3.connect(config.DATABASE)
        g.cloud_db.row_factory = sqlite3.Row
    return g.cloud_db


def close_db(error=None):
    db = g.pop('cloud_db', None)
    if db is not None:
        db.close()


def init_db():
    """Создаёт таблицы и добавляет тестовых пользователей."""
    import bcrypt
    db = sqlite3.connect(config.DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS cloud_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS files (
            id             TEXT PRIMARY KEY,
            filename       TEXT NOT NULL,
            owner          TEXT NOT NULL,
            encrypted_path TEXT NOT NULL,
            encrypted_key  BLOB NOT NULL,
            sha256_hash    TEXT NOT NULL,
            uploaded_at    TEXT NOT NULL,
            size           INTEGER NOT NULL
        );
    """)
    # Тестовые пользователи (создаются один раз)
    count = db.execute("SELECT COUNT(*) FROM cloud_users").fetchone()[0]
    if count == 0:
        admin_hash = bcrypt.hashpw(b'admin123', bcrypt.gensalt())
        user_hash = bcrypt.hashpw(b'user123', bcrypt.gensalt())
        db.execute(
            "INSERT INTO cloud_users (email, password_hash, role) VALUES (?, ?, 'admin')",
            ('admin@cloud.local', admin_hash)
        )
        db.execute(
            "INSERT INTO cloud_users (email, password_hash, role) VALUES (?, ?, 'user')",
            ('user@cloud.local', user_hash)
        )
    db.commit()
    db.close()


def log_audit(user: str, action: str, detail: str = '') -> None:
    """Этап 7: логирует все события безопасности в cloud_audit.log."""
    from flask import request as req
    try:
        ip = req.remote_addr or 'unknown'
    except RuntimeError:
        ip = 'unknown'
    msg = f"user={user} | action={action}"
    if detail:
        msg += f" | {detail}"
    msg += f" | ip={ip}"
    logging.info(msg)


# --- Этап 10: автоудаление файлов через 24 часа ---

_last_purge = datetime.min.replace(tzinfo=timezone.utc)


def purge_old_files() -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=config.FILE_RETENTION_HOURS)).isoformat()
    db = get_db()
    rows = db.execute(
        "SELECT id, encrypted_path FROM files WHERE uploaded_at < ?", (cutoff,)
    ).fetchall()
    for row in rows:
        try:
            os.remove(row['encrypted_path'])
        except FileNotFoundError:
            pass
    if rows:
        db.execute("DELETE FROM files WHERE uploaded_at < ?", (cutoff,))
        db.commit()
        logging.info(f"AUTO_PURGE | Удалено {len(rows)} файлов старше {config.FILE_RETENTION_HOURS}ч")


def maybe_purge() -> None:
    global _last_purge
    now = datetime.now(timezone.utc)
    if now - _last_purge > timedelta(hours=1):
        _last_purge = now
        try:
            purge_old_files()
        except Exception:
            pass
