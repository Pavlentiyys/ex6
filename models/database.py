"""
Model — работа с базой данных.
Содержит: подключение, инициализацию схемы, логирование доступа, автоочистку.
"""

import sqlite3
import logging
from datetime import datetime, timedelta, timezone

from flask import g, request

import config


def get_db() -> sqlite3.Connection:
    """Возвращает соединение с БД для текущего контекста запроса."""
    if 'db' not in g:
        g.db = sqlite3.connect(config.DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(error=None):
    """Закрывает соединение с БД по завершении запроса."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Создаёт таблицы при первом запуске."""
    db = sqlite3.connect(config.DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT    NOT NULL UNIQUE,
            password_hash   BLOB    NOT NULL,
            iin_hash        TEXT    NOT NULL,
            phone_encrypted BLOB,
            role            TEXT    NOT NULL DEFAULT 'user',
            created_at      TEXT    NOT NULL,
            last_login      TEXT
        );
        CREATE TABLE IF NOT EXISTS access_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email  TEXT,
            action      TEXT,
            timestamp   TEXT,
            ip_address  TEXT
        );
    """)
    db.commit()
    db.close()


def log_access(user_email: str, action: str) -> None:
    """Этап 6: логирует каждое обращение к персональным данным."""
    ip = request.remote_addr if request else 'unknown'
    logging.info(f"ACCESS | user={user_email} | action={action} | ip={ip}")
    try:
        db = get_db()
        db.execute(
            "INSERT INTO access_log (user_email, action, timestamp, ip_address) VALUES (?, ?, ?, ?)",
            (user_email, action, datetime.now(timezone.utc).isoformat(), ip)
        )
        db.commit()
    except Exception:
        pass  # логирование не должно прерывать основной поток


# --- Бонус 2: автоудаление устаревших данных ---

_last_purge = datetime.min.replace(tzinfo=timezone.utc)


def purge_old_accounts():
    """Удаляет аккаунты старше DATA_RETENTION_DAYS дней."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=config.DATA_RETENTION_DAYS)).isoformat()
    db = get_db()
    result = db.execute("DELETE FROM users WHERE created_at < ?", (cutoff,))
    db.commit()
    if result.rowcount > 0:
        logging.info(f"PURGE | Удалено {result.rowcount} устаревших аккаунтов")


def maybe_purge():
    """before_request-хук: запускает очистку не чаще раза в час."""
    global _last_purge
    now = datetime.now(timezone.utc)
    if now - _last_purge > timedelta(hours=1):
        _last_purge = now
        try:
            purge_old_accounts()
        except Exception:
            pass
