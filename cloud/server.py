"""
Практическая работа №7-8 — Облачное хранилище с шифрованием.
Точка входа. Порт 5002.
"""

import os
import sys

# Добавляем cloud/ в sys.path чтобы import config / from models... работал корректно
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask

import config
from extensions import limiter
from models.database import close_db, init_db, maybe_purge
from services.encryption import setup_keys
from controllers.auth_controller import auth_bp
from controllers.files_controller import files_bp
from controllers.admin_controller import admin_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_FILE_SIZE  # Этап 10

    limiter.init_app(app)

    app.teardown_appcontext(close_db)
    app.before_request(maybe_purge)

    app.register_blueprint(auth_bp)    # /register, /login
    app.register_blueprint(files_bp)   # /upload, /download, /files
    app.register_blueprint(admin_bp)   # /admin/*

    return app


if __name__ == '__main__':
    os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)

    print("=" * 60)
    print("Практическая работа №7-8 — Облачное хранилище")
    print("=" * 60)

    # Этап 3: создаём key.key и Этап 4: RSA-ключи (если не существуют)
    setup_keys()

    # Создаём таблицы и тестовых пользователей
    init_db()

    # Этап 6: SSL-сертификат (reuse из lab 6)
    root = os.path.dirname(os.path.dirname(__file__))
    cert_path = os.path.join(root, 'cert.pem')
    key_path = os.path.join(root, 'key.pem')

    if not os.path.exists(cert_path):
        print("ОШИБКА: cert.pem не найден в корне проекта (ex6/)")
        sys.exit(1)

    print(f"  Адрес:      https://localhost:5002")
    print(f"  База:       {config.DATABASE}")
    print(f"  Хранилище:  {config.UPLOAD_FOLDER}")
    print(f"  Аудит-лог:  {config.AUDIT_LOG}")
    print(f"  RSA ключи:  {config.KEYS_DIR}")
    print()
    print("  Тестовые пользователи:")
    print("    admin@cloud.local / admin123  (роль: admin)")
    print("    user@cloud.local  / user123   (роль: user)")
    print("=" * 60)

    app = create_app()
    # Этап 6: HTTPS
    app.run(host='0.0.0.0', port=5002, debug=False, ssl_context=(cert_path, key_path))
