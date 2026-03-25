"""
Практическая работа №6 — Защита персональных данных в сети Интернет.

Точка входа. Фабрика приложения Flask.
Регистрирует blueprints, расширения, хуки жизненного цикла.
"""

import os
from flask import Flask

import config
from extensions import limiter
from models.database import close_db, init_db, maybe_purge
from controllers.auth_controller import auth_bp
from controllers.admin_controller import admin_bp
from controllers.test_controller import test_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['DATABASE'] = config.DATABASE

    # Расширения
    limiter.init_app(app)

    # Хуки жизненного цикла
    app.teardown_appcontext(close_db)
    app.before_request(maybe_purge)

    # Blueprints (View-слой)
    app.register_blueprint(auth_bp)   # /register, /login, /profile
    app.register_blueprint(admin_bp)  # /admin/users, /admin/promote, /admin/logs
    app.register_blueprint(test_bp)   # /test/sql-injection, /test/xss

    return app


if __name__ == '__main__':
    app = create_app()
    init_db()

    cert_path = os.path.join(os.path.dirname(__file__), 'cert.pem')
    key_path = os.path.join(os.path.dirname(__file__), 'key.pem')

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print("ОШИБКА: cert.pem и key.pem не найдены!")
        print("Сгенерируй: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'")
        exit(1)

    print("=" * 60)
    print("Практическая работа №6 — Защита персональных данных")
    print("=" * 60)
    print(f"Адрес:       https://localhost:5001")
    print(f"База данных: {config.DATABASE}")
    print(f"Лог:         access.log")
    print(f"Fernet-ключ: {'из ENV' if os.environ.get('FERNET_KEY') else 'временный (новый при каждом запуске)'}")
    print("=" * 60)

    # Этап 4: HTTPS с self-signed сертификатом
    app.run(host='0.0.0.0', port=5001, debug=False, ssl_context=(cert_path, key_path))
