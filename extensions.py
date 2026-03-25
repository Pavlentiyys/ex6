from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Создаём без привязки к app — инициализируется через limiter.init_app(app) в server.py.
# Это стандартный Flask-паттерн, исключающий циклические импорты.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://"
)
