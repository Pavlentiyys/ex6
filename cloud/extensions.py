from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Создаётся без app — инициализируется через limiter.init_app(app) в server.py
limiter = Limiter(key_func=get_remote_address, storage_uri='memory://')
