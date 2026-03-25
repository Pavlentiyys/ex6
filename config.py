import os
import logging
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SECRET_KEY = os.environ.get('SECRET_KEY', 'lab6-secret-key-change-in-production')
DATABASE = os.path.join(BASE_DIR, 'users.db')
DATA_RETENTION_DAYS = 30

# Этап 3: Fernet-ключ для шифрования телефона.
# Для постоянства между запусками задай переменную окружения:
#   export FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
_raw = os.environ.get('FERNET_KEY')
FERNET_KEY = _raw.encode() if _raw else Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

# Этап 6: настройка логирования
logging.basicConfig(
    filename=os.path.join(BASE_DIR, 'access.log'),
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
