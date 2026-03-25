import os
import logging
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SECRET_KEY = os.environ.get('SECRET_KEY', 'lab6-secret-key-change-in-production')
DATABASE = os.path.join(BASE_DIR, 'users.db')
DATA_RETENTION_DAYS = 30

_raw = os.environ.get('FERNET_KEY')
FERNET_KEY = _raw.encode() if _raw else Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

logging.basicConfig(
    filename=os.path.join(BASE_DIR, 'access.log'),
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
