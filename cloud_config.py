import os
from pathlib import Path

BASE_DIR = Path(__file__).parent        # ex6/

SECRET_KEY = os.environ.get('CLOUD_SECRET_KEY', 'cloud-secret-key-lab7')
DATABASE = str(BASE_DIR / 'cloud.db')
UPLOAD_FOLDER = str(BASE_DIR / 'cloud_storage')
KEYS_DIR = str(BASE_DIR / 'keys')
KEY_FILE = str(BASE_DIR / 'keys' / 'key.key')        # Этап 3: симметричный ключ
PRIVATE_KEY_FILE = str(BASE_DIR / 'keys' / 'private.pem')  # Этап 4: RSA
PUBLIC_KEY_FILE = str(BASE_DIR / 'keys' / 'public.pem')
AUDIT_LOG = str(BASE_DIR / 'cloud_audit.log')

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB — Этап 10
FILE_RETENTION_HOURS = 24          # Этап 10: автоудаление
