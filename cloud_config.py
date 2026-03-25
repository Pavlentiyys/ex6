import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

SECRET_KEY = os.environ.get('CLOUD_SECRET_KEY', 'cloud-secret-key-lab7')
DATABASE = str(BASE_DIR / 'cloud.db')
UPLOAD_FOLDER = str(BASE_DIR / 'cloud_storage')
KEYS_DIR = str(BASE_DIR / 'keys')
KEY_FILE = str(BASE_DIR / 'keys' / 'key.key')
PRIVATE_KEY_FILE = str(BASE_DIR / 'keys' / 'private.pem')
PUBLIC_KEY_FILE = str(BASE_DIR / 'keys' / 'public.pem')
AUDIT_LOG = str(BASE_DIR / 'cloud_audit.log')

MAX_FILE_SIZE = 10 * 1024 * 1024
FILE_RETENTION_HOURS = 24
