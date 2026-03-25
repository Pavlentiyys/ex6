"""
Service — шифрование файлов.
Этап 2: симметричное шифрование (Fernet/AES).
Этап 3: управление ключами (key.key).
Этап 4: асимметричное шифрование (RSA-4096), гибридная схема.
Этап 10: SHA-256 для проверки целостности.
"""

import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import cloud_config as config


# ---------------------------------------------------------------------------
# Этап 3: Управление ключами
# ---------------------------------------------------------------------------

def setup_keys() -> None:
    """Генерирует все ключи при первом запуске (если не существуют)."""
    os.makedirs(config.KEYS_DIR, exist_ok=True)

    # Этап 3: симметричный Fernet-ключ в key.key
    if not os.path.exists(config.KEY_FILE):
        key = Fernet.generate_key()
        with open(config.KEY_FILE, 'wb') as f:
            f.write(key)
        print(f"  [keys] Создан симметричный ключ: {config.KEY_FILE}")

    # Этап 4: RSA-4096 пара ключей
    if not os.path.exists(config.PRIVATE_KEY_FILE):
        print("  [keys] Генерация RSA-4096 (займёт несколько секунд)...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        with open(config.PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(config.PUBLIC_KEY_FILE, 'wb') as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        print(f"  [keys] RSA ключи созданы: {config.KEYS_DIR}")


def _load_public_key():
    with open(config.PUBLIC_KEY_FILE, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def _load_private_key():
    with open(config.PRIVATE_KEY_FILE, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ---------------------------------------------------------------------------
# Этап 2 + Этап 4: Гибридное шифрование (Fernet + RSA)
# Схема: Файл → Fernet(AES) → зашифрованные данные
#                Fernet-ключ → RSA(публичный) → зашифрованный ключ в БД
# ---------------------------------------------------------------------------

def encrypt_file(data: bytes) -> tuple[bytes, bytes]:
    """
    Гибридное шифрование:
    1. Генерирует уникальный Fernet-ключ для файла
    2. Шифрует файл Fernet-ключом
    3. Шифрует Fernet-ключ RSA публичным ключом

    Returns: (encrypted_data, encrypted_fernet_key)
    """
    fernet_key = Fernet.generate_key()
    encrypted_data = Fernet(fernet_key).encrypt(data)

    encrypted_fernet_key = _load_public_key().encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_data, encrypted_fernet_key


def decrypt_file(encrypted_data: bytes, encrypted_fernet_key: bytes) -> bytes:
    """
    Гибридная расшифровка:
    1. RSA приватным ключом расшифровывает Fernet-ключ
    2. Fernet-ключом расшифровывает файл
    """
    fernet_key = _load_private_key().decrypt(
        encrypted_fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return Fernet(fernet_key).decrypt(encrypted_data)


# ---------------------------------------------------------------------------
# Этап 10: Целостность файла
# ---------------------------------------------------------------------------

def sha256_hash(data: bytes) -> str:
    """SHA-256 хеш для проверки целостности файла."""
    return hashlib.sha256(data).hexdigest()
