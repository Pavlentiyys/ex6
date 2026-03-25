import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import cloud_config as config


def setup_keys() -> None:
    os.makedirs(config.KEYS_DIR, exist_ok=True)

    if not os.path.exists(config.KEY_FILE):
        key = Fernet.generate_key()
        with open(config.KEY_FILE, 'wb') as f:
            f.write(key)
        print(f"  [keys] Создан симметричный ключ: {config.KEY_FILE}")

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


def encrypt_file(data: bytes) -> tuple[bytes, bytes]:
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
    fernet_key = _load_private_key().decrypt(
        encrypted_fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return Fernet(fernet_key).decrypt(encrypted_data)


def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
