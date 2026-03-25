import hashlib
import html

import bcrypt

import config


def hash_iin(iin: str) -> str:
    return hashlib.sha256(iin.encode('utf-8')).hexdigest()


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)


def encrypt_phone(phone: str) -> bytes:
    return config.fernet.encrypt(phone.encode('utf-8'))


def decrypt_phone(ciphertext: bytes) -> str:
    return config.fernet.decrypt(ciphertext).decode('utf-8')


def sanitize_input(data: str) -> str:
    return html.escape(str(data).strip())
