"""
Service — функции безопасности.
Этапы 1, 2, 3, 7: хеширование, шифрование, экранирование.
Нет зависимостей от Flask или БД — чистые функции.
"""

import hashlib
import html

import bcrypt

import config


# --- Этап 1: Минимизация данных ---

def hash_iin(iin: str) -> str:
    """SHA-256 хеш ИИН. Оригинал никогда не сохраняется."""
    return hashlib.sha256(iin.encode('utf-8')).hexdigest()


# --- Этап 2: Защита пароля ---

def hash_password(password: str) -> bytes:
    """bcrypt-хеш пароля для хранения как BLOB."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    """Проверяет пароль против bcrypt-хеша."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)


# --- Этап 3: Шифрование чувствительных данных ---

def encrypt_phone(phone: str) -> bytes:
    """Шифрует номер телефона алгоритмом Fernet."""
    return config.fernet.encrypt(phone.encode('utf-8'))


def decrypt_phone(ciphertext: bytes) -> str:
    """Расшифровывает номер телефона."""
    return config.fernet.decrypt(ciphertext).decode('utf-8')


# --- Этап 7: Защита от XSS ---

def sanitize_input(data: str) -> str:
    """Экранирует HTML-символы для нейтрализации XSS-атак."""
    return html.escape(str(data).strip())
