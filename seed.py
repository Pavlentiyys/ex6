import hashlib
import io
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import config
import cloud_config

FERNET = config.fernet


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def encrypt_phone(phone: str) -> bytes:
    return FERNET.encrypt(phone.encode())


def bcrypt_hash(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12))


def seed_users_db():
    db = sqlite3.connect(config.DATABASE)
    db.execute("DELETE FROM access_log")
    db.execute("DELETE FROM users")
    db.execute("DELETE FROM sqlite_sequence WHERE name IN ('users','access_log')")

    users = [
        {
            "email": "ivanov@example.com",
            "password": "Ivanov2026!",
            "iin": "900101350123",
            "phone": "+7 701 234 56 78",
            "role": "user",
            "created_at": "2026-03-20T09:14:32+00:00",
            "last_login": "2026-03-26T01:42:13+00:00",
        },
        {
            "email": "petrov@example.com",
            "password": "Petrov_pass99",
            "iin": "850515401234",
            "phone": "+7 702 345 67 89",
            "role": "user",
            "created_at": "2026-03-21T11:03:55+00:00",
            "last_login": "2026-03-25T18:30:00+00:00",
        },
        {
            "email": "seitkali@example.com",
            "password": "Seitkali#2026",
            "iin": "950320301987",
            "phone": "+7 705 456 78 90",
            "role": "user",
            "created_at": "2026-03-22T14:27:10+00:00",
            "last_login": "2026-03-26T00:05:44+00:00",
        },
        {
            "email": "admin@example.com",
            "password": "admin123",
            "iin": "800801123456",
            "phone": "+7 700 111 22 33",
            "role": "admin",
            "created_at": "2026-03-01T08:00:00+00:00",
            "last_login": "2026-03-26T02:00:00+00:00",
        },
    ]

    for u in users:
        db.execute(
            """INSERT INTO users (email, password_hash, iin_hash, phone_encrypted, role, created_at, last_login)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                u["email"],
                bcrypt_hash(u["password"]),
                sha256(u["iin"]),
                encrypt_phone(u["phone"]),
                u["role"],
                u["created_at"],
                u["last_login"],
            ),
        )

    logs = [
        ("ivanov@example.com",   "register",        "2026-03-20T09:14:32+00:00", "192.168.1.101"),
        ("petrov@example.com",   "register",        "2026-03-21T11:03:55+00:00", "192.168.1.45"),
        ("seitkali@example.com", "register",        "2026-03-22T14:27:10+00:00", "10.0.0.17"),
        ("ivanov@example.com",   "login_success",   "2026-03-26T01:42:13+00:00", "192.168.1.101"),
        ("ivanov@example.com",   "view_profile",    "2026-03-26T01:42:15+00:00", "192.168.1.101"),
        ("ivanov@example.com",   "DENIED:list_users","2026-03-26T01:42:17+00:00","192.168.1.101"),
        ("admin@example.com",    "login_success",   "2026-03-26T01:42:19+00:00", "10.0.0.1"),
        ("admin@example.com",    "admin_list_users","2026-03-26T01:42:20+00:00", "10.0.0.1"),
        ("admin@example.com",    "promote_user",    "2026-03-26T01:42:22+00:00", "10.0.0.1"),
        ("petrov@example.com",   "login_success",   "2026-03-25T18:30:00+00:00", "192.168.1.45"),
        ("petrov@example.com",   "view_profile",    "2026-03-25T18:30:03+00:00", "192.168.1.45"),
        ("seitkali@example.com", "login_success",   "2026-03-26T00:05:44+00:00", "10.0.0.17"),
        ("unknown",              "login_failed",    "2026-03-26T01:15:03+00:00", "185.220.101.47"),
        ("unknown",              "login_failed",    "2026-03-26T01:15:07+00:00", "185.220.101.47"),
    ]

    for email, action, ts, ip in logs:
        db.execute(
            "INSERT INTO access_log (user_email, action, timestamp, ip_address) VALUES (?, ?, ?, ?)",
            (email, action, ts, ip),
        )

    db.commit()
    db.close()
    print(f"  users.db: {len(users)} users, {len(logs)} access_log entries")


def seed_cloud_db():
    db = sqlite3.connect(cloud_config.DATABASE)
    db.execute("DELETE FROM files")
    db.execute("DELETE FROM cloud_users")
    db.execute("DELETE FROM sqlite_sequence WHERE name IN ('cloud_users')")

    cloud_users = [
        ("admin@cloud.local", b"admin123", "admin"),
        ("user@cloud.local",  b"user123",  "user"),
        ("developer@cloud.local", b"Dev2026#", "user"),
        ("manager@cloud.local",   b"Mgr_pass1", "user"),
    ]

    for email, pw, role in cloud_users:
        db.execute(
            "INSERT INTO cloud_users (email, password_hash, role) VALUES (?, ?, ?)",
            (email, bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)), role),
        )

    public_key_path = cloud_config.PUBLIC_KEY_FILE
    with open(public_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())

    def rsa_encrypt(data: bytes) -> bytes:
        return pub_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    os.makedirs(cloud_config.UPLOAD_FOLDER, exist_ok=True)

    files_meta = [
        {
            "filename": "document.txt",
            "owner": "user@cloud.local",
            "content": b"secret document content\nowner: user@cloud.local\nclassification: internal",
            "uploaded_at": "2026-03-26T02:15:42+00:00",
        },
        {
            "filename": "report_q1_2026.pdf",
            "owner": "admin@cloud.local",
            "content": b"Q1 2026 Financial Report - CONFIDENTIAL\nRevenue: 4 200 000 KZT\nProfit: 1 050 000 KZT",
            "uploaded_at": "2026-03-25T14:30:11+00:00",
        },
        {
            "filename": "client_list.csv",
            "owner": "manager@cloud.local",
            "content": b"id,name,email,phone\n1,Ivanov Ivan,ivanov@example.com,+77012345678\n2,Petrov Petr,petrov@example.com,+77023456789",
            "uploaded_at": "2026-03-24T09:00:00+00:00",
        },
        {
            "filename": "deploy_config.yaml",
            "owner": "developer@cloud.local",
            "content": b"app:\n  name: cloudsync\n  version: 2.1.4\n  env: production\n  replicas: 3",
            "uploaded_at": "2026-03-23T16:45:20+00:00",
        },
    ]

    for meta in files_meta:
        fernet_key = Fernet.generate_key()
        encrypted_data = Fernet(fernet_key).encrypt(meta["content"])
        encrypted_key = rsa_encrypt(fernet_key)
        file_hash = hashlib.sha256(meta["content"]).hexdigest()
        file_id = str(uuid.uuid4())
        enc_path = os.path.join(cloud_config.UPLOAD_FOLDER, f"{file_id}.enc")

        with open(enc_path, "wb") as f:
            f.write(encrypted_data)

        db.execute(
            """INSERT INTO files
               (id, filename, owner, encrypted_path, encrypted_key, sha256_hash, uploaded_at, size)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, meta["filename"], meta["owner"], enc_path,
             encrypted_key, file_hash, meta["uploaded_at"], len(meta["content"])),
        )

    db.commit()
    db.close()
    print(f"  cloud.db: {len(cloud_users)} users, {len(files_meta)} files")


if __name__ == "__main__":
    print("Seeding users.db (lab 6)...")
    seed_users_db()

    print("Seeding cloud.db (lab 7-8)...")
    seed_cloud_db()

    print("Done.")
