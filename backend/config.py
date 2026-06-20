# backend/config.py
import os
import secrets
import pathlib


def _load_or_create_secret():
    secret_path = pathlib.Path(os.path.expanduser("~/.gunnerc2/jwt_secret"))
    if secret_path.is_file() and secret_path.stat().st_size > 0:
        return secret_path.read_text().strip()
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    secret_path.write_text(key)
    os.chmod(secret_path, 0o600)
    return key


SECRET_KEY = _load_or_create_secret()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 90

DB_PATH = os.path.expanduser("~/.gunnerc2/operators.db")