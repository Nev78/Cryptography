import os
import json
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256  # <-- правильний модуль для pycryptodome

USERS_FILE = "users.json"

def derive_key(username: str, password: str) -> bytes:
    """
    Генерує ключ AES-128 (16 байт) на основі пароля користувача.
    Використовується PBKDF2-HMAC-SHA256 для підвищення ентропії.
    """
    # Завантажуємо існуючі метадані або створюємо пустий список
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
    else:
        users = []

    # Шукаємо користувача
    user_data = next((u for u in users if u["username"] == username), None)

    if user_data is None:
        # Створюємо нову сіль (salt) для нового користувача
        salt = os.urandom(16)  # 16 байт = 128 біт
        user_data = {
            "username": username,
            "salt": salt.hex()
        }
        users.append(user_data)
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)
    else:
        salt = bytes.fromhex(user_data["salt"])

    # Генеруємо ключ AES-128 (16 байт)
    key = PBKDF2(password, salt, dkLen=16, count=100_000, hmac_hash_module=SHA256)

    return key

# Приклад використання:
if __name__ == "__main__":
    key = derive_key("Alice", "supersecretpassword")
    print("AES-128 key (hex):", key.hex())
