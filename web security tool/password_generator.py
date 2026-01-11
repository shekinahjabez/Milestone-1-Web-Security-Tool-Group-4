import random
import string
import hashlib
from datetime import datetime

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def log_password(password, hashed):
    with open("logs/security_log.txt", "a") as file:
        file.write(f"{datetime.now()} | {password} | {hashed}\n")
