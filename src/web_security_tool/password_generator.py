import secrets
import string
import hashlib
import bcrypt
from datetime import datetime

from .utils import PASSWORD_HASH_FILE, SECURITY_LOG_FILE


def generate_secure_password(length: int = 16) -> str:
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    numbers = string.digits
    symbols = '!@#$%^&*()_-+={}[];:,.?'

    if length < 8:
        raise ValueError("Password length must be at least 8.")
    if length < 4:
        raise ValueError("Password length must be at least 4 to include all required character sets.")

    # Ensure at least one from each group
    password_chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(numbers),
        secrets.choice(symbols),
    ]

    all_chars = uppercase + lowercase + numbers + symbols
    password_chars.extend(secrets.choice(all_chars) for _ in range(length - 4))

    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


def sha256_hash(password: str) -> str:
    # For demo/display only (NOT recommended for password storage)
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def bcrypt_hash(password: str, rounds: int = 12) -> str:
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password_bcrypt(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def save_bcrypt_hash_only(bcrypt_h: str) -> None:
    """
    Saves ONLY the bcrypt hash to data/passwords.txt
    (No plaintext password, no SHA-256)
    """
    PASSWORD_HASH_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with PASSWORD_HASH_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {bcrypt_h}\n")


def log_hashes_only(sha256_h: str, bcrypt_h: str) -> str:
    """
    Logs ONLY hashes (no plaintext password).
    """
    SECURITY_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with SECURITY_LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(
            f"Timestamp: {timestamp}\n"
            f"SHA-256 Hash: {sha256_h}\n"
            f"Bcrypt Hash: {bcrypt_h}\n"
            + "-" * 30 + "\n"
        )

    return timestamp


def process_generation(length: int = 16):
    """
    Returns plaintext to UI (display only),
    but writes/saves ONLY bcrypt hash + logs hashes only.
    """
    pwd = generate_secure_password(length)

    sha_h = sha256_hash(pwd)        # display/log only
    bcr_h = bcrypt_hash(pwd)        # store + log

    save_bcrypt_hash_only(bcr_h)    # ✅ only bcrypt saved
    ts = log_hashes_only(sha_h, bcr_h)  # ✅ no plaintext logged

    return pwd, sha_h, bcr_h, ts
