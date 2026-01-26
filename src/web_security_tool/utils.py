from pathlib import Path

# -----------------------------
# Project paths (safe file I/O)
# -----------------------------
# Points to project root: MILESTONE-1-WEB-SECURITY-TOOL/
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"

PASSWORD_HASH_FILE = DATA_DIR / "passwords.txt"
SECURITY_LOG_FILE = LOGS_DIR / "security_log.txt"


# -----------------------------
# Security reference lists
# -----------------------------
COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "admin", "letmein", "welcome"
]

DICTIONARY_WORDS = [
    "apple", "computer", "dragon", "monkey"
]

SQL_KEYWORDS = [
    "select", "insert", "update", "delete", "drop", "union"
]
