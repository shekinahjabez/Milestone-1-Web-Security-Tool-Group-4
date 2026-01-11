import re
from utils import COMMON_PASSWORDS, DICTIONARY_WORDS

def evaluate_password(password):
    feedback = []
    score = 0

    if password.lower() in COMMON_PASSWORDS:
        return "Weak", "Password is commonly used."

    for word in DICTIONARY_WORDS:
        if word in password.lower():
            return "Weak", "Password contains a dictionary word."

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Minimum 12 characters required.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    if re.search(r"[!@#$%^&*()_+=\-[\]{};:'\",.<>?/\\|]", password):
        score += 1
    else:
        feedback.append("Add special characters.")

    if score <= 2:
        return "Weak", "\n".join(feedback)
    elif score <= 4:
        return "Moderate", "\n".join(feedback)
    else:
        return "Strong", "Password meets security requirements."
