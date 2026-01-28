import re
import html

class InputValidator:
    """
    Logic-only validator/sanitizer for 4 web-form fields:
    Full Name, Email, Username, Message.
    """

    @staticmethod
    def sanitize_input(text: str, field_type: str):
        """
        Sanitizes input by removing/neutralizing dangerous patterns.
        Returns: (sanitized_text, was_sanitized, notes[list[str]])
        """
        original = "" if text is None else str(text)
        t = original
        notes = []

        # -------------------
        # 1) Remove script blocks completely
        # -------------------
        script_pat = r"<\s*script\b.*?>.*?<\s*/\s*script\s*>"
        if re.search(script_pat, t, flags=re.IGNORECASE | re.DOTALL):
            t = re.sub(script_pat, "", t, flags=re.IGNORECASE | re.DOTALL)
            notes.append("Script tags removed")

        # -------------------
        # 2) Neutralize suspicious <img ... on...=> patterns
        # -------------------
        img_on_pat = r"<\s*img\b[^>]*\bon\w+\s*=\s*[^>]*>"
        if re.search(img_on_pat, t, flags=re.IGNORECASE):
            t = re.sub(img_on_pat, "", t, flags=re.IGNORECASE)
            notes.append("Suspicious <img> attributes removed")

        # -------------------
        # 3) Neutralize common SQL injection patterns
        # -------------------
        sql_patterns = [
            r"'\s*or\s*'1'\s*=\s*'1",
            r'"\s*or\s*"1"\s*=\s*"1',
            r"\bunion\b\s+\bselect\b",
            r"\bdrop\b",
            r"\binsert\b",
            r"\bdelete\b",
            r"\bupdate\b",
            r"\bselect\b",
            r"\bwhere\b",
        ]
        for pat in sql_patterns:
            if re.search(pat, t, flags=re.IGNORECASE):
                t = re.sub(pat, "", t, flags=re.IGNORECASE)
                if "SQL patterns neutralized" not in notes:
                    notes.append("SQL patterns neutralized")

        # -------------------
        # 4) Escape any remaining HTML tags/angle brackets
        # (turns < > into &lt; &gt; so tags can't run)
        # -------------------
        escaped = html.escape(t)
        if escaped != t:
            t = escaped
            notes.append("HTML characters escaped")

        # -------------------
        # 5) Field-specific cleanup (remove disallowed characters)
        # -------------------
        unescaped = html.unescape(t)

        if field_type == "name":
            cleaned = re.sub(r"[^a-zA-Z\s'-]", "", unescaped)
            if cleaned != unescaped:
                notes.append("Invalid characters removed from name")
            t = cleaned.strip()

        elif field_type == "email":
            cleaned = unescaped.replace(" ", "")
            cleaned2 = re.sub(r"[^a-zA-Z0-9@._+-]", "", cleaned)
            if cleaned2 != unescaped:
                notes.append("Invalid characters/spaces removed from email")
            t = cleaned2.strip()

        elif field_type == "username":
            cleaned = re.sub(r"[^a-zA-Z0-9_]", "", unescaped)
            if cleaned != unescaped:
                notes.append("Invalid characters removed from username")
            t = cleaned.strip()

        elif field_type == "message":
            # keep content, but it's already script/img/sql-neutralized + escaped
            t = t.strip()

        else:
            # unknown field_type: just return safely-escaped
            t = t.strip()

        # Normalize whitespace
        t2 = re.sub(r"\s+", " ", t).strip()
        if t2 != t:
            t = t2
            notes.append("Whitespace normalized")

        was_sanitized = (t != original) or (len(notes) > 0)
        # Remove duplicate notes while preserving order
        seen = set()
        notes = [n for n in notes if not (n in seen or seen.add(n))]

        return t, was_sanitized, notes

    # -------------------
    # VALIDATORS (return (bool, errors[]))
    # -------------------
    @staticmethod
    def validate_full_name(name: str):
        errors = []
        name = (name or "").strip()

        if len(name) < 2:
            errors.append("Full Name must be at least 2 characters long")

        if re.search(r"\d", name):
            errors.append("Full Name must not contain numbers")

        if re.search(r"[^a-zA-Z\s'-]", name):
            errors.append("Full Name must not contain special characters except spaces, hyphens, or apostrophes")

        return len(errors) == 0, errors

    @staticmethod
    def validate_email_simple(email: str):
        errors = []
        email = (email or "").strip()

        if " " in email:
            errors.append("Email Address must not contain spaces")

        if email and not email[0].isalnum():
            errors.append("Email Address must not start with a special character")

        if "@" not in email:
            errors.append("Email Address must contain an '@' symbol")

        # must end with .<letters> (like .com, .org, .ph)
        if not re.search(r"\.[a-zA-Z]{2,}$", email):
            errors.append("Invalid email format (missing domain like .com, .org)")

        return len(errors) == 0, errors

    @staticmethod
    def validate_username(username: str):
        errors = []
        username = (username or "").strip()

        if len(username) < 4:
            errors.append("Username must be at least 4 characters")

        if len(username) > 16:
            errors.append("Username cannot exceed 16 characters")

        if username and username[0].isdigit():
            errors.append("Username cannot start with a number")

        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", username):
            errors.append("Username can only contain letters, numbers, and underscores")

        return len(errors) == 0, errors

    @staticmethod
    def validate_message(message: str):
        errors = []
        message = (message or "")

        if not message.strip():
            errors.append("Message / Comment cannot be empty")

        if len(message) > 250:
            errors.append("Message / Comment cannot exceed 250 characters")

        # harmful patterns (in case user pasted raw and it survived)
        if re.search(r"<\s*script\b", message, re.IGNORECASE):
            errors.append("The message contains prohibited <script> tags")

        if re.search(r"<\s*img\b[^>]*\bon\w+\s*=", message, re.IGNORECASE):
            errors.append("The message contains suspicious <img> attributes")

        sql_keywords = ["SELECT", "DROP", "INSERT", "DELETE", "UPDATE", "UNION", "WHERE"]
        for kw in sql_keywords:
            if re.search(rf"\b{kw}\b", message, re.IGNORECASE):
                errors.append(f"The message contains prohibited SQL keyword: {kw}")
                break

        return len(errors) == 0, errors
