import hashlib
import requests
from zxcvbn import zxcvbn

class Password_Assessor:
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

    @staticmethod
    def check_hibp_breach(password):
        """
        Checks if password exists in HIBP database using k-Anonymity.
        Returns the count of times breached, or 0 if safe.
        """
        # SHA-1 hash the password
        sha1_pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
        
        try:
            # Send only the first 5 chars to preserve privacy
            response = requests.get(f"{Password_Assessor.HIBP_API_URL}{prefix}", timeout=5)
            if response.status_code != 200:
                return 0 # Fail gracefully
            
            # Search response for our specific suffix
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
        except requests.RequestException:
            return 0
        return 0

    @classmethod
    def evaluate_password(cls, password, user_inputs=None):
        """
        Combines zxcvbn heuristics with live HIBP breach data.
        """
        if not password:
            return "Weak", "Password cannot be empty."

        # 1. Check Live Breach Data (Critical Priority)
        pwned_count = cls.check_hibp_breach(password)
        if pwned_count > 0:
            return "Weak", f"CRITICAL: This password was found in {pwned_count:,} data breaches. Change it immediately."

        # 2. Advanced Heuristics with zxcvbn
        # user_inputs can include username/email to detect personalized weak patterns
        results = zxcvbn(password, user_inputs=user_inputs)
        score = results['score'] # 0-4
        feedback = results['feedback']['warning']
        suggestions = results['feedback']['suggestions']

        # 3. Final Multi-layered Rating
        if score <= 1:
            status = "Weak"
        elif score <= 2:
            status = "Moderate"
        elif score >= 3:
            # Enforce absolute minimum length despite high entropy
            if len(password) < 12:
                status = "Moderate"
                suggestions.append("Even with patterns, aim for at least 12 characters.")
            else:
                status = "Strong"
        
        # Format detailed report
        report = f"{feedback}\n" + "\n".join([f"• {s}" for s in suggestions])
        return status, report.strip() or "Password is secure and unique."