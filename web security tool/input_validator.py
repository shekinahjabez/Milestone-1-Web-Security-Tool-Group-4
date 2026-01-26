import tkinter as tk
from tkinter import messagebox, scrolledtext
import re
import random
import string
import hashlib
from urllib.parse import urlparse

class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    @staticmethod
    def validate_full_name(name):
        """
        Validates the full name field.
        Rules: No numbers, only spaces/hyphens/apostrophes as special chars, min 2 chars
        """
        errors = []
        
        if len(name) < 2:
            errors.append("Full Name must be at least 2 characters long")
        
        # Check for numbers
        if re.search(r'\d', name):
            errors.append("Full Name cannot contain numbers")
        
        # Check for invalid special characters (allow only space, hyphen, apostrophe)
        if re.search(r'[^a-zA-Z\s\'-]', name):
            errors.append("Full Name contains invalid special characters")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_email_simple(email):
        """
        Validates the email address.
        Rules: Must have @, domain extension, no spaces, no leading special char
        """
        errors = []
        
        # Check for spaces
        if ' ' in email:
            errors.append("Email cannot contain spaces")
        
        # Check if starts with special character
        if email and not email[0].isalnum():
            errors.append("Email cannot start with a special character")
        
        # Check for @ symbol
        if '@' not in email:
            errors.append("Email must contain '@' symbol")
        
        # Check for domain extension
        if not re.search(r'\.[a-zA-Z]{2,}$', email):
            errors.append("Email must contain a valid domain (e.g., .com, .org)")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_username(username):
        """
        Validates the username.
        Rules: Only letters/numbers/underscores, 4-16 chars, cannot start with number
        """
        errors = []
        
        if len(username) < 4:
            errors.append("Username must be at least 4 characters")
        
        if len(username) > 16:
            errors.append("Username cannot exceed 16 characters")
        
        # Check if starts with a number
        if username and username[0].isdigit():
            errors.append("Username cannot start with a number")
        
        # Check for invalid characters (only letters, numbers, underscores allowed)
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', username):
            errors.append("Username can only contain letters, numbers, and underscores")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_message(message):
        """
        Validates the message/comment field.
        Rules: Not empty, max 250 chars, no harmful patterns
        """
        errors = []
        
        if not message.strip():
            errors.append("Message cannot be empty")
        
        if len(message) > 250:
            errors.append("Message cannot exceed 250 characters")
        
        # Check for harmful patterns
        if re.search(r'<script', message, re.IGNORECASE):
            errors.append("Message contains prohibited <script> tag")
        
        if re.search(r'<img[^>]*on\w+\s*=', message, re.IGNORECASE):
            errors.append("Message contains suspicious <img> attributes")
        
        # Check for SQL injection keywords
        sql_keywords = ['SELECT', 'DROP', 'INSERT', 'DELETE', 'UPDATE', 'UNION', 'WHERE']
        for keyword in sql_keywords:
            if re.search(r'\b' + keyword + r'\b', message, re.IGNORECASE):
                errors.append(f"Message contains prohibited SQL keyword: {keyword}")
                break
        
        return len(errors) == 0, errors
    
    @staticmethod
    def sanitize_input(text, field_type):
        """
        Sanitizes input by removing or neutralizing dangerous elements.
        Returns: (sanitized_text, was_sanitized, sanitization_notes)
        """
        original = text
        notes = []
        
        # Remove HTML tags
        if re.search(r'<[^>]+>', text):
            text = re.sub(r'<[^>]+>', '', text)
            notes.append("HTML tags removed")
        
        # Remove script content
        if re.search(r'<script.*?</script>', text, re.IGNORECASE | re.DOTALL):
            text = re.sub(r'<script.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
            notes.append("Script tags removed")
        
        # Remove SQL injection keywords and patterns
        sql_keywords = ['SELECT', 'DROP', 'INSERT', 'DELETE', 'UPDATE', 'UNION', 'WHERE', 'FROM', 'TABLE']
        for keyword in sql_keywords:
            if re.search(r'\b' + keyword + r'\b', text, re.IGNORECASE):
                text = re.sub(r'\b' + keyword + r'\b', '', text, flags=re.IGNORECASE)
                notes.append(f"SQL keyword '{keyword}' removed")
        
        # Remove SQL special characters and patterns
        sql_chars = [';', '--', '/*', '*/', '1=1', "' OR '", '" OR "']
        for char in sql_chars:
            if char in text:
                text = text.replace(char, '')
                if "SQL" not in ' '.join(notes):
                    notes.append("SQL injection patterns neutralized")
        
        # Remove quotes used in SQL injection
        if re.search(r"['\"]", text):
            text = re.sub(r"['\"]", '', text)
            if "SQL" not in ' '.join(notes):
                notes.append("Potentially dangerous quotes removed")
        
        # Field-specific sanitization
        if field_type == 'name':
            # Remove any characters that aren't letters, spaces, hyphens, or apostrophes
            text = re.sub(r'[^a-zA-Z\s\'-]', '', text)
            if text != original and "Invalid characters" not in ' '.join(notes):
                notes.append("Invalid characters removed from name")
        
        elif field_type == 'username':
            # Remove any characters that aren't letters, numbers, or underscores
            text = re.sub(r'[^a-zA-Z0-9_]', '', text)
            if text != original and "Invalid characters" not in ' '.join(notes):
                notes.append("Invalid characters removed from username")
        
        elif field_type == 'email':
            # Remove spaces
            text = text.replace(' ', '')
            if text != original and "Spaces" not in ' '.join(notes):
                notes.append("Spaces removed from email")
        
        # Clean up extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        was_sanitized = len(notes) > 0
        return text, was_sanitized, notes
    
    @staticmethod
    def validate_email(value):
        errors = []
        warnings = []
        sanitized = value.replace('\0', '').strip()
        is_valid = True
        
        # Check for XSS
        if re.search(r'<script|javascript:|onerror=|onload=', value, re.IGNORECASE):
            warnings.append('⚠️ Potential XSS attempt detected')
        
        # Email validation
        email_regex = r'^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not value:
            errors.append('Email is required')
            is_valid = False
        elif not re.match(email_regex, value):
            errors.append('Invalid email format')
            is_valid = False
        elif len(value) > 254:
            errors.append('Email is too long (max 254 characters)')
            is_valid = False
        
        # Sanitize email
        sanitized = sanitized.lower()
        
        # Check for consecutive dots
        if '@' in sanitized:
            domain = sanitized.split('@')[1]
            if '..' in domain:
                errors.append('Email contains consecutive dots')
                is_valid = False
        
        return {
            'isValid': is_valid,
            'sanitized': sanitized,
            'errors': errors,
            'warnings': warnings
        }
    
    @staticmethod
    def validate_url(value):
        errors = []
        warnings = []
        sanitized = value.replace('\0', '').strip()
        is_valid = True
        
        # Check for XSS
        if re.search(r'<script|javascript:|onerror=|onload=', value, re.IGNORECASE):
            warnings.append('⚠️ Potential XSS attempt detected')
        
        if not value:
            errors.append('URL is required')
            is_valid = False
        else:
            try:
                parsed = urlparse(sanitized)
                
                # Check protocol
                if parsed.scheme not in ['http', 'https']:
                    errors.append('URL must use HTTP or HTTPS protocol')
                    is_valid = False
                
                # Check for suspicious TLDs
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
                if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
                    warnings.append('Domain uses a potentially suspicious TLD')
                
                sanitized = parsed.geturl()
                
            except:
                errors.append('Invalid URL format')
                is_valid = False
        
        return {
            'isValid': is_valid,
            'sanitized': sanitized,
            'errors': errors,
            'warnings': warnings
        }
    
    @staticmethod
    def validate_phone(value):
        errors = []
        warnings = []
        sanitized = value.replace('\0', '').strip()
        is_valid = True
        
        # Remove all non-digit characters
        digits_only = re.sub(r'\D', '', sanitized)
        
        if not value:
            errors.append('Phone number is required')
            is_valid = False
        elif len(digits_only) < 10:
            errors.append('Phone number must be at least 10 digits')
            is_valid = False
        elif len(digits_only) > 15:
            errors.append('Phone number is too long')
            is_valid = False
        
        # Format phone number
        if len(digits_only) == 10:
            sanitized = f"({digits_only[:3]}) {digits_only[3:6]}-{digits_only[6:]}"
        elif len(digits_only) == 11:
            sanitized = f"+{digits_only[0]} ({digits_only[1:4]}) {digits_only[4:7]}-{digits_only[7:]}"
        else:
            sanitized = digits_only
        
        return {
            'isValid': is_valid,
            'sanitized': sanitized,
            'errors': errors,
            'warnings': warnings
        }
    
    @staticmethod
    def validate_alphanumeric(value):
        errors = []
        warnings = []
        sanitized = value.replace('\0', '').strip()
        is_valid = True
        
        # Alphanumeric validation
        alphanumeric_regex = r'^[a-zA-Z0-9]+$'
        
        if not value:
            errors.append('Input is required')
            is_valid = False
        elif not re.match(alphanumeric_regex, value):
            errors.append('Only letters and numbers are allowed')
            is_valid = False
        elif len(value) < 3:
            errors.append('Must be at least 3 characters long')
            is_valid = False
        elif len(value) > 50:
            errors.append('Must be less than 50 characters')
            is_valid = False
        
        # Sanitize - remove any non-alphanumeric
        sanitized = re.sub(r'[^a-zA-Z0-9]', '', sanitized)
        
        return {
            'isValid': is_valid,
            'sanitized': sanitized,
            'errors': errors,
            'warnings': warnings
        }
    
    @staticmethod
    def validate_text(value):
        errors = []
        warnings = []
        sanitized = value.replace('\0', '').strip()
        is_valid = True
        
        # Check for XSS
        if re.search(r'<script|javascript:|onerror=|onload=', value, re.IGNORECASE):
            warnings.append('⚠️ Potential XSS attempt detected')
        
        if not value:
            errors.append('Text is required')
            is_valid = False
        elif len(value) > 1000:
            errors.append('Text is too long (max 1000 characters)')
            is_valid = False
        
        # HTML encode special characters
        sanitized = (sanitized
                    .replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('"', '&quot;')
                    .replace("'", '&#x27;')
                    .replace('/', '&#x2F;'))
        
        # Warn about potentially dangerous characters
        if re.search(r'[<>{}\\]', value):
            warnings.append('HTML/Script tags have been sanitized')
        
        return {
            'isValid': is_valid,
            'sanitized': sanitized,
            'errors': errors,
            'warnings': warnings
        }
    
    @staticmethod
    def validate_sql(value):
        errors = []
        warnings = []
        sanitized = value.replace('\0', '').strip()
        is_valid = True
        
        # Check for SQL injection patterns
        if re.search(r"'.*--|\/\*|\*\/|xp_|sp_|exec\s*\(|union\s+select", value, re.IGNORECASE):
            warnings.append('⚠️ Potential SQL injection pattern detected')
        
        if not value:
            errors.append('SQL input is required')
            is_valid = False
        
        # Check for dangerous SQL commands
        dangerous_patterns = [
            (r'drop\s+(table|database)', 'DROP TABLE/DATABASE'),
            (r'delete\s+from', 'DELETE FROM'),
            (r'truncate', 'TRUNCATE'),
            (r'alter\s+table', 'ALTER TABLE'),
            (r'grant|revoke', 'GRANT/REVOKE'),
            (r'exec\s*\(', 'EXEC')
        ]
        
        for pattern, name in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                errors.append(f'Dangerous SQL command detected: {name}')
                warnings.append('⚠️ CRITICAL: Potential data destruction command')
                is_valid = False
                break
        
        # Escape single quotes
        sanitized = sanitized.replace("'", "''")
        
        # Add warning about parameterized queries
        if "'" in value or '"' in value:
            warnings.append('Use parameterized queries instead of string concatenation')
        
        return {
            'isValid': is_valid,
            'sanitized': sanitized,
            'errors': errors,
            'warnings': warnings
        }

class WebSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Security Tool")
        self.root.geometry("1100x900")
        self.root.configure(bg="#0a0e27")
        
        # Main container
        self.main_container = tk.Frame(self.root, bg="#0a0e27")
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self.create_header()
        
        # Tab buttons
        self.create_tab_buttons()
        
        # Content area
        self.content_frame = tk.Frame(self.main_container, bg="#1e2139", relief=tk.FLAT)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=(20, 40))
        
        # Show default tab
        self.current_tab = "validator"
        self.show_input_validator()
        
    def create_header(self):
        header_frame = tk.Frame(self.main_container, bg="#0a0e27")
        header_frame.pack(fill=tk.X, pady=(30, 20))
        
        icon_label = tk.Label(header_frame, text="🛡️", font=("Arial", 48), 
                             bg="#0a0e27", fg="#22d3ee")
        icon_label.pack()
        
        title = tk.Label(header_frame, text="Web Security Tool", 
                        font=("Arial", 36, "bold"), bg="#0a0e27", fg="white")
        title.pack(pady=(10, 5))
        
        subtitle = tk.Label(header_frame, 
                           text="Professional security utilities for password management and input validation",
                           font=("Arial", 12), bg="#0a0e27", fg="#94a3b8")
        subtitle.pack()
    
    def create_tab_buttons(self):
        tab_frame = tk.Frame(self.main_container, bg="#0a0e27")
        tab_frame.pack(pady=20)
        
        button_container = tk.Frame(tab_frame, bg="#0a0e27")
        button_container.pack()
        
        self.strength_btn = tk.Button(button_container, text="🛡️  Password Strength",
                                      command=lambda: self.switch_tab("strength"),
                                      bg="#1e293b", fg="#94a3b8", font=("Arial", 11, "bold"),
                                      relief=tk.FLAT, cursor="hand2", padx=25, pady=12,
                                      activebackground="#334155", activeforeground="white")
        self.strength_btn.pack(side=tk.LEFT, padx=5)
        
        self.generator_btn = tk.Button(button_container, text="🔑  Password Generator",
                                       command=lambda: self.switch_tab("generator"),
                                       bg="#1e293b", fg="#94a3b8", font=("Arial", 11, "bold"),
                                       relief=tk.FLAT, cursor="hand2", padx=25, pady=12,
                                       activebackground="#334155", activeforeground="white")
        self.generator_btn.pack(side=tk.LEFT, padx=5)
        
        self.validator_btn = tk.Button(button_container, text="📋  Input Validator",
                                       command=lambda: self.switch_tab("validator"),
                                       bg="#06b6d4", fg="white", font=("Arial", 11, "bold"),
                                       relief=tk.FLAT, cursor="hand2", padx=25, pady=12,
                                       activebackground="#0891b2", activeforeground="white")
        self.validator_btn.pack(side=tk.LEFT, padx=5)
        
        self.tab_buttons = {
            "strength": self.strength_btn,
            "generator": self.generator_btn,
            "validator": self.validator_btn
        }
    
    def switch_tab(self, tab_name):
        for name, btn in self.tab_buttons.items():
            if name == tab_name:
                btn.configure(bg="#06b6d4", fg="white")
            else:
                btn.configure(bg="#1e293b", fg="#94a3b8")
        
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        self.current_tab = tab_name
        if tab_name == "strength":
            self.show_password_strength()
        elif tab_name == "generator":
            self.show_password_generator()
        elif tab_name == "validator":
            self.show_input_validator()
    
    def show_password_strength(self):
        content = tk.Frame(self.content_frame, bg="#1e2139")
        content.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        tk.Label(content, text="Password Strength Checker", 
                font=("Arial", 20, "bold"), bg="#1e2139", fg="white").pack(anchor=tk.W)
        
        tk.Label(content, text="Analyze your password security", 
                font=("Arial", 11), bg="#1e2139", fg="#94a3b8").pack(anchor=tk.W, pady=(5, 25))
        
        tk.Label(content, text="Enter password to check:", 
                font=("Arial", 10), bg="#1e2139", fg="#94a3b8").pack(anchor=tk.W, pady=(0, 8))
        
        self.pwd_entry = tk.Entry(content, font=("Arial", 12), bg="#2d3250", fg="white", 
                                  insertbackground="white", relief=tk.FLAT, show="*",
                                  borderwidth=0, highlightthickness=0)
        self.pwd_entry.pack(fill=tk.X, ipady=12, pady=(0, 20))
        
        check_btn = tk.Button(content, text="Check Password Strength", 
                             command=self.check_password_strength,
                             bg="#06b6d4", fg="white", font=("Arial", 12, "bold"),
                             relief=tk.FLAT, cursor="hand2", padx=30, pady=15,
                             borderwidth=0, activebackground="#0891b2")
        check_btn.pack(fill=tk.X, pady=(0, 25))
        
        self.pwd_result_frame = tk.Frame(content, bg="#1e2139")
        self.pwd_result_frame.pack(fill=tk.BOTH, expand=True)
    
    def check_password_strength(self):
        for widget in self.pwd_result_frame.winfo_children():
            widget.destroy()
        
        password = self.pwd_entry.get()
        
        if not password:
            return
        
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters")
        
        if len(password) >= 12:
            score += 1
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if re.search(r'[0-9]', password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if re.search(r'[^a-zA-Z0-9]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        if score >= 5:
            strength = "Strong"
            color = "#10b981"
        elif score >= 3:
            strength = "Medium"
            color = "#f59e0b"
        else:
            strength = "Weak"
            color = "#ef4444"
        
        result_frame = tk.Frame(self.pwd_result_frame, bg="#2d3250")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        inner = tk.Frame(result_frame, bg="#2d3250")
        inner.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)
        
        strength_frame = tk.Frame(inner, bg="#2d3250")
        strength_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(strength_frame, text="Strength:", font=("Arial", 13), 
                bg="#2d3250", fg="white").pack(side=tk.LEFT)
        tk.Label(strength_frame, text=strength, font=("Arial", 18, "bold"), 
                bg="#2d3250", fg=color).pack(side=tk.RIGHT)
        
        progress_frame = tk.Frame(inner, bg="#475569", height=12)
        progress_frame.pack(fill=tk.X, pady=(0, 20))
        progress_frame.pack_propagate(False)
        
        progress_fill = tk.Frame(progress_frame, bg=color, height=12)
        progress_fill.place(relwidth=score/6, relheight=1)
        
        if feedback:
            tk.Label(inner, text="Suggestions:", font=("Arial", 12, "bold"), 
                    bg="#2d3250", fg="white").pack(anchor=tk.W, pady=(10, 8))
            
            for tip in feedback:
                tk.Label(inner, text=f"• {tip}", font=("Arial", 10), 
                        bg="#2d3250", fg="#94a3b8").pack(anchor=tk.W, padx=(15, 0), pady=2)
    
    def show_password_generator(self):
        content = tk.Frame(self.content_frame, bg="#1e2139")
        content.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        tk.Label(content, text="Password Generator", 
                font=("Arial", 20, "bold"), bg="#1e2139", fg="white").pack(anchor=tk.W)
        
        tk.Label(content, text="Generate secure random passwords", 
                font=("Arial", 11), bg="#1e2139", fg="#94a3b8").pack(anchor=tk.W, pady=(5, 25))
        
        gen_btn = tk.Button(content, text="Generate Secure Password", 
                           command=self.generate_password,
                           bg="#06b6d4", fg="white", font=("Arial", 12, "bold"),
                           relief=tk.FLAT, cursor="hand2", padx=30, pady=15,
                           borderwidth=0, activebackground="#0891b2")
        gen_btn.pack(fill=tk.X, pady=(0, 25))
        
        self.gen_result_frame = tk.Frame(content, bg="#1e2139")
        self.gen_result_frame.pack(fill=tk.BOTH, expand=True)
    
    def generate_password(self):
        for widget in self.gen_result_frame.winfo_children():
            widget.destroy()
        
        length = 16
        charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        password = ''.join(random.choice(charset) for _ in range(length))
        
        hash_obj = hashlib.sha256(password.encode())
        hash_hex = hash_obj.hexdigest()
        
        result_frame = tk.Frame(self.gen_result_frame, bg="#2d3250")
        result_frame.pack(fill=tk.X, padx=5, pady=5)
        
        inner = tk.Frame(result_frame, bg="#2d3250")
        inner.pack(fill=tk.BOTH, padx=25, pady=25)
        
        tk.Label(inner, text="Generated Password:", 
                font=("Arial", 10), bg="#2d3250", fg="#94a3b8").pack(anchor=tk.W, pady=(0, 8))
        
        pwd_frame = tk.Frame(inner, bg="#2d3250")
        pwd_frame.pack(fill=tk.X, pady=(0, 20))
        
        pwd_display = tk.Frame(pwd_frame, bg="#1a1d2e")
        pwd_display.pack(fill=tk.X)
        
        pwd_label = tk.Label(pwd_display, text=password, font=("Courier", 16, "bold"), 
                            bg="#1a1d2e", fg="#06b6d4", anchor=tk.W)
        pwd_label.pack(side=tk.LEFT, padx=15, pady=15, fill=tk.X, expand=True)
        
        copy_btn = tk.Button(pwd_display, text="Copy", 
                            command=lambda: self.copy_to_clipboard(password),
                            bg="#06b6d4", fg="white", font=("Arial", 10, "bold"), 
                            relief=tk.FLAT, cursor="hand2", padx=20, pady=8,
                            borderwidth=0)
        copy_btn.pack(side=tk.RIGHT, padx=15, pady=15)
        
        tk.Label(inner, text="SHA-256 Hash:", 
                font=("Arial", 10), bg="#2d3250", fg="#94a3b8").pack(anchor=tk.W, pady=(10, 8))
        
        hash_display = tk.Frame(inner, bg="#1a1d2e")
        hash_display.pack(fill=tk.X)
        
        tk.Label(hash_display, text=hash_hex, font=("Courier", 9), 
                bg="#1a1d2e", fg="#94a3b8", wraplength=700, anchor=tk.W).pack(padx=15, pady=15)
    
    def show_input_validator(self):
        # Create scrollable content
        canvas = tk.Canvas(self.content_frame, bg="#1e2139", highlightthickness=0)
        scrollbar = tk.Scrollbar(self.content_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#1e2139")
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        content = tk.Frame(scrollable_frame, bg="#1e2139")
        content.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        tk.Label(content, text="Input Validator & Sanitizer", 
                font=("Arial", 20, "bold"), bg="#1e2139", fg="white").pack(anchor=tk.W)
        
        tk.Label(content, text="Validate and sanitize user input to prevent security vulnerabilities", 
                font=("Arial", 11), bg="#1e2139", fg="#94a3b8").pack(anchor=tk.W, pady=(5, 25))
        
        # Validation Type
        tk.Label(content, text="Validation Type", 
                font=("Arial", 10), bg="#1e2139", fg="#94a3b8").pack(anchor=tk.W, pady=(0, 10))
        
        type_frame = tk.Frame(content, bg="#1e2139")
        type_frame.pack(fill=tk.X, pady=(0, 25))
        
        self.validation_type = tk.StringVar(value="email")
        self.type_buttons = {}
        
        types = [
            ("Email Address", "email"),
            ("URL/Website", "url"),
            ("Phone Number", "phone"),
            ("Alphanumeric", "alphanumeric"),
            ("Text/HTML", "text"),
            ("SQL Input", "sql")
        ]
        
        for i, (label, value) in enumerate(types):
            row = i // 3
            col = i % 3
            
            btn = tk.Button(type_frame, text=label, 
                           command=lambda v=value: self.select_validation_type(v),
                           bg="#06b6d4" if value == "email" else "#2d3250",
                           fg="white" if value == "email" else "#94a3b8",
                           font=("Arial", 10, "bold"),
                           relief=tk.FLAT, cursor="hand2", padx=20, pady=12,
                           borderwidth=0,
                           activebackground="#0891b2" if value == "email" else "#3d4268")
            btn.grid(row=row, column=col, sticky="ew", padx=5, pady=5)
            self.type_buttons[value] = btn
        
        for i in range(3):
            type_frame.columnconfigure(i, weight=1)
        
        # Input area
        tk.Label(content, text="Enter Input to Validate", 
                font=("Arial", 10), bg="#1e2139", fg="#94a3b8").pack(anchor=tk.W, pady=(0, 8))
        
        # Create a frame for the text widget with fixed height
        text_frame = tk.Frame(content, bg="#2d3250", height=200)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 25))
        text_frame.pack_propagate(False)
        
        self.input_text = tk.Text(text_frame, font=("Arial", 11), 
                                 bg="#2d3250", fg="white", insertbackground="white", 
                                 relief=tk.FLAT, wrap=tk.WORD, borderwidth=0,
                                 highlightthickness=0, padx=15, pady=12)
        self.input_text.pack(fill=tk.BOTH, expand=True)
        
        # Validate button
        validate_btn = tk.Button(content, text="🛡️  Validate & Sanitize Input", 
                                command=self.validate_input,
                                bg="#06b6d4", fg="white", font=("Arial", 12, "bold"),
                                relief=tk.FLAT, cursor="hand2", padx=30, pady=15,
                                borderwidth=0, activebackground="#0891b2")
        validate_btn.pack(fill=tk.X, pady=(0, 25))
        
        self.val_result_frame = tk.Frame(content, bg="#1e2139")
        self.val_result_frame.pack(fill=tk.BOTH, expand=True)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def select_validation_type(self, val_type):
        self.validation_type.set(val_type)
        
        for vtype, btn in self.type_buttons.items():
            if vtype == val_type:
                btn.configure(bg="#06b6d4", fg="white")
            else:
                btn.configure(bg="#2d3250", fg="#94a3b8")
    
    def validate_input(self):
        for widget in self.val_result_frame.winfo_children():
            widget.destroy()
        
        input_value = self.input_text.get("1.0", tk.END).strip()
        val_type = self.validation_type.get()
        
        if not input_value:
            return
        
        # Get validation result
        validator = InputValidator()
        if val_type == "email":
            result = validator.validate_email(input_value)
        elif val_type == "url":
            result = validator.validate_url(input_value)
        elif val_type == "phone":
            result = validator.validate_phone(input_value)
        elif val_type == "alphanumeric":
            result = validator.validate_alphanumeric(input_value)
        elif val_type == "text":
            result = validator.validate_text(input_value)
        elif val_type == "sql":
            result = validator.validate_sql(input_value)
        else:
            result = {"isValid": False, "sanitized": "", "errors": ["Unknown type"], "warnings": []}
        
        # Validation Status Box
        if result["isValid"]:
            status_bg = "#064e3b"
            status_border = "#10b981"
            status_icon = "✓"
            status_text = "Valid Input"
            status_color = "#10b981"
        else:
            status_bg = "#7f1d1d"
            status_border = "#ef4444"
            status_icon = "✗"
            status_text = "Invalid Input"
            status_color = "#ef4444"
        
        status_frame = tk.Frame(self.val_result_frame, bg=status_border)
        status_frame.pack(fill=tk.X, padx=5, pady=(0, 15))
        
        status_inner = tk.Frame(status_frame, bg=status_bg)
        status_inner.pack(fill=tk.X, padx=2, pady=2)
        
        status_content = tk.Frame(status_inner, bg=status_bg)
        status_content.pack(padx=20, pady=15)
        
        tk.Label(status_content, text=f"{status_icon}  {status_text}", 
                font=("Arial", 14, "bold"), bg=status_bg, fg=status_color).pack()
        
        # Errors
        if result["errors"]:
            error_frame = tk.Frame(self.val_result_frame, bg="#7f1d1d")
            error_frame.pack(fill=tk.X, padx=5, pady=(0, 15))
            
            error_inner = tk.Frame(error_frame, bg="#7f1d1d")
            error_inner.pack(fill=tk.X, padx=2, pady=2)
            
            error_content = tk.Frame(error_inner, bg="#7f1d1d")
            error_content.pack(fill=tk.X, padx=20, pady=15)
            
            header_frame = tk.Frame(error_content, bg="#7f1d1d")
            header_frame.pack(anchor=tk.W, pady=(0, 10))
            
            tk.Label(header_frame, text="✗", font=("Arial", 14), 
                    bg="#7f1d1d", fg="#ef4444").pack(side=tk.LEFT, padx=(0, 10))
            tk.Label(header_frame, text="Validation Errors", font=("Arial", 12, "bold"), 
                    bg="#7f1d1d", fg="#ef4444").pack(anchor=tk.W)