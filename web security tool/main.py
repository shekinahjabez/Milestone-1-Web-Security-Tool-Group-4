import tkinter as tk
from tkinter import ttk, messagebox
import re
import random
import string
import hashlib

class ModernButton(tk.Canvas):
    def __init__(self, parent, text, command, bg_color, fg_color="white", **kwargs):
        super().__init__(parent, highlightthickness=0, **kwargs)
        self.command = command
        self.bg_color = bg_color
        self.fg_color = fg_color
        self.text = text
        self.is_selected = False
        
        self.configure(bg=bg_color, height=45)
        self.bind("<Button-1>", lambda e: self.on_click())
        self.bind("<Enter>", lambda e: self.on_hover())
        self.bind("<Leave>", lambda e: self.on_leave())
        
        self.draw()
    
    def draw(self):
        self.delete("all")
        width = self.winfo_width() if self.winfo_width() > 1 else 200
        height = 45
        
        # Draw rounded rectangle
        radius = 8
        self.create_oval(0, 0, radius*2, radius*2, fill=self.bg_color, outline="")
        self.create_oval(width-radius*2, 0, width, radius*2, fill=self.bg_color, outline="")
        self.create_oval(0, height-radius*2, radius*2, height, fill=self.bg_color, outline="")
        self.create_oval(width-radius*2, height-radius*2, width, height, fill=self.bg_color, outline="")
        self.create_rectangle(radius, 0, width-radius, height, fill=self.bg_color, outline="")
        self.create_rectangle(0, radius, width, height-radius, fill=self.bg_color, outline="")
        
        # Draw text
        self.create_text(width//2, height//2, text=self.text, fill=self.fg_color, 
                        font=("Arial", 11, "bold"))
    
    def on_click(self):
        if self.command:
            self.command()
    
    def on_hover(self):
        if not self.is_selected:
            self.configure(bg=self.adjust_color(self.bg_color, 1.1))
    
    def on_leave(self):
        if not self.is_selected:
            self.configure(bg=self.bg_color)
    
    def adjust_color(self, color, factor):
        # Simple color adjustment
        return color

class WebSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Security Tool")
        self.root.geometry("1000x750")
        self.root.configure(bg="#0a0e27")
        
        # Main container with gradient-like background
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
        
        # Shield icon (using text emoji)
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
        
        # Password Strength button
        self.strength_btn = tk.Button(button_container, text="🛡️  Password Strength",
                                      command=lambda: self.switch_tab("strength"),
                                      bg="#1e293b", fg="#94a3b8", font=("Arial", 11, "bold"),
                                      relief=tk.FLAT, cursor="hand2", padx=25, pady=12,
                                      activebackground="#334155", activeforeground="white")
        self.strength_btn.pack(side=tk.LEFT, padx=5)
        
        # Password Generator button
        self.generator_btn = tk.Button(button_container, text="🔑  Password Generator",
                                       command=lambda: self.switch_tab("generator"),
                                       bg="#1e293b", fg="#94a3b8", font=("Arial", 11, "bold"),
                                       relief=tk.FLAT, cursor="hand2", padx=25, pady=12,
                                       activebackground="#334155", activeforeground="white")
        self.generator_btn.pack(side=tk.LEFT, padx=5)
        
        # Input Validator button
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
        # Update button colors
        for name, btn in self.tab_buttons.items():
            if name == tab_name:
                btn.configure(bg="#06b6d4", fg="white")
            else:
                btn.configure(bg="#1e293b", fg="#94a3b8")
        
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Show selected tab
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
            bar_color = "#10b981"
        elif score >= 3:
            strength = "Medium"
            color = "#f59e0b"
            bar_color = "#f59e0b"
        else:
            strength = "Weak"
            color = "#ef4444"
            bar_color = "#ef4444"
        
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
        
        progress_fill = tk.Frame(progress_frame, bg=bar_color, height=12)
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
        content = tk.Frame(self.content_frame, bg="#1e2139")
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
        
        self.input_text = tk.Text(content, height=5, font=("Arial", 11), 
                                 bg="#2d3250", fg="white", insertbackground="white", 
                                 relief=tk.FLAT, wrap=tk.WORD, borderwidth=0,
                                 highlightthickness=0, padx=15, pady=12)
        self.input_text.pack(fill=tk.X, pady=(0, 25))
        
        # Validate button
        validate_btn = tk.Button(content, text="Validate Input", 
                                command=self.validate_input,
                                bg="#06b6d4", fg="white", font=("Arial", 12, "bold"),
                                relief=tk.FLAT, cursor="hand2", padx=30, pady=15,
                                borderwidth=0, activebackground="#0891b2")
        validate_btn.pack(fill=tk.X, pady=(0, 25))
        
        self.val_result_frame = tk.Frame(content, bg="#1e2139")
        self.val_result_frame.pack(fill=tk.BOTH, expand=True)
    
    def select_validation_type(self, val_type):
        self.validation_type.set(val_type)
        
        # Update button colors
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
        
        if val_type == "email":
            result = self.validate_email(input_value)
        elif val_type == "url":
            result = self.validate_url(input_value)
        elif val_type == "phone":
            result = self.validate_phone(input_value)
        elif val_type == "alphanumeric":
            result = self.validate_alphanumeric(input_value)
        elif val_type == "text":
            result = self.validate_text(input_value)
        elif val_type == "sql":
            result = self.validate_sql(input_value)
        else:
            result = {"isValid": False, "sanitized": "", "errors": ["Unknown type"], "warnings": []}
        
        # Display results
        if result["isValid"]:
            bg_color = "#064e3b"
            border_color = "#10b981"
            status_icon = "✓"
            status_text = "Valid Input"
            status_color = "#10b981"
        else:
            bg_color = "#7f1d1d"
            border_color = "#ef4444"
            status_icon = "✗"
            status_text = "Invalid Input"
            status_color = "#ef4444"
        
        result_frame = tk.Frame(self.val_result_frame, bg=border_color)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        inner_frame = tk.Frame(result_frame, bg=bg_color)
        inner_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        inner = tk.Frame(inner_frame, bg=bg_color)
        inner.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)
        
        status_frame = tk.Frame(inner, bg=bg_color)
        status_frame.pack(anchor=tk.W, pady=(0, 20))
        
        tk.Label(status_frame, text=status_icon, font=("Arial", 18, "bold"), 
                bg=bg_color, fg=status_color).pack(side=tk.LEFT, padx=(0, 10))
        tk.Label(status_frame, text=status_text, font=("Arial", 16, "bold"), 
                bg=bg_color, fg=status_color).pack(side=tk.LEFT)
        
        if result["errors"]:
            tk.Label(inner, text="Errors:", font=("Arial", 11, "bold"), 
                    bg=bg_color, fg="#fca5a5").pack(anchor=tk.W, pady=(5, 5))
            for error in result["errors"]:
                tk.Label(inner, text=f"• {error}", font=("Arial", 10), 
                        bg=bg_color, fg="#fca5a5").pack(anchor=tk.W, padx=(15, 0), pady=2)
        
        if result["warnings"]:
            tk.Label(inner, text="Warnings:", font=("Arial", 11, "bold"), 
                    bg=bg_color, fg="#fde047").pack(anchor=tk.W, pady=(10, 5))
            for warning in result["warnings"]:
                tk.Label(inner, text=f"• {warning}", font=("Arial", 10), 
                        bg=bg_color, fg="#fde047").pack(anchor=tk.W, padx=(15, 0), pady=2)
        
        tk.Label(inner, text="Sanitized Output:", font=("Arial", 11, "bold"), 
                bg=bg_color, fg="white").pack(anchor=tk.W, pady=(15, 8))
        
        sanitized_frame = tk.Frame(inner, bg="#1a1d2e")
        sanitized_frame.pack(fill=tk.X)
        
        tk.Label(sanitized_frame, text=result["sanitized"] or "(empty)", 
                font=("Courier", 10), bg="#1a1d2e", fg="#06b6d4", 
                wraplength=700, anchor=tk.W).pack(padx=15, pady=15)
    
    def validate_email(self, email):
        sanitized = email.strip()
        email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        
        if not re.match(email_regex, sanitized):
            return {"isValid": False, "sanitized": sanitized, 
                   "errors": ["Invalid email format"], "warnings": []}
        
        warnings = []
        xss_pattern = r'<script|javascript:|onerror=|onload='
        if re.search(xss_pattern, sanitized, re.IGNORECASE):
            warnings.append("⚠️ Potential XSS attempt detected")
        
        return {"isValid": True, "sanitized": sanitized, "errors": [], "warnings": warnings}
    
    def validate_url(self, url):
        sanitized = url.strip()
        url_regex = r'^https?://[^\s/$.?#].[^\s]*$'
        
        if not re.match(url_regex, sanitized, re.IGNORECASE):
            return {"isValid": False, "sanitized": sanitized, 
                   "errors": ["Invalid URL format"], "warnings": []}
        
        warnings = []
        xss_pattern = r'<script|javascript:|onerror=|onload='
        if re.search(xss_pattern, sanitized, re.IGNORECASE):
            warnings.append("⚠️ Potential XSS attempt detected")
        
        return {"isValid": True, "sanitized": sanitized, "errors": [], "warnings": warnings}
    
    def validate_phone(self, phone):
        sanitized = re.sub(r'\D', '', phone)
        
        if not re.match(r'^\d{10,15}$', sanitized):
            return {"isValid": False, "sanitized": sanitized, 
                   "errors": ["Invalid phone number (10-15 digits required)"], "warnings": []}
        
        return {"isValid": True, "sanitized": sanitized, "errors": [], "warnings": []}
    
    def validate_alphanumeric(self, text):
        sanitized = re.sub(r'[^a-zA-Z0-9]', '', text)
        warnings = []
        
        if sanitized != text.strip():
            warnings.append("Special characters removed")
        
        return {"isValid": True, "sanitized": sanitized, "errors": [], "warnings": warnings}
    
    def validate_text(self, text):
        sanitized = text.replace('\0', '').strip()
        warnings = []
        
        xss_pattern = r'<script|javascript:|onerror=|onload='
        if re.search(xss_pattern, sanitized, re.IGNORECASE):
            warnings.append("⚠️ Potential XSS attempt detected")
        
        return {"isValid": True, "sanitized": sanitized, "errors": [], "warnings": warnings}
    
    def validate_sql(self, text):
        sanitized = text.strip()
        warnings = []
        
        sql_pattern = r'\b(union|select|drop|delete|insert|update)\b'
        if re.search(sql_pattern, sanitized, re.IGNORECASE):
            warnings.append("⚠️ Potential SQL injection pattern detected")
        
        errors = ["SQL injection pattern detected"] if warnings else []
        
        return {"isValid": not warnings, "sanitized": sanitized, 
               "errors": errors, "warnings": warnings}
    
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebSecurityTool(root)
    root.mainloop()