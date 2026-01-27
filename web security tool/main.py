import customtkinter as ctk
import random
import string
import hashlib
from password_assessor import Password_Assessor
import html
import re
from datetime import datetime

# 1. Import your custom logic
# from password_assessor import evaluate_password
from password_generator import process_generation
from input_validator import InputValidator

# --- Styling Constants ---
COLORS = {
    "bg_dark": "#0f172a",
    "bg_card": "#1e293b",
    "accent": "#06b6d4",
    "text_main": "#ffffff",
    "text_dim": "#94a3b8",
    "border": "#334155",
    "success": "#10b981",
    "warning": "#f59e0b",
    "danger": "#ef4444",
}

class WebSecurityTool(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Web Security Tool - MS1")
        self.geometry("1000x950")
        self.configure(fg_color=COLORS["bg_dark"])
        
        self.show_password = False
        self.setup_ui()

    def setup_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(pady=(30, 15))
        ctk.CTkLabel(header, text="🛡️ Web Security Tool", font=("Inter", 32, "bold"), text_color="white").pack()
        ctk.CTkLabel(header, text="MO-IT142 Security Script Programming", font=("Inter", 14), text_color="white").pack()
        
        self.nav_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12, border_width=1, border_color=COLORS["border"])
        self.nav_frame.pack(padx=50, fill="x", pady=10)
        
        self.tabs = {}
        for text, key in [("Strength Assessor", "strength"), ("Hash Generator", "generator"), ("Input Validator", "validator")]:
            btn = ctk.CTkButton(self.nav_frame, text=text, fg_color="transparent", text_color=COLORS["text_dim"], 
                               font=("Inter", 13, "bold"), hover_color=COLORS["border"],
                               command=lambda k=key: self.switch_tab(k))
            btn.pack(side="left", expand=True, padx=5, pady=8)
            self.tabs[key] = btn

        self.container = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=16, border_width=1, border_color=COLORS["border"])
        self.container.pack(padx=50, pady=20, fill="both", expand=True)
        self.switch_tab("strength")

    def switch_tab(self, key):
        # Update button colors
        for k, btn in self.tabs.items():
            btn.configure(
                fg_color=COLORS["accent"] if k == key else "transparent", 
                text_color="white" if k == key else COLORS["text_dim"]
            )
        
        # HIDE all existing frames instead of destroying them
        for widget in self.container.winfo_children(): 
            widget.pack_forget() 
        
        # Check if the frame for this tab already exists, if not, create it once
        if not hasattr(self, 'frames'):
            self.frames = {}

        if key not in self.frames:
            if key == "strength":
                self.frames[key] = self.create_strength_frame()
            elif key == "generator":
                self.frames[key] = self.create_generator_frame()
            elif key == "validator":
                self.frames[key] = self.create_validator_frame()
        
        # Show the frame
        self.frames[key].pack(fill="both", expand=True)

    def create_strength_frame(self):
        scroll_frame = ctk.CTkScrollableFrame(self.container, fg_color="transparent")
        scroll_frame.pack(padx=10, pady=10, fill="both", expand=True)

        ctk.CTkLabel(scroll_frame, text="Password Strength Assessor", font=("Inter", 24, "bold"), text_color="white").pack(anchor="w", padx=40, pady=(20, 0))
        
        input_container = ctk.CTkFrame(scroll_frame, fg_color=COLORS["bg_dark"], corner_radius=10, border_width=1, border_color=COLORS["border"])
        input_container.pack(fill="x", padx=40, pady=20)

        self.strength_entry = ctk.CTkEntry(input_container, placeholder_text="Type your password here...", 
                                         height=55, border_width=0, fg_color="transparent",     text_color="white",            
    placeholder_text_color="#AAAAAA",
    show="*")
        self.strength_entry.pack(side="left", fill="x", expand=True, padx=15)
        
        self.toggle_eye = ctk.CTkButton(input_container, text="👁️", width=45, height=45, fg_color="transparent",text_color="white",     
    hover_color=COLORS["bg_dark"], command=self.toggle_pwd_view)
        self.toggle_eye.pack(side="right", padx=5)

        ctk.CTkButton(scroll_frame, text="Check Password Strength", fg_color=COLORS["accent"], height=50, 
                     font=("Inter", 14, "bold"), command=self.handle_check_password).pack(fill="x", padx=40, pady=10)

        self.results_area = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        self.results_area.pack(fill="x", padx=40, pady=(10, 40))

        self.render_waiting_state()

        return scroll_frame

    def render_waiting_state(self):
        self.waiting_frame = ctk.CTkFrame(self.results_area, fg_color="transparent")
        self.waiting_frame.pack(pady=50)
        ctk.CTkLabel(self.waiting_frame, text="🔍", font=("Inter", 48)).pack()
        ctk.CTkLabel(self.waiting_frame, text="Enter a password above and click \"Check Password Strength\"\nto see its assessment", 
                    text_color=COLORS["text_dim"], justify="center").pack(pady=10)

    def handle_check_password(self):
        pwd = self.strength_entry.get()
        for widget in self.results_area.winfo_children(): 
            widget.destroy()

        if not pwd.strip():
            self.render_waiting_state()
            err_frame = ctk.CTkFrame(self.results_area, fg_color="#2d1f21", border_width=1, border_color=COLORS["danger"])
            err_frame.pack(fill="x", pady=10)
            ctk.CTkLabel(err_frame, text="⚠️ Please enter a password before checking.", text_color=COLORS["danger"]).pack(pady=10)
            return

        # Call External Logic
        rating, feedback = evaluate_password(pwd)

        # Mapping for UI
        if rating == "Weak": color, pct = COLORS["danger"], 0.25
        elif rating == "Moderate": color, pct = COLORS["warning"], 0.6
        else: color, pct = COLORS["success"], 1.0

        self.display_results(pwd, rating, feedback, color, pct)

    def display_results(self, pwd, rating, feedback, color, pct):
        # 1. Strength Bar Card
        card = ctk.CTkFrame(self.results_area, fg_color=COLORS["bg_card"], border_width=1, border_color=COLORS["border"])
        card.pack(fill="x", pady=5)
        
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(15, 5))
        ctk.CTkLabel(row, text="Security Rating:", text_color="white").pack(side="left")
        ctk.CTkLabel(row, text=rating, font=("Inter", 18, "bold"), text_color=color).pack(side="right")
        
        bar = ctk.CTkProgressBar(card, height=12, progress_color=color)
        bar.pack(fill="x", padx=20, pady=(0, 20))
        bar.set(pct)

        # 2. Security Criteria Checklist (The missing part)
        criteria_frame = ctk.CTkFrame(self.results_area, fg_color=COLORS["bg_card"], border_width=1, border_color=COLORS["border"])
        criteria_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(criteria_frame, text="Security Criteria Assessment", font=("Inter", 14, "bold"), text_color="white").pack(anchor="w", padx=20, pady=10)

        # We manually verify these for the UI checklist display
        checks = [
            (len(pwd) >= 12, "At least 12 characters"),
            (bool(re.search(r"[A-Z]", pwd)), "Contains uppercase letters"),
            (bool(re.search(r"[a-z]", pwd)), "Contains lowercase letters"),
            (bool(re.search(r"[0-9]", pwd)), "Contains numbers"),
            (bool(re.search(r"[!@#$%^&*()_+=\-[\]{};:'\",.<>?/\\|]", pwd)), "Contains special symbols"),
        ]

        for met, text in checks:
            icon = "✅" if met else "❌"
            t_color = COLORS["success"] if met else COLORS["danger"]
            ctk.CTkLabel(criteria_frame, text=f"{icon}  {text}", text_color=t_color).pack(anchor="w", padx=40, pady=2)

        # 3. Recommendations Card
        feedback_card = ctk.CTkFrame(self.results_area, fg_color=COLORS["bg_card"], border_width=1, border_color=COLORS["border"])
        feedback_card.pack(fill="x", pady=5)
        ctk.CTkLabel(feedback_card, text="Recommendations", font=("Inter", 14, "bold"), text_color="white").pack(anchor="w", padx=20, pady=10)
        ctk.CTkLabel(feedback_card, text=feedback, text_color="white", justify="left", wraplength=800).pack(anchor="w", padx=40, pady=(0, 20))

    def toggle_pwd_view(self):
        self.show_password = not self.show_password
        self.strength_entry.configure(show="" if self.show_password else "*")
        self.toggle_eye.configure(text="🔒" if self.show_password else "👁️")

    # (Other tabs like generator and validator remain unchanged)
    def create_generator_frame(self):
        # Create a parent frame for this tab
        parent_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        
        ctk.CTkLabel(parent_frame, text="Secure Password Generator", font=("Inter", 24, "bold"), text_color="white").pack(anchor="w", padx=40, pady=(20, 0))
        ctk.CTkLabel(parent_frame, text="Generate cryptographically secure passwords with SHA-256 hashing", 
                     text_color="white").pack(anchor="w", padx=40)
        
        # Slider Section
        slider_container = ctk.CTkFrame(parent_frame, fg_color=COLORS["bg_dark"], corner_radius=10)
        slider_container.pack(fill="x", padx=40, pady=20)
        
        self.len_label = ctk.CTkLabel(slider_container, text="Password Length: 16", font=("Inter", 13, "bold"), text_color="white")
        self.len_label.pack(pady=(10, 0))
        
        # CORRECTED SLIDER: from_ and to
        self.length_slider = ctk.CTkSlider(slider_container, from_=8, to=16, number_of_steps=8,
                                          command=lambda v: self.len_label.configure(text=f"Password Length: {int(v)}"))
        self.length_slider.set(16)
        self.length_slider.pack(fill="x", padx=20, pady=20)

        ctk.CTkButton(parent_frame, text="Generate Secure Password", fg_color=COLORS["accent"], height=50, 
                     font=("Inter", 14, "bold"), command=self.process_gen).pack(padx=40, fill="x")

        # Result area
        self.gen_res_area = ctk.CTkScrollableFrame(parent_frame, fg_color="transparent", height=400)
        self.gen_res_area.pack(fill="both", expand=True, padx=40, pady=20)
        
        return parent_frame # Crucial for the switch_tab logic

    def process_gen(self):
        try:
            # 1. Get value safely
            val = self.length_slider.get()
            length = int(val)
            
            # 2. Call your logic - now returns bcrypt hash too
            pwd, hsh, bcrypt_hash, ts = process_generation(length)
            
            # 3. ONLY clear the result area, NOT the slider
            for widget in self.gen_res_area.winfo_children():
                widget.destroy()
                
            # 4. Display results
            ctk.CTkLabel(self.gen_res_area, text=f"Generated at: {ts}", text_color="white").pack(anchor="w")
            
            p_box = ctk.CTkTextbox(self.gen_res_area, height=70, fg_color=COLORS["bg_dark"], text_color="#ffffff")
            p_box.pack(fill="x", pady=5)
            p_box.insert("1.0", f"PASSWORD: {pwd}")
            
            h_box = ctk.CTkTextbox(self.gen_res_area, height=70, fg_color=COLORS["bg_dark"], text_color="#4ade80")
            h_box.pack(fill="x", pady=5)
            h_box.insert("1.0", f"SHA-256 HASH: {hsh}")
            
            # Add bcrypt hash display
            bcrypt_box = ctk.CTkTextbox(self.gen_res_area, height=90, fg_color=COLORS["bg_dark"], text_color="#f59e0b")
            bcrypt_box.pack(fill="x", pady=5)
            bcrypt_box.insert("1.0", f"BCRYPT HASH: {bcrypt_hash}")

        except Exception as e:
            print(f"UI Update Error: {e}")

    def create_validator_frame(self):
        scroll_frame = ctk.CTkScrollableFrame(self.container, fg_color="transparent")
        scroll_frame.pack(padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(scroll_frame, text="Web Form Input Validator", font=("Inter", 24, "bold"), text_color="white").pack(anchor="w", padx=40, pady=(10,20))
        self.val_inputs = {}
        for field in ["Full Name", "Email Address", "Username", "Message"]:
            ctk.CTkLabel(scroll_frame, text=field, text_color="white").pack(anchor="w", padx=40)
            e = ctk.CTkEntry(scroll_frame, height=45, fg_color=COLORS["bg_dark"], border_color=COLORS["border"], text_color="white")
            e.pack(fill="x", padx=40, pady=(5, 15))
            self.val_inputs[field] = e
        ctk.CTkButton(scroll_frame, text="Validate & Sanitize", fg_color=COLORS["accent"], height=45, command=self.do_val).pack(fill="x", padx=40, pady=10)
        self.val_res = ctk.CTkTextbox(scroll_frame, height=200, fg_color=COLORS["bg_dark"], border_color=COLORS["border"], text_color="white")
        self.val_res.pack(fill="x", padx=40, pady=20)

        return scroll_frame

    def do_val(self):
        # Get form data
        full_name = self.val_inputs["Full Name"].get().strip()
        email = self.val_inputs["Email Address"].get().strip()
        username = self.val_inputs["Username"].get().strip()
        message = self.val_inputs["Message"].get().strip()
        
        # Check if all fields are provided
        if not all([full_name, email, username, message]):
            self.val_res.delete("1.0", "end")
            self.val_res.insert("end", "⚠️ Error: All fields are required!")
            return
        
        # Sanitize inputs first using InputValidator
        sanitized_name, name_sanitized, name_notes = InputValidator.sanitize_input(full_name, 'name')
        sanitized_email, email_sanitized, email_notes = InputValidator.sanitize_input(email, 'email')
        sanitized_username, username_sanitized, username_notes = InputValidator.sanitize_input(username, 'username')
        sanitized_message, message_sanitized, message_notes = InputValidator.sanitize_input(message, 'message')
        
        # Validate sanitized inputs using InputValidator
        name_valid, name_errors = InputValidator.validate_full_name(sanitized_name)
        email_valid, email_errors = InputValidator.validate_email_simple(sanitized_email)
        username_valid, username_errors = InputValidator.validate_username(sanitized_username)
        message_valid, message_errors = InputValidator.validate_message(sanitized_message)
        
        # Build results output
        output = "=" * 60 + "\n"
        output += "VALIDATION RESULTS\n"
        output += "=" * 60 + "\n\n"
        
        # Full Name results
        output += f"Full Name: {'✓ Valid' if name_valid else '✗ Invalid'}\n"
        if not name_valid:
            for error in name_errors:
                output += f"  - {error}\n"
        if name_sanitized:
            output += f"  - Sanitized: {', '.join(name_notes)}\n"
        output += "\n"
        
        # Email results
        output += f"Email: {'✓ Valid' if email_valid else '✗ Invalid'}\n"
        if not email_valid:
            for error in email_errors:
                output += f"  - {error}\n"
        if email_sanitized:
            output += f"  - Sanitized: {', '.join(email_notes)}\n"
        output += "\n"
        
        # Username results
        output += f"Username: {'✓ Valid' if username_valid else '✗ Invalid'}\n"
        if not username_valid:
            for error in username_errors:
                output += f"  - {error}\n"
        if username_sanitized:
            output += f"  - Sanitized: {', '.join(username_notes)}\n"
        output += "\n"
        
        # Message results
        output += f"Message: {'✓ Valid' if message_valid else '✗ Invalid'}\n"
        if not message_valid:
            for error in message_errors:
                output += f"  - {error}\n"
        if message_sanitized:
            output += f"  - Sanitized: {', '.join(message_notes)}\n"
        output += "\n"
        
        # Sanitized output section
        output += "=" * 60 + "\n"
        output += "SANITIZED OUTPUT\n"
        output += "=" * 60 + "\n\n"
        output += f"Full Name: {sanitized_name if name_valid else '[INVALID - Cannot display]'}\n"
        output += f"Email: {sanitized_email if email_valid else '[INVALID - Cannot display]'}\n"
        output += f"Username: {sanitized_username if username_valid else '[INVALID - Cannot display]'}\n"
        output += f"Message: {sanitized_message[:100] if message_valid else '[INVALID - Cannot display]'}{'...' if message_valid and len(sanitized_message) > 100 else ''}\n\n"
        
        # Summary
        all_valid = name_valid and email_valid and username_valid and message_valid
        any_sanitized = name_sanitized or email_sanitized or username_sanitized or message_sanitized
        
        output += "=" * 60 + "\n"
        output += "SUMMARY\n"
        output += "=" * 60 + "\n"
        if all_valid and not any_sanitized:
            output += "✓ All fields are valid. No sanitization needed.\n"
        elif all_valid and any_sanitized:
            output += "✓ All fields are valid after sanitization.\n"
        else:
            output += "✗ Some fields contain errors. Please correct them.\n"
        
        output += "\nProcess Complete.\n"
        
        # Display results
        self.val_res.delete("1.0", "end")
        self.val_res.insert("end", output)

if __name__ == "__main__":
    app = WebSecurityTool()
    app.mainloop()