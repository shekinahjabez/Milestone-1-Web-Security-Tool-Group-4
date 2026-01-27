import customtkinter as ctk
import re

from ..password_assessor import PasswordAssessor


class StrengthFrame(ctk.CTkScrollableFrame):
    def __init__(self, parent, colors: dict):
        super().__init__(parent, fg_color="transparent")
        self.COLORS = colors
        self.show_password = False

        ctk.CTkLabel(
            self,
            text="Password Strength Assessor",
            font=("Inter", 24, "bold"),
            text_color="white",
        ).pack(anchor="w", padx=40, pady=(20, 0))

        input_container = ctk.CTkFrame(
            self,
            fg_color=self.COLORS["bg_dark"],
            corner_radius=10,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        input_container.pack(fill="x", padx=40, pady=20)

        self.strength_entry = ctk.CTkEntry(
            input_container,
            placeholder_text="Type your password here...",
            height=55,
            border_width=0,
            fg_color="transparent",
            text_color="white",
            placeholder_text_color="#AAAAAA",
            show="*",
        )
        self.strength_entry.pack(side="left", fill="x", expand=True, padx=15)
        self.strength_entry.bind("<Return>", lambda e: self.handle_check_password())

        self.toggle_eye = ctk.CTkButton(
            input_container,
            text="👁️",
            width=45,
            height=45,
            fg_color="transparent",
            text_color="white",
            hover_color=self.COLORS["bg_dark"],
            command=self.toggle_pwd_view,
        )
        self.toggle_eye.pack(side="right", padx=5)

        ctk.CTkButton(
            self,
            text="Check Password Strength",
            fg_color=self.COLORS["accent"],
            height=50,
            font=("Inter", 14, "bold"),
            command=self.handle_check_password,
        ).pack(fill="x", padx=40, pady=10)

        self.results_area = ctk.CTkFrame(self, fg_color="transparent")
        self.results_area.pack(fill="x", padx=40, pady=(10, 40))

        self.render_waiting_state()

    def render_waiting_state(self):
        for widget in self.results_area.winfo_children():
            widget.destroy()

        waiting_frame = ctk.CTkFrame(self.results_area, fg_color="transparent")
        waiting_frame.pack(pady=50)

        ctk.CTkLabel(waiting_frame, text="🔍", font=("Inter", 48)).pack()
        ctk.CTkLabel(
            waiting_frame,
            text='Enter a password above and click "Check Password Strength"\n'
                 'to see its assessment',
            text_color=self.COLORS["text_dim"],
            justify="center",
        ).pack(pady=10)

    def toggle_pwd_view(self):
        self.show_password = not self.show_password
        self.strength_entry.configure(show="" if self.show_password else "*")
        self.toggle_eye.configure(text="🔒" if self.show_password else "👁️")

    def handle_check_password(self):
        pwd = self.strength_entry.get()

        for widget in self.results_area.winfo_children():
            widget.destroy()

        if not pwd.strip():
            self.render_waiting_state()
            err_frame = ctk.CTkFrame(
                self.results_area,
                fg_color="#2d1f21",
                border_width=1,
                border_color=self.COLORS["danger"],
            )
            err_frame.pack(fill="x", pady=10)
            ctk.CTkLabel(
                err_frame,
                text="⚠️ Please enter a password before checking.",
                text_color=self.COLORS["danger"],
            ).pack(pady=10)
            return

        # ✅ NO LOGIC CHANGE: still using your PasswordAssessor
        rating, feedback = PasswordAssessor.evaluate_password(pwd)

        # UI mapping only
        if rating == "Weak":
            color, pct = self.COLORS["danger"], 0.25
        elif rating == "Moderate":
            color, pct = self.COLORS["warning"], 0.6
        else:
            color, pct = self.COLORS["success"], 1.0

        self.display_results(pwd, rating, feedback, color, pct)

    def display_results(self, pwd, rating, feedback, color, pct):
        # 1) Strength Bar Card
        card = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            border_width=1,
            border_color=self.COLORS["border"],
        )
        card.pack(fill="x", pady=5)

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(15, 5))
        ctk.CTkLabel(row, text="Security Rating:", text_color="white").pack(side="left")
        ctk.CTkLabel(row, text=rating, font=("Inter", 18, "bold"), text_color=color).pack(side="right")

        bar = ctk.CTkProgressBar(card, height=12, progress_color=color)
        bar.pack(fill="x", padx=20, pady=(0, 20))
        bar.set(pct)

        # 2) Checklist (UI-only checks)
        criteria_frame = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            border_width=1,
            border_color=self.COLORS["border"],
        )
        criteria_frame.pack(fill="x", pady=5)

        ctk.CTkLabel(
            criteria_frame,
            text="Security Criteria Assessment",
            font=("Inter", 14, "bold"),
            text_color="white",
        ).pack(anchor="w", padx=20, pady=10)

        checks = [
            (len(pwd) >= 12, "At least 12 characters"),
            (bool(re.search(r"[A-Z]", pwd)), "Contains uppercase letters"),
            (bool(re.search(r"[a-z]", pwd)), "Contains lowercase letters"),
            (bool(re.search(r"[0-9]", pwd)), "Contains numbers"),
            (bool(re.search(r"[!@#$%^&*()_+=\-[\]{};:'\",.<>?/\\|]", pwd)),
             "Contains special symbols"),
        ]

        for met, text in checks:
            icon = "✅" if met else "❌"
            t_color = self.COLORS["success"] if met else self.COLORS["danger"]
            ctk.CTkLabel(
                criteria_frame,
                text=f"{icon}  {text}",
                text_color=t_color
            ).pack(anchor="w", padx=40, pady=2)

        # 3) Recommendations
        feedback_card = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            border_width=1,
            border_color=self.COLORS["border"],
        )
        feedback_card.pack(fill="x", pady=5)

        ctk.CTkLabel(
            feedback_card,
            text="Recommendations",
            font=("Inter", 14, "bold"),
            text_color="white",
        ).pack(anchor="w", padx=20, pady=10)

        ctk.CTkLabel(
            feedback_card,
            text=feedback,
            text_color="white",
            justify="left",
            wraplength=800,
        ).pack(anchor="w", padx=40, pady=(0, 20))
        print("Loaded analyze.py; StrengthFrame =", "StrengthFrame" in globals())
        __all__ = ["StrengthFrame"]


