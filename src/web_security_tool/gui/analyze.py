# src/web_security_tool/gui/analyze.py
import customtkinter as ctk
import re

from ..password_assessor import PasswordAssessor
from .components.section_title import SectionTitle

__all__ = ["StrengthFrame"]


class StrengthFrame(ctk.CTkScrollableFrame):
    def __init__(self, parent, colors: dict):
        super().__init__(parent, fg_color="transparent")
        self.COLORS = colors
        self.show_password = False

        # Header (refactored)
        SectionTitle(
            self,
            title="Password Strength Analyzer",
            subtitle="Evaluate the security level of your password",
            colors=self.COLORS,
        ).pack(anchor="w", padx=40, pady=(20, 18))

        # Input label
        ctk.CTkLabel(
            self,
            text="Enter Password",
            font=("Inter", 12, "bold"),
            text_color=self.COLORS.get("text_mid", self.COLORS["text_main"]),
        ).pack(anchor="w", padx=40, pady=(0, 8))

        input_container = ctk.CTkFrame(
            self,
            fg_color=self.COLORS["bg_card"],
            corner_radius=14,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        input_container.pack(fill="x", padx=40, pady=(0, 18))

        self.strength_entry = ctk.CTkEntry(
            input_container,
            placeholder_text="Type your password here...",
            height=52,
            fg_color=self.COLORS["bg_dark"],
            border_width=1,
            border_color=self.COLORS["border"],
            text_color=self.COLORS["text_main"],
            placeholder_text_color=self.COLORS["text_dim"],
            show="*",
        )
        self.strength_entry.pack(side="left", fill="x", expand=True, padx=(14, 8), pady=12)
        self.strength_entry.bind("<Return>", lambda e: self.handle_check_password())

        # Eye toggle (emoji centered using label+place)
        self.toggle_eye = ctk.CTkButton(
            input_container,
            text="",
            width=44,
            height=44,
            fg_color=self.COLORS["bg_dark"],
            hover_color="#e2e8f0",
            border_width=1,
            border_color=self.COLORS["border"],
            command=self.toggle_pwd_view,
        )
        self.toggle_eye.pack(side="right", padx=(0, 14), pady=12)
        self.toggle_eye.pack_propagate(False)

        self.eye_lbl = ctk.CTkLabel(
            self.toggle_eye,
            text="👁️",
            font=("Inter", 16, "bold"),
            text_color=self.COLORS["text_dim"],
        )
        self.eye_lbl.place(relx=0.5, rely=0.5, anchor="center")
        self.eye_lbl.bind("<Button-1>", lambda e: self.toggle_pwd_view())

        ctk.CTkButton(
            self,
            text="Check Password Strength",
            fg_color=self.COLORS["accent"],
            hover_color="#1d4ed8",
            text_color="white",
            height=52,
            font=("Inter", 14, "bold"),
            command=self.handle_check_password,
        ).pack(fill="x", padx=40, pady=(0, 10))

        self.results_area = ctk.CTkFrame(self, fg_color="transparent")
        self.results_area.pack(fill="x", padx=40, pady=(10, 40))

        self.render_waiting_state()

    def render_waiting_state(self):
        for widget in self.results_area.winfo_children():
            widget.destroy()

        waiting_frame = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        waiting_frame.pack(fill="x", pady=10)

        inner = ctk.CTkFrame(waiting_frame, fg_color="transparent")
        inner.pack(padx=20, pady=24)

        ctk.CTkLabel(inner, text="🔍", font=("Inter", 42)).pack()
        ctk.CTkLabel(
            inner,
            text='Enter a password above and click "Check Password Strength"\n'
                 "to see its assessment.",
            text_color=self.COLORS["text_dim"],
            font=("Inter", 13),
            justify="center",
        ).pack(pady=(10, 0))

    def toggle_pwd_view(self):
        self.show_password = not self.show_password
        self.strength_entry.configure(show="" if self.show_password else "*")
        if self.show_password:
            self.eye_lbl.configure(text="🔒", text_color=self.COLORS["text_main"])
        else:
            self.eye_lbl.configure(text="👁️", text_color=self.COLORS["text_dim"])

    def handle_check_password(self):
        pwd = self.strength_entry.get()

        for widget in self.results_area.winfo_children():
            widget.destroy()

        if not pwd.strip():
            self.render_waiting_state()
            err_frame = ctk.CTkFrame(
                self.results_area,
                fg_color="#fef2f2",
                corner_radius=14,
                border_width=1,
                border_color=self.COLORS["danger"],
            )
            err_frame.pack(fill="x", pady=10)
            ctk.CTkLabel(
                err_frame,
                text="⚠️ Please enter a password before checking.",
                text_color=self.COLORS["danger"],
                font=("Inter", 12, "bold"),
            ).pack(pady=12)
            return

        rating, feedback = PasswordAssessor.evaluate_password(pwd)

        if rating == "Weak":
            color, pct = self.COLORS["danger"], 0.25
        elif rating == "Moderate":
            color, pct = self.COLORS["warning"], 0.6
        else:
            color, pct = self.COLORS["success"], 1.0

        self.display_results(pwd, rating, feedback, color, pct)

    def display_results(self, pwd, rating, feedback, color, pct):
        card = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        card.pack(fill="x", pady=8)

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(16, 8))

        ctk.CTkLabel(
            row,
            text="Strength Level",
            text_color=self.COLORS["text_dim"],
            font=("Inter", 11, "bold"),
        ).pack(side="left")

        ctk.CTkLabel(
            row,
            text=rating,
            font=("Inter", 18, "bold"),
            text_color=color,
        ).pack(side="right")

        bar = ctk.CTkProgressBar(card, height=12, progress_color=color)
        bar.pack(fill="x", padx=20, pady=(0, 6))
        bar.set(pct)

        ctk.CTkLabel(
            card,
            text=f"Security Score: {int(pct * 8)}/8",
            text_color=self.COLORS["text_dim"],
            font=("Inter", 11, "bold"),
        ).pack(pady=(0, 16))

        criteria_frame = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        criteria_frame.pack(fill="x", pady=8)

        ctk.CTkLabel(
            criteria_frame,
            text="Security Checks",
            font=("Inter", 12, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(anchor="w", padx=20, pady=(16, 10))

        checks = [
            (len(pwd) >= 12, "At least 12 characters"),
            (bool(re.search(r"[A-Z]", pwd)), "Uppercase (A-Z)"),
            (bool(re.search(r"[a-z]", pwd)), "Lowercase (a-z)"),
            (bool(re.search(r"[0-9]", pwd)), "Numbers (0-9)"),
            (bool(re.search(r"[!@#$%^&*()_+=\-[\]{};:'\",.<>?/\\|]", pwd)), "Symbols (!@#)"),
        ]

        for met, text in checks:
            bg = "#ecfdf5" if met else "#fef2f2"
            bd = "#a7f3d0" if met else "#fecaca"
            tc = self.COLORS["success"] if met else self.COLORS["danger"]
            icon = "✅" if met else "❌"

            item = ctk.CTkFrame(
                criteria_frame,
                fg_color=bg,
                corner_radius=12,
                border_width=1,
                border_color=bd,
            )
            item.pack(fill="x", padx=20, pady=6)

            ctk.CTkLabel(
                item,
                text=f"{icon}  {text}",
                text_color=tc,
                font=("Inter", 12, "bold"),
            ).pack(anchor="w", padx=14, pady=10)

        feedback_card = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        feedback_card.pack(fill="x", pady=8)

        ctk.CTkLabel(
            feedback_card,
            text="Recommendations",
            font=("Inter", 12, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(anchor="w", padx=20, pady=(16, 10))

        ctk.CTkLabel(
            feedback_card,
            text=feedback,
            text_color=self.COLORS.get("text_mid", self.COLORS["text_main"]),
            font=("Inter", 13),
            justify="left",
            wraplength=820,
        ).pack(anchor="w", padx=20, pady=(0, 16))
