# src/web_security_tool/gui/generate.py

import customtkinter as ctk
import json
from pathlib import Path
from tkinter import filedialog, messagebox

from openpyxl import Workbook
from openpyxl.styles import Font, Alignment

from ..password_generator import ProcessGenerator
from .components.section_title import SectionTitle


class GeneratorFrame(ctk.CTkFrame):
    def __init__(self, parent, colors: dict):
        super().__init__(parent, fg_color="transparent")
        self.COLORS = colors

        # UI state
        self.length = 16
        self.show_password = True
        self.password = ""
        self.sha256_hash = ""
        self.bcrypt_hash = ""
        self.password_history = []  # {timestamp, sha256Hash, bcryptHash}

        # Persistence
        self.history_path = Path("password_history.json")
        self._load_history()

        self._build()

    # -----------------------------
    # Persistence
    # -----------------------------
    def _load_history(self):
        if self.history_path.exists():
            try:
                data = json.loads(self.history_path.read_text(encoding="utf-8"))
                self.password_history = data if isinstance(data, list) else []
            except Exception:
                self.password_history = []

    def _save_history(self):
        try:
            self.history_path.write_text(
                json.dumps(self.password_history, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    # -----------------------------
    # UI Build
    # -----------------------------
    def _build(self):
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.pack(fill="both", expand=True, padx=10, pady=10)

        SectionTitle(
            self.scroll,
            title="Password Generator",
            subtitle="Create cryptographically secure passwords",
            colors=self.COLORS,
        ).pack(anchor="w", padx=40, pady=(20, 18))

        # Length card
        length_card = ctk.CTkFrame(
            self.scroll,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        length_card.pack(fill="x", padx=40, pady=(0, 12))

        row = ctk.CTkFrame(length_card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(18, 6))

        ctk.CTkLabel(
            row,
            text="Password Length",
            font=("Inter", 12, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(side="left")

        self.length_value = ctk.CTkLabel(
            row,
            text=str(self.length),
            font=("Inter", 18, "bold"),
            text_color=self.COLORS["success"],
        )
        self.length_value.pack(side="right")

        self.length_slider = ctk.CTkSlider(
            length_card,
            from_=8,
            to=16,
            number_of_steps=8,
            command=self._on_length_change,
        )
        self.length_slider.set(self.length)
        self.length_slider.pack(fill="x", padx=20, pady=(0, 10))

        # Generate button
        self.generate_btn = ctk.CTkButton(
            self.scroll,
            text="⟳  Generate Password",
            fg_color=self.COLORS["success"],
            hover_color="#059669",
            height=52,
            font=("Inter", 14, "bold"),
            text_color="white",
            command=self.generate_password,
        )
        self.generate_btn.pack(fill="x", padx=40, pady=(4, 12))

        self.output_area = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.output_area.pack(fill="x", padx=40, pady=(0, 12))

        self.history_area = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.history_area.pack(fill="x", padx=40, pady=(0, 30))

        self._render_output()
        self._render_history()

    # -----------------------------
    # UI Behaviors
    # -----------------------------
    def _on_length_change(self, value):
        self.length = int(value)
        self.length_value.configure(text=str(self.length))

    def _copy(self, text: str):
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)

    def _toggle_show_password(self):
        self.show_password = not self.show_password
        self._render_output()

    # -----------------------------
    # Main Action
    # -----------------------------
    def generate_password(self):
        pwd, sha256_hash, bcrypt_hash, ts = ProcessGenerator.generate(self.length)

        self.password = pwd
        self.sha256_hash = sha256_hash
        self.bcrypt_hash = bcrypt_hash

        self.password_history.append(
            {"timestamp": ts, "sha256Hash": sha256_hash, "bcryptHash": bcrypt_hash}
        )
        self._save_history()

        self._render_output()
        self._render_history()

    # -----------------------------
    # Render Output
    # -----------------------------
    def _render_output(self):
        for w in self.output_area.winfo_children():
            w.destroy()

        if not self.password:
            return

        pw_card = ctk.CTkFrame(
            self.output_area,
            fg_color="#064e3b",
            corner_radius=16,
            border_width=1,
            border_color="#34d399",
        )
        pw_card.pack(fill="x", pady=(0, 12))

        row = ctk.CTkFrame(pw_card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=18)

        show_char = "" if self.show_password else "*"
        pw_entry = ctk.CTkEntry(
            row,
            height=48,
            fg_color="white",
            text_color="#047857",
            font=("Consolas", 14, "bold"),
            show=show_char,
        )
        pw_entry.insert(0, self.password)
        pw_entry.configure(state="readonly")
        pw_entry.pack(side="left", fill="x", expand=True)

        ctk.CTkButton(
            row,
            text="Copy",
            width=90,
            command=lambda: self._copy(self.password),
        ).pack(side="right", padx=(10, 0))

        if self.password_history:
            ctk.CTkButton(
                self.output_area,
                text=f"⬇  Download History ({len(self.password_history)} entries)",
                height=48,
                command=self._download_history_excel,
            ).pack(fill="x")

    # -----------------------------
    # Render History (masked)
    # -----------------------------
    def _render_history(self):
        for w in self.history_area.winfo_children():
            w.destroy()

        if not self.password_history:
            return

        card = ctk.CTkFrame(self.history_area)
        card.pack(fill="x")

        last_five = self.password_history[-5:][::-1]
        for entry in last_five:
            ctk.CTkLabel(
                card,
                text=f"{entry.get('timestamp')}  •  •••••••••••• (hidden)",
                font=("Consolas", 11, "bold"),
            ).pack(anchor="w", padx=20, pady=6)

    # -----------------------------
    # Excel Export
    # -----------------------------
    def _download_history_excel(self):
        if not self.password_history:
            messagebox.showwarning("No history", "There is no password history to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx")],
            initialfile="password_history.xlsx",
        )
        if not path:
            return

        p = Path(path)
        if p.suffix.lower() != ".xlsx":
            p = p.with_suffix(".xlsx")

        try:
            wb = Workbook()
            ws = wb.active
            ws.title = "Password History"

            ws.append(["#", "Timestamp", "SHA-256 Hash", "Bcrypt Hash"])
            for idx, entry in enumerate(self.password_history, start=1):
                ws.append([
                    idx,
                    entry["timestamp"],
                    entry["sha256Hash"],
                    entry["bcryptHash"],
                ])

            wb.save(str(p))
            messagebox.showinfo("Export complete", f"Saved to:\n{p.resolve()}")

        except Exception as e:
            messagebox.showerror("Export failed", str(e))
