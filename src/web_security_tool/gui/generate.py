import customtkinter as ctk
from tkinter import filedialog
import json
from pathlib import Path

from ..password_generator import process_generation


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
        self.password_history = []  # list of dicts: {timestamp, password, sha256Hash, bcryptHash}

        # Persistence (optional, replaces localStorage)
        self.history_path = Path("password_history.json")
        self._load_history()

        # Build UI
        self._build()

    # -----------------------------
    # Persistence (UI feature only)
    # -----------------------------
    def _load_history(self):
        if self.history_path.exists():
            try:
                self.password_history = json.loads(self.history_path.read_text(encoding="utf-8"))
                if not isinstance(self.password_history, list):
                    self.password_history = []
            except Exception:
                self.password_history = []

    def _save_history(self):
        try:
            self.history_path.write_text(json.dumps(self.password_history, indent=2), encoding="utf-8")
        except Exception:
            # If saving fails, ignore—UI feature only.
            pass

    # -----------------------------
    # UI Build
    # -----------------------------
    def _build(self):
        # Scrollable layout for long history
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        ctk.CTkLabel(
            self.scroll,
            text="Password Generator",
            font=("Inter", 24, "bold"),
            text_color="white",
        ).pack(anchor="w", padx=40, pady=(20, 0))

        ctk.CTkLabel(
            self.scroll,
            text="Create cryptographically secure passwords",
            font=("Inter", 14),
            text_color=self.COLORS["text_dim"],
        ).pack(anchor="w", padx=40, pady=(2, 18))

        # Length section
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
            text_color="white",
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

        range_row = ctk.CTkFrame(length_card, fg_color="transparent")
        range_row.pack(fill="x", padx=20, pady=(0, 18))
        ctk.CTkLabel(range_row, text="8 characters", text_color=self.COLORS["text_dim"], font=("Inter", 11)).pack(side="left")
        ctk.CTkLabel(range_row, text="16 characters", text_color=self.COLORS["text_dim"], font=("Inter", 11)).pack(side="right")

        # Character types card 
        types_card = ctk.CTkFrame(
            self.scroll,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        types_card.pack(fill="x", padx=40, pady=(0, 12))

        top = ctk.CTkFrame(types_card, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(18, 10))

        ctk.CTkLabel(
            top,
            text="Character Types",
            font=("Inter", 12, "bold"),
            text_color="white",
        ).pack(side="left")

        ctk.CTkLabel(
            top,
            text="● All required",
            font=("Inter", 11, "bold"),
            text_color=self.COLORS["success"],
        ).pack(side="right")

        grid = ctk.CTkFrame(types_card, fg_color="transparent")
        grid.pack(fill="x", padx=20, pady=(0, 18))

        # Disabled checkboxes
        self._type_tile(grid, "A-Z", "Uppercase", 0, 0)
        self._type_tile(grid, "a-z", "Lowercase", 0, 1)
        self._type_tile(grid, "0-9", "Numbers", 1, 0)
        self._type_tile(grid, "!@#", "Symbols", 1, 1)

        grid.grid_columnconfigure(0, weight=1)
        grid.grid_columnconfigure(1, weight=1)

        # Generate button
        self.generate_btn = ctk.CTkButton(
            self.scroll,
            text="⟳  Generate Password",
            fg_color=self.COLORS["success"],
            hover_color="#059669",  # slightly darker emerald
            height=52,
            font=("Inter", 14, "bold"),
            command=self.generate_password,
        )
        self.generate_btn.pack(fill="x", padx=40, pady=(4, 12))

        # Output area
        self.output_area = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.output_area.pack(fill="x", padx=40, pady=(0, 12))

        # History area
        self.history_area = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.history_area.pack(fill="x", padx=40, pady=(0, 30))

        # Initial render
        self._render_output()
        self._render_history()

    def _type_tile(self, parent, label: str, desc: str, r: int, c: int):
        tile = ctk.CTkFrame(
            parent,
            fg_color=self.COLORS["bg_dark"],
            corner_radius=12,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        tile.grid(row=r, column=c, sticky="ew", padx=6, pady=6)

        # "checkbox" look (disabled)
        chk = ctk.CTkLabel(tile, text="☑", text_color=self.COLORS["success"], font=("Inter", 16, "bold"))
        chk.pack(side="left", padx=(12, 10), pady=14)

        txt = ctk.CTkFrame(tile, fg_color="transparent")
        txt.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(txt, text=label, text_color="white", font=("Inter", 13, "bold")).pack(anchor="w")
        ctk.CTkLabel(txt, text=desc, text_color=self.COLORS["text_dim"], font=("Inter", 11)).pack(anchor="w")

    # -----------------------------
    # UI behaviors
    # -----------------------------
    def _on_length_change(self, value):
        self.length = int(value)
        self.length_value.configure(text=str(self.length))

    def _copy(self, text: str):
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    def _toggle_show_password(self):
        self.show_password = not self.show_password
        self._render_output()

    # -----------------------------
    # Main action (logic call)
    # -----------------------------
    def generate_password(self):
        # ✅ Logic unchanged: call your existing generator
        pwd, sha256_hash, bcrypt_hash, ts = process_generation(self.length)

        self.password = pwd
        self.sha256_hash = sha256_hash
        self.bcrypt_hash = bcrypt_hash

        entry = {
            "timestamp": ts,
            "password": pwd,
            "sha256Hash": sha256_hash,
            "bcryptHash": bcrypt_hash,
        }
        self.password_history.append(entry)
        self._save_history()

        self._render_output()
        self._render_history()

    # -----------------------------
    # Render output / history
    # -----------------------------
    def _render_output(self):
        for w in self.output_area.winfo_children():
            w.destroy()

        if not self.password:
            return

        # Password display card
        pw_card = ctk.CTkFrame(
            self.output_area,
            fg_color="#064e3b",  # deep emerald tone
            corner_radius=16,
            border_width=1,
            border_color="#34d399",
        )
        pw_card.pack(fill="x", pady=(0, 12))

        top = ctk.CTkFrame(pw_card, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(16, 10))

        ctk.CTkLabel(
            top,
            text="YOUR PASSWORD",
            font=("Inter", 11, "bold"),
            text_color="white",
        ).pack(side="left")

        eye_text = "🙈" if self.show_password else "👁️"
        ctk.CTkButton(
            top,
            text=eye_text,
            width=44,
            height=32,
            fg_color="transparent",
            hover_color=self.COLORS["bg_dark"],
            command=self._toggle_show_password,
        ).pack(side="right")

        row = ctk.CTkFrame(pw_card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 18))

        show_char = "" if self.show_password else "*"
        pw_entry = ctk.CTkEntry(
            row,
            height=48,
            fg_color="white",
            text_color="#047857",
            border_width=1,
            border_color="#34d399",
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
            fg_color=self.COLORS["bg_dark"],
            hover_color=self.COLORS["border"],
            command=lambda: self._copy(self.password),
        ).pack(side="right", padx=(10, 0))

        # Hash cards (2 columns)
        hash_grid = ctk.CTkFrame(self.output_area, fg_color="transparent")
        hash_grid.pack(fill="x", pady=(0, 12))
        hash_grid.grid_columnconfigure(0, weight=1)
        hash_grid.grid_columnconfigure(1, weight=1)

        self._hash_card(
            hash_grid,
            col=0,
            title="SHA-256 Hash",
            value=self.sha256_hash,
            accent="#2563eb",
        )
        self._hash_card(
            hash_grid,
            col=1,
            title="Bcrypt Hash",
            value=self.bcrypt_hash,
            accent="#4f46e5",
        )

        # Download button (only if history exists)
        if self.password_history:
            ctk.CTkButton(
                self.output_area,
                text=f"⬇  Download History ({len(self.password_history)} passwords)",
                fg_color=self.COLORS["bg_dark"],
                hover_color=self.COLORS["border"],
                border_width=1,
                border_color=self.COLORS["border"],
                height=48,
                font=("Inter", 13, "bold"),
                command=self._download_history_txt,
            ).pack(fill="x")

    def _hash_card(self, parent, col: int, title: str, value: str, accent: str):
        card = ctk.CTkFrame(
            parent,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        card.grid(row=0, column=col, sticky="ew", padx=6)

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 10))

        ctk.CTkLabel(header, text="◆", text_color=accent, font=("Inter", 14, "bold")).pack(side="left")
        ctk.CTkLabel(header, text=title, text_color="white", font=("Inter", 12, "bold")).pack(side="left", padx=(6, 0))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 16))

        entry = ctk.CTkEntry(
            row,
            height=40,
            fg_color="white",
            text_color=accent,
            border_width=1,
            border_color=self.COLORS["border"],
            font=("Consolas", 10, "bold"),
        )
        entry.insert(0, value)
        entry.configure(state="readonly")
        entry.pack(side="left", fill="x", expand=True)

        ctk.CTkButton(
            row,
            text="Copy",
            width=76,
            fg_color=self.COLORS["bg_dark"],
            hover_color=self.COLORS["border"],
            command=lambda: self._copy(value),
        ).pack(side="right", padx=(10, 0))

    def _render_history(self):
        for w in self.history_area.winfo_children():
            w.destroy()

        if not self.password_history:
            return

        card = ctk.CTkFrame(
            self.history_area,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        card.pack(fill="x")

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(16, 10))

        ctk.CTkLabel(
            top,
            text="🕒  RECENT PASSWORDS",
            font=("Inter", 12, "bold"),
            text_color="white",
        ).pack(side="left")

        ctk.CTkLabel(
            top,
            text=f"{len(self.password_history)} total",
            font=("Inter", 11, "bold"),
            text_color=self.COLORS["text_dim"],
        ).pack(side="right")

        # Show last 5 (like TSX)
        last_five = self.password_history[-5:][::-1]

        for entry in last_five:
            item = ctk.CTkFrame(
                card,
                fg_color=self.COLORS["bg_dark"],
                corner_radius=12,
                border_width=1,
                border_color=self.COLORS["border"],
            )
            item.pack(fill="x", padx=20, pady=6)

            ctk.CTkLabel(
                item,
                text=entry.get("timestamp", ""),
                text_color=self.COLORS["text_dim"],
                font=("Inter", 10),
            ).pack(anchor="w", padx=14, pady=(10, 2))

            ctk.CTkLabel(
                item,
                text=entry.get("password", ""),
                text_color=self.COLORS["success"],
                font=("Consolas", 11, "bold"),
                wraplength=820,
                justify="left",
            ).pack(anchor="w", padx=14, pady=(0, 10))

        if len(self.password_history) > 5:
            ctk.CTkLabel(
                card,
                text="Showing last 5 passwords",
                text_color=self.COLORS["text_dim"],
                font=("Inter", 10),
            ).pack(anchor="w", padx=20, pady=(8, 16))
        else:
            ctk.CTkLabel(card, text="", fg_color="transparent").pack(pady=(0, 10))

    def _download_history_txt(self):
        if not self.password_history:
            return

        # Build file content like your TSX
        lines = []
        for idx, entry in enumerate(self.password_history, start=1):
            lines.append(f"Entry {idx}:")
            lines.append(f"Timestamp: {entry.get('timestamp','')}")
            lines.append(f"Password: {entry.get('password','')}")
            lines.append(f"SHA-256 Hash: {entry.get('sha256Hash','')}")
            lines.append(f"bcrypt Hash: {entry.get('bcryptHash','')}")
            lines.append("")

        file_content = "\n".join(lines)

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile="passwords.txt",
            title="Save Password History",
        )
        if not path:
            return

        try:
            Path(path).write_text(file_content, encoding="utf-8")
        except Exception:
            # Silent fail; you can also show a CTk message dialog if you want.
            pass
