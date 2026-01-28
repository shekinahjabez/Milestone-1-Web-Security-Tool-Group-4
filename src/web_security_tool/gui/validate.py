import customtkinter as ctk
from datetime import datetime

from ..input_validator import InputValidator
from .components.section_title import SectionTitle


class ValidatorFrame(ctk.CTkScrollableFrame):
    """
    UI-only refactor of the Input Validator tab to match your new design.
    Logic stays the same: uses InputValidator methods exactly as before.
    """

    def __init__(self, parent, colors: dict):
        super().__init__(parent, fg_color="transparent")
        self.COLORS = colors

        self._build_ui()
        self._update_button_state()

    # -----------------------
    # UI BUILD
    # -----------------------
    def _build_ui(self):
        # Header (refactored)
        SectionTitle(
            self,
            title="Form Input Validator",
            subtitle="Validate and sanitize web form submissions",
            colors=self.COLORS,
        ).pack(anchor="w", padx=40, pady=(20, 18))

        form_card = ctk.CTkFrame(
            self,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        form_card.pack(fill="x", padx=40, pady=(0, 12))

        grid = ctk.CTkFrame(form_card, fg_color="transparent")
        grid.pack(fill="x", padx=20, pady=18)
        grid.grid_columnconfigure(0, weight=1)
        grid.grid_columnconfigure(1, weight=1)

        self.fullname = self._labeled_entry(grid, "Full Name", "John Doe", row=0, col=0)
        self.email = self._labeled_entry(grid, "Email Address", "john@example.com", row=0, col=1)
        self.username = self._labeled_entry(grid, "Username", "johndoe123", row=1, col=0)
        self.message = self._labeled_textbox(grid, "Message", "Your message here...", row=1, col=1)

        self.validate_btn = ctk.CTkButton(
            self,
            text="🛡️  Validate & Sanitize",
            fg_color=self.COLORS["indigo"],
            hover_color="#4338ca",
            height=52,
            font=("Inter", 14, "bold"),
            text_color="white",
            command=self._handle_validate,
        )
        self.validate_btn.pack(fill="x", padx=40, pady=(6, 12))

        self.results_area = ctk.CTkFrame(self, fg_color="transparent")
        self.results_area.pack(fill="x", padx=40, pady=(0, 30))

        for widget in (self.fullname, self.email, self.username):
            widget.bind("<KeyRelease>", lambda e: self._update_button_state())
        self.message.bind("<KeyRelease>", lambda e: self._update_button_state())

    def _labeled_entry(self, parent, label, placeholder, row, col):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=row, column=col, sticky="ew", padx=8, pady=8)

        ctk.CTkLabel(
            wrap,
            text=label,
            font=("Inter", 12, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(anchor="w", pady=(0, 6))

        entry = ctk.CTkEntry(
            wrap,
            height=48,
            fg_color=self.COLORS["bg_dark"],
            border_color=self.COLORS["border"],
            border_width=1,
            text_color=self.COLORS["text_main"],
            placeholder_text=placeholder,
            placeholder_text_color=self.COLORS["text_dim"],
        )
        entry.pack(fill="x")
        return entry

    def _labeled_textbox(self, parent, label, placeholder, row, col):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=row, column=col, sticky="ew", padx=8, pady=8)

        ctk.CTkLabel(
            wrap,
            text=label,
            font=("Inter", 12, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(anchor="w", pady=(0, 6))

        tb = ctk.CTkTextbox(
            wrap,
            height=120,
            fg_color=self.COLORS["bg_dark"],
            border_color=self.COLORS["border"],
            border_width=1,
            text_color=self.COLORS["text_main"],
        )
        tb.pack(fill="x")

        self._message_placeholder = placeholder
        tb.insert("1.0", placeholder)
        tb.configure(text_color=self.COLORS["text_dim"])

        def on_focus_in(_):
            current = tb.get("1.0", "end").strip()
            if current == self._message_placeholder:
                tb.delete("1.0", "end")
                tb.configure(text_color=self.COLORS["text_main"])

        def on_focus_out(_):
            current = tb.get("1.0", "end").strip()
            if not current:
                tb.insert("1.0", self._message_placeholder)
                tb.configure(text_color=self.COLORS["text_dim"])

        tb.bind("<FocusIn>", on_focus_in)
        tb.bind("<FocusOut>", on_focus_out)

        return tb

    # -----------------------
    # UI STATE
    # -----------------------
    def _get_message_value(self) -> str:
        val = self.message.get("1.0", "end").strip()
        if val == self._message_placeholder:
            return ""
        return val

    def _update_button_state(self):
        all_filled = (
            self.fullname.get().strip()
            and self.email.get().strip()
            and self.username.get().strip()
            and self._get_message_value().strip()
        )

        if all_filled:
            self.validate_btn.configure(state="normal", fg_color=self.COLORS["indigo"])
        else:
            self.validate_btn.configure(state="disabled", fg_color=self.COLORS["text_dim"])

    # -----------------------
    # MAIN ACTION (NO LOGIC CHANGE)
    # -----------------------
    def _handle_validate(self):
        full_name = self.fullname.get().strip()
        email = self.email.get().strip()
        username = self.username.get().strip()
        message = self._get_message_value().strip()

        for w in self.results_area.winfo_children():
            w.destroy()

        sanitized_name, name_sanitized, name_notes = InputValidator.sanitize_input(full_name, "name")
        sanitized_email, email_sanitized, email_notes = InputValidator.sanitize_input(email, "email")
        sanitized_username, username_sanitized, username_notes = InputValidator.sanitize_input(username, "username")
        sanitized_message, message_sanitized, message_notes = InputValidator.sanitize_input(message, "message")

        name_valid, name_errors = InputValidator.validate_full_name(sanitized_name)
        email_valid, email_errors = InputValidator.validate_email_simple(sanitized_email)
        username_valid, username_errors = InputValidator.validate_username(sanitized_username)
        message_valid, message_errors = InputValidator.validate_message(message)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self._render_validation_status([
            ("Full Name", name_valid, name_errors, name_notes),
            ("Email", email_valid, email_errors, email_notes),
            ("Username", username_valid, username_errors, username_notes),
            ("Message", message_valid, message_errors, message_notes),
        ])

        self._render_sanitized_data(
            sanitized_name if name_valid else "",
            sanitized_email if email_valid else "",
            sanitized_username if username_valid else "",
            sanitized_message if message_valid else "",
        )

        self._render_success_banner(name_valid, email_valid, username_valid, message_valid)

    # -----------------------
    # RENDER HELPERS (Design)
    # -----------------------
    def _render_validation_status(self, fields):
        card = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            card,
            text="Validation Status",
            font=("Inter", 12, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(anchor="w", padx=20, pady=(16, 10))

        for field, is_valid, errors, warnings in fields:
            ok = bool(is_valid)

            bg = "#ecfdf5" if ok else "#fef2f2"
            bd = "#a7f3d0" if ok else "#fecaca"
            icon = "✅" if ok else "❌"
            title_color = self.COLORS["success"] if ok else self.COLORS["danger"]

            row = ctk.CTkFrame(
                card,
                fg_color=bg,
                corner_radius=12,
                border_width=1,
                border_color=bd,
            )
            row.pack(fill="x", padx=20, pady=6)

            left = ctk.CTkFrame(row, fg_color="transparent")
            left.pack(side="left", padx=14, pady=12)

            ctk.CTkLabel(
                left,
                text=f"{icon}  {field}",
                font=("Inter", 12, "bold"),
                text_color=title_color,
            ).pack(anchor="w")

            right = ctk.CTkFrame(row, fg_color="transparent")
            right.pack(side="right", padx=14, pady=12)

            msg = ""
            msg_color = self.COLORS["text_dim"]
            if errors:
                msg = errors[0]
                msg_color = self.COLORS["danger"]
            elif warnings:
                msg = warnings[0]
                msg_color = self.COLORS["warning"]

            if msg:
                ctk.CTkLabel(right, text=msg, font=("Inter", 11), text_color=msg_color).pack(anchor="e")

    def _render_sanitized_data(self, name, email, username, message):
        card = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            card,
            text="Sanitized Data",
            font=("Inter", 12, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(anchor="w", padx=20, pady=(16, 10))

        inner = ctk.CTkFrame(
            card,
            fg_color=self.COLORS["bg_dark"],
            corner_radius=12,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        inner.pack(fill="x", padx=20, pady=(0, 16))

        self._kv(inner, "Full Name", name or "(empty)")
        self._kv(inner, "Email", email or "(empty)")
        self._kv(inner, "Username", username or "(empty)")
        self._kv(inner, "Message", message or "(empty)")

    def _kv(self, parent, k, v):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="x", padx=14, pady=(10, 0))

        ctk.CTkLabel(
            wrap,
            text=f"{k}:",
            font=("Inter", 10, "bold"),
            text_color=self.COLORS["text_dim"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            wrap,
            text=v,
            font=("Inter", 12),
            text_color=self.COLORS["text_main"],
            wraplength=820,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _render_timestamp_and_hashes(self, timestamp, sha256_hash, bcrypt_hash):
        ts_card = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        ts_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            ts_card,
            text="Timestamp",
            font=("Inter", 12, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(anchor="w", padx=20, pady=(16, 8))

        ctk.CTkLabel(
            ts_card,
            text=timestamp,
            font=("Inter", 12),
            text_color=self.COLORS["text_main"],
        ).pack(anchor="w", padx=20, pady=(0, 16))

        hash_card = ctk.CTkFrame(
            self.results_area,
            fg_color=self.COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        hash_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            hash_card,
            text="Hashes (of Sanitized Data)",
            font=("Inter", 12, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(anchor="w", padx=20, pady=(16, 10))

        self._hash_row(hash_card, "SHA-256", sha256_hash, self.COLORS["blue"])
        self._hash_row(hash_card, "Bcrypt", bcrypt_hash, self.COLORS["indigo"])

        ctk.CTkLabel(hash_card, text="", fg_color="transparent").pack(pady=(0, 10))

    def _hash_row(self, parent, label, value, accent):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=6)

        ctk.CTkLabel(
            row,
            text=label,
            font=("Inter", 11, "bold"),
            text_color=self.COLORS["text_dim"],
            width=90,
        ).pack(side="left")

        entry = ctk.CTkEntry(
            row,
            height=40,
            fg_color=self.COLORS["bg_dark"],
            border_color=self.COLORS["border"],
            border_width=1,
            text_color=accent,
            font=("Consolas", 10, "bold"),
        )
        entry.insert(0, str(value))
        entry.configure(state="readonly")
        entry.pack(side="left", fill="x", expand=True, padx=(8, 8))

        ctk.CTkButton(
            row,
            text="Copy",
            width=70,
            fg_color=self.COLORS["bg_dark"],
            hover_color=self.COLORS["border"],
            text_color=self.COLORS["text_main"],
            command=lambda: self._copy_to_clipboard(str(value)),
        ).pack(side="right")

    def _copy_to_clipboard(self, text: str):
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception:
            pass

    def _render_success_banner(self, name_valid, email_valid, username_valid, message_valid):
        all_valid = name_valid and email_valid and username_valid and message_valid

        bg = "#ecfdf5" if all_valid else "#fef2f2"
        bd = "#a7f3d0" if all_valid else "#fecaca"
        title_color = self.COLORS["success"] if all_valid else self.COLORS["danger"]

        banner = ctk.CTkFrame(
            self.results_area,
            fg_color=bg,
            corner_radius=16,
            border_width=1,
            border_color=bd,
        )
        banner.pack(fill="x", pady=(0, 12))

        title = "✓ Validation Complete" if all_valid else "✗ Validation Finished With Errors"
        subtitle = (
            "All form data has been validated and sanitized."
            if all_valid
            else "Some fields contain errors. Please correct them and try again."
        )

        ctk.CTkLabel(
            banner,
            text=title,
            font=("Inter", 16, "bold"),
            text_color=title_color,
        ).pack(pady=(14, 4))

        ctk.CTkLabel(
            banner,
            text=subtitle,
            font=("Inter", 12),
            text_color=self.COLORS.get("text_mid", self.COLORS["text_main"]),
        ).pack(pady=(0, 14))
