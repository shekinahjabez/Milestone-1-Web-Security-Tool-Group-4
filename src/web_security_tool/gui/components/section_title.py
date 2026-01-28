import customtkinter as ctk


class SectionTitle(ctk.CTkFrame):
    """
    Reusable section title + optional subtitle.
    Matches SecureKit light theme typography and spacing.
    """

    def __init__(
        self,
        parent,
        *,
        title: str,
        subtitle: str | None = None,
        colors: dict,
        align: str = "left",   # "left" or "center"
    ):
        super().__init__(parent, fg_color="transparent")
        self.COLORS = colors

        anchor = "w" if align == "left" else "center"

        # Title
        ctk.CTkLabel(
            self,
            text=title,
            font=("Inter", 24, "bold"),
            text_color=self.COLORS["text_main"],
        ).pack(anchor=anchor)

        # Optional subtitle
        if subtitle:
            ctk.CTkLabel(
                self,
                text=subtitle,
                font=("Inter", 14),
                text_color=self.COLORS["text_dim"],
                wraplength=820,
                justify="left" if align == "left" else "center",
            ).pack(anchor=anchor, pady=(4, 0))
