# src/web_security_tool/gui/components/buttons.py
import customtkinter as ctk


class PrimaryButton(ctk.CTkButton):
    """
    Primary action button (filled).
    Defaults to your theme accent color.
    """

    def __init__(
        self,
        parent,
        *,
        text: str,
        command=None,
        colors: dict,
        fg_color: str | None = None,
        hover_color: str | None = None,
        height: int = 52,
        width: int | None = None,
        font=("Inter", 14, "bold"),
        text_color: str = "white",
        **kwargs,
    ):
        self.COLORS = colors

        super().__init__(
            parent,
            text=text,
            command=command,
            fg_color=fg_color or self.COLORS["accent"],
            hover_color=hover_color or "#1d4ed8",  # blue-700
            height=height,
            font=font,
            text_color=text_color,
            **kwargs,
        )

        if width is not None:
            self.configure(width=width)


class AccentButton(ctk.CTkButton):
    """
    Filled button in a specific accent color (e.g., emerald/indigo).
    Useful for Generate/Validate buttons.
    """

    def __init__(
        self,
        parent,
        *,
        text: str,
        command=None,
        colors: dict,
        accent: str,
        hover: str,
        height: int = 52,
        width: int | None = None,
        font=("Inter", 14, "bold"),
        text_color: str = "white",
        **kwargs,
    ):
        self.COLORS = colors
        super().__init__(
            parent,
            text=text,
            command=command,
            fg_color=accent,
            hover_color=hover,
            height=height,
            font=font,
            text_color=text_color,
            **kwargs,
        )

        if width is not None:
            self.configure(width=width)


class SecondaryButton(ctk.CTkButton):
    """
    Secondary button (light / outline feel), matches your cards.
    Great for Copy / Download actions.
    """

    def __init__(
        self,
        parent,
        *,
        text: str,
        command=None,
        colors: dict,
        height: int = 44,
        width: int | None = None,
        font=("Inter", 12, "bold"),
        **kwargs,
    ):
        self.COLORS = colors
        super().__init__(
            parent,
            text=text,
            command=command,
            fg_color=self.COLORS["bg_dark"],
            hover_color=self.COLORS["border"],
            text_color=self.COLORS["text_main"],
            border_width=1,
            border_color=self.COLORS["border"],
            height=height,
            font=font,
            **kwargs,
        )

        if width is not None:
            self.configure(width=width)


class IconButton(ctk.CTkButton):
    """
    Small square icon button (emoji), with proper centering.
    You can optionally pass an on_click command.
    """

    def __init__(
        self,
        parent,
        *,
        icon: str,
        command=None,
        colors: dict,
        size: int = 44,
        fg_color: str | None = None,
        hover_color: str | None = None,
        border: bool = True,
        **kwargs,
    ):
        self.COLORS = colors
        super().__init__(
            parent,
            text="",  # we center an inner label
            command=command,
            width=size,
            height=size,
            fg_color=fg_color or self.COLORS["bg_dark"],
            hover_color=hover_color or "#e2e8f0",
            border_width=1 if border else 0,
            border_color=self.COLORS["border"] if border else None,
            **kwargs,
        )
        self.pack_propagate(False)

        self.icon_lbl = ctk.CTkLabel(
            self,
            text=icon,
            font=("Inter", 16, "bold"),
            text_color=self.COLORS["text_dim"],
        )
        self.icon_lbl.place(relx=0.5, rely=0.5, anchor="center")

        # Clicking on the label should click the button too
        if command is not None:
            self.icon_lbl.bind("<Button-1>", lambda e: command())

    def set_icon(self, icon: str, *, color: str | None = None):
        self.icon_lbl.configure(text=icon)
        if color is not None:
            self.icon_lbl.configure(text_color=color)
