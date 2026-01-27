import customtkinter as ctk


class IconTile(ctk.CTkFrame):
    """
    Square icon tile with perfect centering.
    Handles idle / hover / active states.
    """

    def __init__(
        self,
        parent,
        *,
        emoji: str,
        color_name: str,
        colors: dict,
        tint_bg_for,    # (color_name, active) -> color
        accent_for,     # (color_name) -> color
        size: int = 58,
        radius: int = 16,
        on_click=None,
    ):
        self.COLORS = colors
        self.color_name = color_name
        self._tint_bg_for = tint_bg_for
        self._accent_for = accent_for
        self._is_active = False
        self._on_click = on_click

        super().__init__(
            parent,
            fg_color=self._tint_bg_for(self.color_name, active=False),
            corner_radius=radius,
            width=size,
            height=size,
        )
        self.pack_propagate(False)

        # Emoji icon — use place() for TRUE center
        self.icon_lbl = ctk.CTkLabel(
            self,
            text=emoji,
            font=("Inter", 22, "bold"),
            text_color=self.COLORS["text_dim"],
        )
        self.icon_lbl.place(relx=0.5, rely=0.5, anchor="center")

        # Click handling
        if self._on_click:
            self.bind("<Button-1>", lambda e: self._on_click())
            self.icon_lbl.bind("<Button-1>", lambda e: self._on_click())

    def set_active(self, is_active: bool):
        """Switch between active and idle state."""
        self._is_active = is_active
        if is_active:
            self.configure(
                fg_color=self._tint_bg_for(self.color_name, active=True)
            )
            self.icon_lbl.configure(
                text_color=self._accent_for(self.color_name)
            )
        else:
            self.configure(
                fg_color=self._tint_bg_for(self.color_name, active=False)
            )
            self.icon_lbl.configure(
                text_color=self.COLORS["text_dim"]
            )

    def set_hover(self, hovered: bool):
        """Subtle hover tint (ignored when active)."""
        if self._is_active:
            return

        if hovered:
            self.configure(fg_color="#eef2ff")  # soft slate/indigo tint
        else:
            self.configure(
                fg_color=self._tint_bg_for(self.color_name, active=False)
            )
