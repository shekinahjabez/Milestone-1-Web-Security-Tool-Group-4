import customtkinter as ctk
from PIL import Image


class IconTile(ctk.CTkFrame):
    """
    Square icon tile with perfect centering.
    Handles idle / hover / active states.
    PNG icon version (no emoji).
    """

    def __init__(
        self,
        parent,
        *,
        icon_path: str,
        color_name: str,
        colors: dict,
        tint_bg_for,    # (color_name, active) -> color
        accent_for,     # (color_name) -> color
        size: int = 58,
        radius: int = 16,
        icon_size: int = 26,
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

        # Load PNG icon
        img = Image.open(icon_path).convert("RGBA")
        self._icon_img = ctk.CTkImage(light_image=img, dark_image=img, size=(icon_size, icon_size))

        # Center icon
        self.icon_lbl = ctk.CTkLabel(self, text="", image=self._icon_img)
        self.icon_lbl.place(relx=0.5, rely=0.5, anchor="center")

        # Click handling
        if self._on_click:
            self.bind("<Button-1>", lambda e: self._on_click())
            self.icon_lbl.bind("<Button-1>", lambda e: self._on_click())

    def set_active(self, is_active: bool):
        """Switch between active and idle state."""
        self._is_active = is_active
        self.configure(fg_color=self._tint_bg_for(self.color_name, active=is_active))

    def set_hover(self, hovered: bool):
        """Subtle hover tint (ignored when active)."""
        if self._is_active:
            return

        if hovered:
            self.configure(fg_color="#eef2ff")
        else:
            self.configure(fg_color=self._tint_bg_for(self.color_name, active=False))
