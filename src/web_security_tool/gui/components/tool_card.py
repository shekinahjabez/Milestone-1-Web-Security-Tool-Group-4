import customtkinter as ctk
from .icon_tile import IconTile


class ToolCard(ctk.CTkFrame):
    """
    Clickable tool card (Analyze / Generate / Validate).
    Uses IconTile for perfect icon centering + tinting.
    """

    def __init__(
        self,
        parent,
        *,
        tool_id: str,
        title: str,
        subtitle: str,
        emoji: str,
        color_name: str,
        colors: dict,
        on_click,      # callable: (tool_id: str) -> None
        tint_bg_for,   # callable: (color_name: str, active: bool) -> str
        accent_for,    # callable: (color_name: str) -> str
    ):
        self.tool_id = tool_id
        self.COLORS = colors
        self.color_name = color_name
        self.on_click = on_click
        self._tint_bg_for = tint_bg_for
        self._accent_for = accent_for

        super().__init__(
            parent,
            fg_color=self.COLORS["card_idle"],
            corner_radius=18,
            border_width=2,
            border_color=self.COLORS["border_idle"],
        )

        self._is_active = False

        # click helper
        def _click(_=None):
            self.on_click(self.tool_id)

        self.bind("<Button-1>", _click)

        # inner layout
        self.inner = ctk.CTkFrame(self, fg_color="transparent")
        self.inner.pack(fill="both", expand=True, padx=18, pady=16)
        self.inner.bind("<Button-1>", _click)

        # icon tile (now component)
        self.icon_tile = IconTile(
            self.inner,
            emoji=emoji,
            color_name=self.color_name,
            colors=self.COLORS,
            tint_bg_for=self._tint_bg_for,
            accent_for=self._accent_for,
            on_click=lambda: self.on_click(self.tool_id),
        )
        self.icon_tile.pack(anchor="center", pady=(0, 10))

        # title
        self.title_lbl = ctk.CTkLabel(
            self.inner,
            text=title,
            font=("Inter", 17, "bold"),
            text_color=self.COLORS["text_main"],
        )
        self.title_lbl.pack(anchor="center")
        self.title_lbl.bind("<Button-1>", _click)

        # subtitle
        self.sub_lbl = ctk.CTkLabel(
            self.inner,
            text=subtitle,
            font=("Inter", 13),
            text_color="#475569",  # slate-600
            wraplength=220,
            justify="center",
        )
        self.sub_lbl.pack(anchor="center", pady=(4, 0))
        self.sub_lbl.bind("<Button-1>", _click)

        # bottom active bar
        bar_wrap = ctk.CTkFrame(self, fg_color="transparent", height=10)
        bar_wrap.pack(side="bottom", fill="x")
        bar_wrap.pack_propagate(False)

        self.bar = ctk.CTkFrame(
            bar_wrap,
            fg_color="transparent",
            height=5,
            corner_radius=999,
        )
        self.bar.pack(fill="x", padx=12, pady=(0, 10))
        self.bar.pack_propagate(False)

        # hover behavior (inactive only)
        def _on_enter(_):
            if not self._is_active:
                self.configure(
                    fg_color=self.COLORS["card_active"],
                    border_color=self.COLORS["border_hover"],
                )
                self.icon_tile.set_hover(True)

        def _on_leave(_):
            if not self._is_active:
                self.configure(
                    fg_color=self.COLORS["card_idle"],
                    border_color=self.COLORS["border_idle"],
                )
                self.icon_tile.set_hover(False)

        for w in (self, self.inner, self.title_lbl, self.sub_lbl):
            w.bind("<Enter>", _on_enter)
            w.bind("<Leave>", _on_leave)

        # also make icon tile contribute to hover (optional but feels nice)
        self.icon_tile.bind("<Enter>", _on_enter)
        self.icon_tile.bind("<Leave>", _on_leave)
        self.icon_tile.icon_lbl.bind("<Enter>", _on_enter)
        self.icon_tile.icon_lbl.bind("<Leave>", _on_leave)

    def set_active(self, is_active: bool):
        self._is_active = is_active

        if is_active:
            self.configure(
                fg_color=self.COLORS["card_active"],
                border_color=self.COLORS["border_active"],
                border_width=2,
            )
            self.icon_tile.set_active(True)
            self.bar.configure(fg_color=self._accent_for(self.color_name))
        else:
            self.configure(
                fg_color=self.COLORS["card_idle"],
                border_color=self.COLORS["border_idle"],
                border_width=2,
            )
            self.icon_tile.set_active(False)
            self.bar.configure(fg_color="transparent")
