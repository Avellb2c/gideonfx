from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ColorTokens:
    # Gideon Rx identity. High-contrast text keeps both primary brand fills WCAG AA.
    # for normal text.
    brand_blue: str = "#168BD1"
    brand_blue_dark: str = "#071824"
    brand_blue_hover: str = "#0B6FA8"
    brand_red: str = "#7CE8FF"
    brand_red_hover: str = "#55BFE9"
    purple: str = "#6750A4"

    # Semantic foregrounds used on LIGHT surfaces.
    success: str = "#0F6B3A"
    warning: str = "#9A4B00"
    danger: str = "#B4232F"
    info: str = "#005B8F"

    # Semantic LIGHT soft surfaces.
    success_soft: str = "#E8F5EE"
    warning_soft: str = "#FFF3E0"
    danger_soft: str = "#FDEBED"
    info_soft: str = "#E8F3FA"
    neutral_soft: str = "#EEF1F4"

    # Semantic DARK foreground/surface pairs.
    dark_success: str = "#80D4A3"
    dark_success_soft: str = "#173526"
    dark_warning: str = "#FFD08A"
    dark_warning_soft: str = "#3A2A13"
    dark_danger: str = "#FF9BA6"
    dark_danger_soft: str = "#421D23"
    dark_info: str = "#88C9F0"
    dark_info_soft: str = "#143247"
    dark_neutral: str = "#C4CDD5"
    dark_neutral_soft: str = "#252D35"

    neutral_0: str = "#FFFFFF"
    neutral_10: str = "#FAFBFC"
    neutral_20: str = "#F4F6F8"
    neutral_30: str = "#EEF1F4"
    neutral_40: str = "#E2E6EA"
    neutral_60: str = "#C4CBD2"
    neutral_90: str = "#8A929A"
    neutral_130: str = "#5F6B76"
    neutral_160: str = "#343A40"
    neutral_190: str = "#1B1F23"

    dark_bg: str = "#0F1419"
    dark_surface: str = "#161C22"
    dark_surface_2: str = "#1D252D"
    dark_border: str = "#2C3742"
    dark_border_strong: str = "#42505E"
    dark_text: str = "#F3F6F8"
    dark_muted: str = "#AEB8C2"


COLORS = ColorTokens()

SPACE_2: int = 2
SPACE_4: int = 4
SPACE_6: int = 6
SPACE_8: int = 8
SPACE_12: int = 12
SPACE_16: int = 16
SPACE_20: int = 20
SPACE_24: int = 24
SPACE_32: int = 32
SPACE_40: int = 40

RADIUS_SM: int = 4
RADIUS_MD: int = 8
RADIUS_LG: int = 12
RADIUS_XL: int = 16

NAV_EXPANDED: int = 236
NAV_COLLAPSED: int = 68
TOP_BAR_HEIGHT: int = 64
COMMAND_BAR_HEIGHT: int = 48

ANIMATION_FAST_MS: int = 120
ANIMATION_NORMAL_MS: int = 180
ANIMATION_SLOW_MS: int = 240

FONT_FAMILY: str = "Segoe UI"
FONT_SIZE_CAPTION: int = 9
FONT_SIZE_BODY: int = 10
FONT_SIZE_BODY_LARGE: int = 11
FONT_SIZE_SUBTITLE: int = 13
FONT_SIZE_TITLE: int = 18
FONT_SIZE_PAGE_TITLE: int = 24
FONT_SIZE_HERO: int = 30
