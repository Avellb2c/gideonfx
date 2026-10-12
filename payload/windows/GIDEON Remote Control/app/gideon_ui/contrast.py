from __future__ import annotations


def _channel(value: int) -> float:
    normalized: float = value / 255.0
    if normalized <= 0.04045:
        return normalized / 12.92
    return ((normalized + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    value: str = hex_color.strip().lstrip("#")
    if len(value) != 6:
        raise ValueError(f"Color hexadecimal inválido: {hex_color!r}")
    red: int = int(value[0:2], 16)
    green: int = int(value[2:4], 16)
    blue: int = int(value[4:6], 16)
    return (
        0.2126 * _channel(red)
        + 0.7152 * _channel(green)
        + 0.0722 * _channel(blue)
    )


def contrast_ratio(foreground: str, background: str) -> float:
    a: float = relative_luminance(foreground)
    b: float = relative_luminance(background)
    lighter: float = max(a, b)
    darker: float = min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def meets_wcag_aa(foreground: str, background: str, *, large_text: bool = False) -> bool:
    minimum: float = 3.0 if large_text else 4.5
    return contrast_ratio(foreground, background) >= minimum
