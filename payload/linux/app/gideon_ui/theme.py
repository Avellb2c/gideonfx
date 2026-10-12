from __future__ import annotations

from enum import StrEnum

from .tokens import COLORS, FONT_FAMILY


class ThemeMode(StrEnum):
    LIGHT = "light"
    DARK = "dark"


def build_stylesheet(mode: ThemeMode) -> str:
    dark: bool = mode == ThemeMode.DARK

    if dark:
        bg = COLORS.dark_bg
        surface = COLORS.dark_surface
        surface2 = COLORS.dark_surface_2
        border = COLORS.dark_border
        border_strong = COLORS.dark_border_strong
        text = COLORS.dark_text
        muted = COLORS.dark_muted
        input_bg = "#12181E"
        hover = "#232C35"
        pressed = "#293743"
        selected = "#123A4C"
        selected_hover = "#16475B"
        table_alt = "#1A2128"
        disabled_fg = "#74808C"
        disabled_bg = "#20272F"
        scrollbar = "#53606C"
        success_fg, success_bg = COLORS.dark_success, COLORS.dark_success_soft
        warning_fg, warning_bg = COLORS.dark_warning, COLORS.dark_warning_soft
        danger_fg, danger_bg = COLORS.dark_danger, COLORS.dark_danger_soft
        info_fg, info_bg = COLORS.dark_info, COLORS.dark_info_soft
        neutral_fg, neutral_bg = COLORS.dark_neutral, COLORS.dark_neutral_soft
        toast_shadow_border = "#36424E"
    else:
        bg = "#F6F7F9"
        surface = COLORS.neutral_0
        surface2 = COLORS.neutral_10
        border = COLORS.neutral_40
        border_strong = COLORS.neutral_60
        text = COLORS.neutral_190
        muted = COLORS.neutral_130
        input_bg = COLORS.neutral_0
        hover = COLORS.neutral_20
        pressed = "#E8EDF1"
        selected = "#E6F2F8"
        selected_hover = "#D7EBF5"
        table_alt = "#FAFBFC"
        disabled_fg = COLORS.neutral_90
        disabled_bg = COLORS.neutral_30
        scrollbar = COLORS.neutral_60
        success_fg, success_bg = COLORS.success, COLORS.success_soft
        warning_fg, warning_bg = COLORS.warning, COLORS.warning_soft
        danger_fg, danger_bg = COLORS.danger, COLORS.danger_soft
        info_fg, info_bg = COLORS.info, COLORS.info_soft
        neutral_fg, neutral_bg = "#425466", COLORS.neutral_soft
        toast_shadow_border = COLORS.neutral_40

    return f"""
    * {{
        font-family: '{FONT_FAMILY}';
        font-size: 10pt;
        color: {text};
    }}

    QMainWindow, QWidget#AppRoot {{
        background: {bg};
    }}

    QWidget#TopBar {{
        background: {surface};
        border-bottom: 1px solid {border};
    }}

    QWidget#Sidebar {{
        background: {COLORS.brand_blue_dark};
        border-right: 1px solid #003A54;
    }}

    QLabel#BrandTitle {{
        color: #FFFFFF;
        font-size: 18pt;
        font-weight: 750;
        letter-spacing: 0.8px;
    }}

    QLabel#BrandSubTitle {{
        color: #DDEFF7;
        font-size: 8.5pt;
        font-weight: 500;
    }}

    QLabel#SidebarFooter {{
        color: #C8E2ED;
        font-size: 8pt;
        padding: 8px;
    }}

    QPushButton#NavButton {{
        background: transparent;
        color: #F8FBFC;
        border: 0;
        border-radius: 7px;
        text-align: left;
        padding: 10px 12px;
        font-weight: 500;
    }}
    QPushButton#NavButton:hover {{
        background: rgba(255,255,255,0.11);
        color: #FFFFFF;
    }}
    QPushButton#NavButton:checked {{
        background: rgba(255,255,255,0.18);
        border-left: 3px solid {COLORS.brand_red};
        color: #FFFFFF;
        font-weight: 700;
    }}

    QFrame#Card, QWidget#Card {{
        background: {surface};
        border: 1px solid {border};
        border-radius: 10px;
    }}
    QFrame#Card[selected="true"], QWidget#Card[selected="true"] {{
        background: {selected};
        border: 2px solid {COLORS.brand_blue};
    }}

    QFrame#SoftCard, QWidget#SoftCard {{
        background: {surface2};
        border: 1px solid {border};
        border-radius: 10px;
    }}

    QFrame#CommandBar {{
        background: {surface};
        border: 1px solid {border};
        border-radius: 9px;
    }}

    QLabel#PageTitle {{
        color: {text};
        font-size: 22pt;
        font-weight: 700;
    }}
    QLabel#SectionTitle {{
        color: {text};
        font-size: 13pt;
        font-weight: 700;
    }}
    QLabel#Muted {{
        color: {muted};
    }}
    QLabel#Caption {{
        color: {muted};
        font-size: 8.5pt;
    }}
    QLabel#MetricValue {{
        color: {text};
        font-size: 22pt;
        font-weight: 700;
    }}
    QLabel#MetricLabel {{
        color: {muted};
        font-size: 8.5pt;
        font-weight: 600;
    }}

    QPushButton {{
        min-height: 30px;
        border-radius: 6px;
        padding: 4px 12px;
        color: {text};
        background: {surface};
        border: 1px solid {border_strong};
    }}
    QPushButton:hover {{
        background: {hover};
        border-color: {border_strong};
    }}
    QPushButton:pressed {{
        background: {pressed};
    }}
    QPushButton:focus {{
        border: 1px solid {COLORS.brand_blue};
    }}
    QPushButton:disabled {{
        color: {disabled_fg};
        background: {disabled_bg};
        border-color: {border};
    }}

    QPushButton#PrimaryButton {{
        background: {COLORS.brand_blue};
        color: #FFFFFF;
        border: 1px solid {COLORS.brand_blue};
        font-weight: 650;
    }}
    QPushButton#PrimaryButton:hover {{
        background: {COLORS.brand_blue_hover};
        color: #FFFFFF;
        border-color: {COLORS.brand_blue_hover};
    }}
    QPushButton#PrimaryButton:pressed {{
        background: {COLORS.brand_blue_dark};
    }}

    QPushButton#DangerButton {{
        background: {COLORS.brand_red};
        color: #FFFFFF;
        border: 1px solid {COLORS.brand_red};
        font-weight: 650;
    }}
    QPushButton#DangerButton:hover {{
        background: {COLORS.brand_red_hover};
        color: #FFFFFF;
        border-color: {COLORS.brand_red_hover};
    }}

    QPushButton#GhostButton {{
        color: {text};
        background: transparent;
        border: 1px solid transparent;
    }}
    QPushButton#GhostButton:hover {{
        background: {hover};
    }}

    QLabel#StatusChip {{
        border: 0;
        border-radius: 10px;
        padding: 3px 8px;
        font-size: 8.5pt;
        font-weight: 650;
    }}
    QLabel#StatusChip[kind="success"] {{ background: {success_bg}; color: {success_fg}; }}
    QLabel#StatusChip[kind="warning"] {{ background: {warning_bg}; color: {warning_fg}; }}
    QLabel#StatusChip[kind="danger"] {{ background: {danger_bg}; color: {danger_fg}; }}
    QLabel#StatusChip[kind="info"] {{ background: {info_bg}; color: {info_fg}; }}
    QLabel#StatusChip[kind="neutral"] {{ background: {neutral_bg}; color: {neutral_fg}; }}

    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateEdit, QTextEdit, QPlainTextEdit {{
        color: {text};
        background: {input_bg};
        border: 1px solid {border_strong};
        border-radius: 6px;
        padding: 6px 8px;
        selection-background-color: {COLORS.brand_blue};
        selection-color: #FFFFFF;
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus,
    QDateEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border: 1px solid {COLORS.brand_blue};
    }}
    QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled, QTextEdit:disabled, QPlainTextEdit:disabled {{
        color: {disabled_fg};
        background: {disabled_bg};
    }}

    QComboBox::drop-down {{
        border: 0;
        width: 24px;
    }}
    QComboBox QAbstractItemView {{
        color: {text};
        background: {surface};
        selection-background-color: {selected};
        selection-color: {text};
        border: 1px solid {border};
    }}

    QCheckBox, QRadioButton {{
        color: {text};
        spacing: 7px;
    }}
    QCheckBox:disabled, QRadioButton:disabled {{
        color: {disabled_fg};
    }}

    QTableView, QTreeView, QListView, QTableWidget {{
        color: {text};
        background: {surface};
        alternate-background-color: {table_alt};
        border: 1px solid {border};
        border-radius: 8px;
        gridline-color: transparent;
        selection-background-color: {selected};
        selection-color: {text};
        outline: 0;
    }}
    QTableView::item, QTreeView::item, QListView::item, QTableWidget::item {{
        color: {text};
        padding: 7px 8px;
        border-bottom: 1px solid {border};
    }}
    QTableView::item:hover, QTreeView::item:hover, QListView::item:hover, QTableWidget::item:hover {{
        background: {selected_hover};
    }}
    QHeaderView::section {{
        color: {muted};
        background: {surface2};
        border: 0;
        border-bottom: 1px solid {border};
        padding: 8px;
        font-weight: 650;
    }}

    QScrollBar:vertical {{ width: 10px; background: transparent; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {scrollbar}; border-radius: 4px; min-height: 30px; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
    QScrollBar:horizontal {{ height: 10px; background: transparent; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {scrollbar}; border-radius: 4px; min-width: 30px; }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; }}

    QTabWidget::pane {{
        border: 1px solid {border};
        border-radius: 8px;
        background: {surface};
    }}
    QTabBar::tab {{
        color: {muted};
        background: transparent;
        padding: 9px 14px;
        border-bottom: 2px solid transparent;
    }}
    QTabBar::tab:hover {{ color: {text}; background: {hover}; }}
    QTabBar::tab:selected {{
        color: {text};
        border-bottom: 2px solid {COLORS.brand_blue};
        font-weight: 650;
    }}

    QProgressBar {{
        border: 0;
        color: {text};
        background: {'#303A44' if dark else COLORS.neutral_30};
        border-radius: 4px;
        min-height: 7px;
        max-height: 7px;
        text-align: center;
    }}
    QProgressBar::chunk {{
        background: {COLORS.brand_blue};
        border-radius: 4px;
    }}

    QFrame#Toast {{
        background: {surface};
        border: 1px solid {toast_shadow_border};
        border-radius: 8px;
    }}
    QFrame#Toast[kind="success"] {{ border-left: 4px solid {success_fg}; }}
    QFrame#Toast[kind="warning"] {{ border-left: 4px solid {warning_fg}; }}
    QFrame#Toast[kind="danger"] {{ border-left: 4px solid {danger_fg}; }}
    QFrame#Toast[kind="info"] {{ border-left: 4px solid {info_fg}; }}
    QLabel#ToastTitle {{ color: {text}; font-weight: 700; }}
    QLabel#ToastMessage {{ color: {muted}; }}

    QMenu, QMenuBar {{
        color: {text};
        background: {surface};
        border-color: {border};
    }}
    QMenu::item:selected, QMenuBar::item:selected {{
        color: {text};
        background: {selected};
    }}

    QStatusBar {{
        color: {muted};
        background: {surface};
        border-top: 1px solid {border};
    }}

    QToolTip {{
        background: {COLORS.neutral_190 if not dark else '#E7ECF0'};
        color: {'#FFFFFF' if not dark else COLORS.neutral_190};
        border: 0;
        padding: 6px;
    }}

    QMessageBox, QDialog {{
        color: {text};
        background: {bg};
    }}
    """
