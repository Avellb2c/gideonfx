from __future__ import annotations

from gideon_common.observability import best_effort_warning

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QEasingCurve, QPoint, QPointF, QPropertyAnimation, QRect, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QIcon, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QPlainTextEdit,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .tokens import (
    ANIMATION_FAST_MS,
    ANIMATION_NORMAL_MS,
    COLORS,
    FONT_FAMILY,
    NAV_COLLAPSED,
    NAV_EXPANDED,
    SPACE_6,
    SPACE_8,
    SPACE_12,
    SPACE_16,
    SPACE_20,
    SPACE_24,
)


class DetailedMessageDialog(QDialog):
    """Technical alert with the complete diagnostic text and one-click copy.

    QMessageBox truncates long backend logs visually and offers no reliable
    "copy all" affordance to operators. This dialog preserves the exact raw
    diagnostic payload so it can be pasted into a ticket or support channel.
    """

    def __init__(
        self,
        title: str,
        message: str,
        details: str,
        parent: QWidget | None = None,
        *,
        level: str = "error",
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(900, 620)
        self.setMinimumSize(680, 440)

        raw_details = str(details or "").strip()
        raw_message = str(message or "").strip()
        self._copy_text = raw_details or raw_message

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_20, SPACE_20, SPACE_20, SPACE_16)
        layout.setSpacing(SPACE_12)

        heading = QLabel(title, self)
        heading.setObjectName("SectionTitle")
        layout.addWidget(heading)

        summary = QLabel(raw_message, self)
        summary.setWordWrap(True)
        summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if level == "error":
            summary.setStyleSheet(f"color:{COLORS.danger}; font-weight:600;")
        elif level == "warning":
            summary.setStyleSheet(f"color:{COLORS.warning}; font-weight:600;")
        layout.addWidget(summary)

        self.details = QPlainTextEdit(self)
        self.details.setObjectName("DiagnosticText")
        self.details.setReadOnly(True)
        self.details.setPlainText(raw_details or raw_message)
        self.details.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        try:
            self.details.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        except Exception as exc:
            best_effort_warning("No se pudo aplicar fuente monoespaciada al detalle técnico", exc)
        layout.addWidget(self.details, 1)

        actions = QHBoxLayout()
        actions.setSpacing(SPACE_8)
        copy_button = QPushButton("Copiar todo", self)
        copy_button.setObjectName("PrimaryButton")
        copy_button.setToolTip("Copia el diagnóstico completo, sin recortes, al portapapeles.")
        copy_button.clicked.connect(self.copy_all)
        actions.addWidget(copy_button)
        actions.addStretch(1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        close_button = buttons.button(QDialogButtonBox.StandardButton.Close)
        if close_button is not None:
            close_button.setText("Cerrar")
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        actions.addWidget(buttons)
        layout.addLayout(actions)

    def copy_all(self) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(self._copy_text)


def show_detailed_message(
    parent: QWidget | None,
    title: str,
    message: str,
    details: str | None = None,
    *,
    level: str = "error",
) -> int:
    """Show a copy-friendly technical message and return its dialog result."""

    dialog = DetailedMessageDialog(
        title=title,
        message=message,
        details=details if details is not None else message,
        parent=parent,
        level=level,
    )
    return dialog.exec()


class GideonRxMarkWidget(QWidget):
    """Original Gideon Rx spacecraft mark drawn without third-party artwork."""

    def __init__(self, parent: QWidget | None = None, size: int = 42) -> None:
        super().__init__(parent)
        self._size: int = size
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def paintEvent(self, event: object) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setBrush(QColor(COLORS.brand_blue_dark))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(self.rect(), self._size * 0.22, self._size * 0.22)

        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(QPen(QColor(COLORS.brand_red), max(2, int(self._size * 0.08)), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(int(self._size * 0.08), int(self._size * 0.40), int(self._size * 0.64), int(self._size * 0.55), 205 * 16, 105 * 16)

        ship = QPolygonF([
            QPointF(self._size * 0.50, self._size * 0.15),
            QPointF(self._size * 0.75, self._size * 0.46),
            QPointF(self._size * 0.64, self._size * 0.73),
            QPointF(self._size * 0.50, self._size * 0.85),
            QPointF(self._size * 0.36, self._size * 0.73),
            QPointF(self._size * 0.25, self._size * 0.46),
        ])
        painter.setPen(QPen(QColor("#D7F9FF"), max(1, int(self._size * 0.04))))
        painter.setBrush(QColor(COLORS.brand_blue))
        painter.drawPolygon(ship)

        painter.setBrush(QColor("#D8FBFF"))
        painter.setPen(QPen(QColor("#0B5D91"), max(1, int(self._size * 0.035))))
        painter.drawEllipse(QRectF(self._size * 0.38, self._size * 0.29, self._size * 0.24, self._size * 0.16))
        painter.setPen(QPen(QColor("#075985"), max(1, int(self._size * 0.045)), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(int(self._size * 0.34), int(self._size * 0.45), int(self._size * 0.32), int(self._size * 0.24), 10 * 16, 160 * 16)
        painter.setBrush(QColor("#F6FDFF"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(self._size * 0.50, self._size * 0.78), self._size * 0.035, self._size * 0.035)
        painter.end()


# Compatibility alias for plugins that imported the old widget class name.
GideonsMarkWidget = GideonRxMarkWidget


class SidebarButton(QPushButton):
    def __init__(
        self,
        text: str,
        glyph: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._label: str = text
        self._glyph: str = glyph
        self._icon_mode = str(glyph).lower().endswith(".svg") and Path(str(glyph)).is_file()
        self.setObjectName("NavButton")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(42)
        if self._icon_mode:
            self.setIcon(QIcon(str(glyph)))
            self.setIconSize(QSize(20, 20))
            self.setText(text)
        else:
            self.setText(f"{glyph}   {text}")

    def set_compact(self, compact: bool) -> None:
        if self._icon_mode:
            self.setText("" if compact else self._label)
        else:
            self.setText(self._glyph if compact else f"{self._glyph}   {self._label}")
        self.setToolTip(self._label if compact else "")
        self.setStyleSheet(
            "text-align:center; padding-left:0px; padding-right:0px;"
            if compact
            else ""
        )


class CollapsibleSidebar(QFrame):
    collapsedChanged: Signal = Signal(bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setMinimumWidth(NAV_EXPANDED)
        self.setMaximumWidth(NAV_EXPANDED)
        self._collapsed: bool = False
        self._animation: QPropertyAnimation = QPropertyAnimation(self, b"maximumWidth", self)
        self._animation.setDuration(ANIMATION_NORMAL_MS)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._min_animation: QPropertyAnimation = QPropertyAnimation(self, b"minimumWidth", self)
        self._min_animation.setDuration(ANIMATION_NORMAL_MS)
        self._min_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._buttons: list[SidebarButton] = []
        self.brand_title: QLabel | None = None
        self.brand_subtitle: QLabel | None = None

    @property
    def collapsed(self) -> bool:
        return self._collapsed

    def register_button(self, button: SidebarButton) -> None:
        self._buttons.append(button)

    def bind_brand(self, title: QLabel, subtitle: QLabel) -> None:
        self.brand_title = title
        self.brand_subtitle = subtitle

    def toggle(self) -> None:
        self.set_collapsed(not self._collapsed)

    def set_collapsed(self, collapsed: bool, animate: bool = True) -> None:
        if collapsed == self._collapsed and animate:
            return
        self._collapsed = collapsed
        target: int = NAV_COLLAPSED if collapsed else NAV_EXPANDED
        for button in self._buttons:
            button.set_compact(collapsed)
        if self.brand_title is not None:
            self.brand_title.setVisible(not collapsed)
        if self.brand_subtitle is not None:
            self.brand_subtitle.setVisible(not collapsed)

        if animate:
            self._animation.stop()
            self._min_animation.stop()
            self._animation.setStartValue(self.width())
            self._animation.setEndValue(target)
            self._min_animation.setStartValue(self.width())
            self._min_animation.setEndValue(target)
            self._animation.start()
            self._min_animation.start()
        else:
            self.setMinimumWidth(target)
            self.setMaximumWidth(target)
        self.collapsedChanged.emit(collapsed)


class AnimatedStackedWidget(QStackedWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._animation: QPropertyAnimation | None = None
        self._effect: QGraphicsOpacityEffect | None = None

    def setCurrentIndexAnimated(self, index: int) -> None:  # noqa: N802
        """Switch pages without a full-widget opacity effect.

        QGraphicsOpacityEffect forces Qt to rasterize large pages (tables, scroll
        areas and cards) on every navigation. On Windows/remote sessions that
        produced the visible "tirón" reported by operators. The sidebar keeps
        its lightweight width animation, while content navigation is immediate.
        """
        if index == self.currentIndex() or index < 0 or index >= self.count():
            return
        if self._animation is not None:
            self._animation.stop()
        current = self.currentWidget()
        if current is not None:
            current.setGraphicsEffect(None)
        self.setCurrentIndex(index)


class MetricCard(QFrame):
    def __init__(
        self,
        label: str,
        value: str = "0",
        accent: str = COLORS.brand_blue,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumHeight(104)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_16, SPACE_12, SPACE_16, SPACE_12)
        layout.setSpacing(4)

        accent_bar = QFrame(self)
        accent_bar.setFixedHeight(3)
        accent_bar.setStyleSheet(f"background:{accent}; border-radius:1px;")
        layout.addWidget(accent_bar)

        caption = QLabel(label.upper(), self)
        caption.setObjectName("MetricLabel")
        layout.addWidget(caption)

        self.value_label = QLabel(value, self)
        self.value_label.setObjectName("MetricValue")
        layout.addWidget(self.value_label)
        layout.addStretch(1)

    def set_value(self, value: object) -> None:
        self.value_label.setText(str(value))


class StatusChip(QLabel):
    _KINDS: tuple[str, ...] = ("success", "warning", "danger", "info", "neutral")

    def __init__(
        self,
        text: str,
        kind: str = "neutral",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self.setObjectName("StatusChip")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        self.set_kind(kind)

    def set_kind(self, kind: str) -> None:
        normalized: str = kind if kind in self._KINDS else "neutral"
        self.setProperty("kind", normalized)
        style = self.style()
        if style is not None:
            style.unpolish(self)
            style.polish(self)
        self.update()


class CommandBar(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("CommandBar")
        self.layout_: QHBoxLayout = QHBoxLayout(self)
        self.layout_.setContentsMargins(SPACE_8, SPACE_6, SPACE_8, SPACE_6)
        self.layout_.setSpacing(6)

    def add_action(
        self,
        text: str,
        callback: Callable[[], None],
        *,
        primary: bool = False,
        danger: bool = False,
    ) -> QPushButton:
        button = QPushButton(text, self)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        if primary:
            button.setObjectName("PrimaryButton")
        elif danger:
            button.setObjectName("DangerButton")
        else:
            button.setObjectName("GhostButton")
        button.clicked.connect(callback)
        self.layout_.addWidget(button)
        return button

    def add_stretch(self) -> None:
        self.layout_.addStretch(1)


class PageHeader(QWidget):
    def __init__(
        self,
        title: str,
        subtitle: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(SPACE_16)

        texts = QVBoxLayout()
        texts.setSpacing(3)
        self.title_label = QLabel(title, self)
        self.title_label.setObjectName("PageTitle")
        self.subtitle_label = QLabel(subtitle, self)
        self.subtitle_label.setObjectName("Muted")
        self.subtitle_label.setWordWrap(True)
        texts.addWidget(self.title_label)
        texts.addWidget(self.subtitle_label)
        layout.addLayout(texts, 1)

        self.actions = QHBoxLayout()
        self.actions.setSpacing(SPACE_8)
        layout.addLayout(self.actions)

    def add_action(self, button: QPushButton) -> None:
        self.actions.addWidget(button)


class EmptyState(QFrame):
    def __init__(
        self,
        title: str,
        message: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("SoftCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_24, SPACE_24, SPACE_24, SPACE_24)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label = QLabel(title, self)
        title_label.setObjectName("SectionTitle")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        message_label = QLabel(message, self)
        message_label.setObjectName("Muted")
        message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        message_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(message_label)


class Toast(QFrame):
    closed: Signal = Signal()

    def __init__(
        self,
        title: str,
        message: str,
        kind: str = "info",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        normalized: str = kind if kind in {"success", "warning", "danger", "info"} else "info"
        self.setObjectName("Toast")
        self.setProperty("kind", normalized)
        self.setMinimumWidth(320)
        self.setMaximumWidth(420)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_12, 10, SPACE_12, 10)
        layout.setSpacing(3)
        title_label = QLabel(title, self)
        title_label.setObjectName("ToastTitle")
        message_label = QLabel(message, self)
        message_label.setObjectName("ToastMessage")
        message_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(message_label)
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._fade = QPropertyAnimation(self._effect, b"opacity", self)
        self._fade.setDuration(ANIMATION_NORMAL_MS)
        self._fade.setStartValue(1.0)
        self._fade.setEndValue(0.0)
        self._fade.finished.connect(self._finish)

    def fade_out(self) -> None:
        self._fade.start()

    def _finish(self) -> None:
        self.closed.emit()
        self.deleteLater()


class ToastManager(QWidget):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setStyleSheet("background:transparent;")
        self.raise_()
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(SPACE_8)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)
        self.hide()

    def reposition(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return
        width = min(440, max(340, parent.width() // 3))
        self.setGeometry(parent.width() - width - 20, 78, width, parent.height() - 96)
        self.raise_()

    def show_toast(
        self,
        title: str,
        message: str,
        kind: str = "info",
        timeout_ms: int = 4200,
    ) -> None:
        self.show()
        toast = Toast(title, message, kind, self)
        toast.closed.connect(self._cleanup)
        self._layout.addWidget(toast, 0, Qt.AlignmentFlag.AlignRight)
        QTimer.singleShot(timeout_ms, toast.fade_out)
        self.reposition()

    def _cleanup(self) -> None:
        if self._layout.count() <= 1:
            QTimer.singleShot(250, self._hide_if_empty)

    def _hide_if_empty(self) -> None:
        alive = 0
        for index in range(self._layout.count()):
            item = self._layout.itemAt(index)
            if item is not None and item.widget() is not None:
                alive += 1
        if alive == 0:
            self.hide()
