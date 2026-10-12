from __future__ import annotations

from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from ..tokens import SPACE_20, SPACE_24


class ScrollPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.scroll = QScrollArea(self)
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self.scroll.viewport().setAutoFillBackground(False)
        outer.addWidget(self.scroll)

        self.content = QWidget(self.scroll)
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(SPACE_24, SPACE_20, SPACE_24, SPACE_24)
        self.content_layout.setSpacing(SPACE_20)
        self.scroll.setWidget(self.content)
