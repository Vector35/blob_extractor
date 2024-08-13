"""Blob Extractor sidebar user interface
"""

from os import path
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QVBoxLayout, QLabel, QWidget, QGridLayout, QFrame, QPushButton
from PySide6.QtGui import QImage
from binaryninja import BinaryView
from binaryninjaui import (
    SidebarWidget,
    SidebarWidgetType,
    ViewFrame,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
    getThemeColor,
    ThemeColor,
)

# Use Qt conventions for variable and function names
# pylint: disable=C0103


class StatusLabel(QLabel):
    """Styled label for status messages"""

    def __init__(self, text: str, parent=None) -> None:
        super(StatusLabel, self).__init__(parent)
        color = getThemeColor(ThemeColor.AlphanumericHighlightColor)
        self.setStyleSheet(f"color: {color.name()}")
        self.setText(text)
        self.setAlignment(Qt.AlignTop)


class HeaderLabel(QLabel):
    """Styled label for widget headers"""

    def __init__(self, text: str, parent=None) -> None:
        super(HeaderLabel, self).__init__(parent)
        self.setStyleSheet("font-size: 14px")
        self.setText(text)
        self.setAlignment(Qt.AlignLeft)
        self.setContentsMargins(0, 5, 0, 5)


class ExtractResultsFrame(QFrame):
    """Frame for displaying extraction results"""

    def __init__(self, parent=None) -> None:
        super(ExtractResultsFrame, self).__init__(parent)
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Extracted files:"))
        self.setLayout(layout)


class ExtractWidget(QWidget):
    """Qt widget for extracting files with unblob"""

    def __init__(self, data: BinaryView, parent=None) -> None:
        super(ExtractWidget, self).__init__(parent)
        self.data = data
        self.lastTmpDir = None
        self.fileReports = None
        self.parents = None

        self.extractButton = QPushButton("Extract")
        self.statusLabel = StatusLabel("")
        self.resultsFrame = ExtractResultsFrame()
        self.resultsFrame.hide()

        layout = QGridLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(HeaderLabel("Extracted Files"), 0, 0, 1, 5)
        layout.addWidget(self.extractButton, 1, 0, Qt.AlignLeft)
        layout.addWidget(self.statusLabel, 1, 1, 1, 4, Qt.AlignLeft)
        layout.addWidget(self.resultsFrame, 2, 0)
        self.setLayout(layout)


class BlobsWidget(QWidget):
    """Qt widget for displaying interesting blobs in the container binary"""

    def __init__(self, parent=None) -> None:
        super(BlobsWidget, self).__init__(parent)
        layout = QGridLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.statusLabel = StatusLabel("")
        layout.addWidget(HeaderLabel("Embedded Blobs"), 0, 0, 1, 5)
        layout.addWidget(self.statusLabel, 1, 0, 1, 5)
        self.setLayout(layout)


class BlobExtractorSidebar(SidebarWidget):
    """Sidebar Qt widget for the Blob Extractor plugin"""

    def __init__(self, frame: ViewFrame, data: BinaryView) -> None:
        # pylint: disable=W0613
        super().__init__("Blob Extractor")
        self.data = data

        layout = QVBoxLayout()
        self.blobWidget = BlobsWidget()
        layout.addWidget(self.blobWidget)
        self.extractWidget = ExtractWidget(data)
        layout.addWidget(self.extractWidget)
        self.setLayout(layout)

    def notifyViewChanged(self, frame: ViewFrame) -> None:
        """User changed focused to another view"""

        if frame is None:
            self.data = None
        else:
            view = frame.getCurrentViewInterface()
            self.data = view.getData()


class BlobExtractorSidebarType(SidebarWidgetType):
    """Sidebar widget type for the Blob Extractor plugin"""

    def __init__(self):
        iconDir = path.dirname(path.abspath(__file__))
        iconPath = path.join(iconDir, "icon.png")
        with open(iconPath, "rb") as f:
            iconData = f.read()
        icon = QImage()
        icon.loadFromData(iconData)
        SidebarWidgetType.__init__(self, icon, "Blob Extractor")

    def createWidget(self, frame: ViewFrame, data: BinaryView) -> SidebarWidget:
        """Create the sidebar widget"""

        return BlobExtractorSidebar(frame, data)

    def defaultLocation(self):
        """Default location for the widget"""

        return SidebarWidgetLocation.LeftContent

    def contextSensitivity(self):
        """Context sensitivity for the widget"""

        return SidebarContextSensitivity.PerViewTypeSidebarContext
