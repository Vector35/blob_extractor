"""Blob Extractor sidebar user interface
"""

from os import path, listdir, walk, sep
from pathlib import Path
from shutil import rmtree
from math import ceil

from PySide6.QtCore import Qt, QModelIndex
from PySide6.QtWidgets import (
    QVBoxLayout,
    QLabel,
    QWidget,
    QGridLayout,
    QFrame,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTreeView,
    QCheckBox,
)
from PySide6.QtGui import QImage, QFont, QStandardItem, QStandardItemModel
from binaryninja import BinaryView
from binaryninjaui import (
    SidebarWidget,
    SidebarWidgetType,
    ViewFrame,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
    getThemeColor,
    ThemeColor,
    getMonospaceFont,
)

from .tasks import FindBlobsTask, ExtractFilesTask

# Use Qt conventions for variable and function names
# pylint: disable=C0103

class TreeModel(QStandardItemModel):
    """Model for tree views"""

    def __init__(self, headers: list, parent=None) -> None:
        super(TreeModel, self).__init__(parent)
        self.setHorizontalHeaderLabels(headers)


class TreeView(QTreeView):
    """Tree view for displaying results"""

    def __init__(self, headers: list, parent=None) -> None:
        super(TreeView, self).__init__(parent)
        self.model = TreeModel(headers, parent)
        self.setEditTriggers(QTreeView.NoEditTriggers)
        self.setSelectionMode(QTreeView.NoSelection)
        self.setModel(self.model)

    def getModel(self):
        """Get the model for the tree view"""

        return self.model


class TextTreeItem(QStandardItem):
    """Styled QStandardItem for tree views"""

    def __init__(self, font: QFont, text: str, color: bool = False, parent=None) -> None:
        super(TextTreeItem, self).__init__(parent)
        self.setEditable(False)
        self.setText(text)
        self.setFont(font)
        if color:
            self.setForeground(getThemeColor(ThemeColor.AlphanumericHighlightColor))


class IntegerTreeItem(QStandardItem):
    """Styled QStandardItem for text in tree views"""

    def __init__(self, font: QFont, addr: int, isDecimal: bool = False) -> None:
        super(IntegerTreeItem, self).__init__()
        color = getThemeColor(ThemeColor.AddressColor)
        self.setForeground(color)
        if isDecimal:
            self.setText(str(addr))
        else:
            self.setText(f"0x{addr:x}")
        self.setFont(font)


class FormCheckBox(QCheckBox):
    """Styled QCheckBox"""

    def __init__(self, font: QFont, text: str, checked: bool, parent=None) -> None:
        super(FormCheckBox, self).__init__(parent)
        self.setFont(font)
        self.setText(text)
        self.setChecked(checked)


class IntegerTableItem(QTableWidgetItem):
    """Styled QTableWidgetItem for integer values"""

    def __init__(self, font: QFont, addr: int, isDecimal: bool = False) -> None:
        super(IntegerTableItem, self).__init__()
        color = getThemeColor(ThemeColor.AddressColor)
        self.setForeground(color)
        if isDecimal:
            self.setText(str(addr))
        else:
            self.setText(f"0x{addr:x}")
        self.setFont(font)


class TextTableItem(QTableWidgetItem):
    """Styled QTableWidgetItem for text"""

    def __init__(self, font: QFont, text: str, highlight: bool = False) -> None:
        super(TextTableItem, self).__init__()
        if highlight:
            color = getThemeColor(ThemeColor.AlphanumericHighlightColor)
            self.setForeground(color)
        self.setText(text)
        self.setFont(font)


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


class DataTable(QTableWidget):
    """Styled table widget for displaying data"""

    def __init__(self, headers, parent=None) -> None:
        super(DataTable, self).__init__(parent)
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionMode(QTableWidget.NoSelection)
        self.setShowGrid(False)


class ExtractResultsFrame(QFrame):
    """Frame for displaying extraction results"""

    def __init__(self, parent=None) -> None:
        super(ExtractResultsFrame, self).__init__(parent)
        self.lastTmpDir = None
        self.fileReports = None
        self.parents = None
        self.extracted = False

        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.filesTree = TreeView(["Name", "Type", "Size"], self)
        self.filesTreeModel = self.filesTree.getModel()
        layout.addWidget(self.filesTree)

        self.setLayout(layout)
        self.hide()

    def getParentItem(self, _path, parents):
        """Get the parent item for the supplied file path"""

        parent = parents.get(_path)
        if parent:
            return parent

        grandParentPath, parentName = _path.rsplit(sep, 1)
        parentItem = TextTreeItem(getMonospaceFont(self), parentName)
        parents[_path] = parentItem
        if path.isdir(_path) and list(x for x in Path(_path).iterdir() if x.is_file()):  # skip empty directories
            dirItem = TextTreeItem(getMonospaceFont(self), "directory")
            self.getParentItem(grandParentPath, parents).appendRow([parentItem, dirItem])

        return parentItem

    def fileReportsToDict(self, fileReports: list) -> dict:
        """Convert the file reports tuple to a dictionary"""

        fileDict = {}
        for reports in fileReports:
            fileDict[path.realpath(reports[0].path)] = reports

        return fileDict

    def handleExtractResults(self, fileReports: list, tempDir: str) -> None:
        """Handle the unblob extraction file reports and build directory tree"""

        self.filesTreeModel.clear()
        if not fileReports:
            return

        self.fileReports = self.fileReportsToDict(fileReports)
        if self.lastTmpDir:
            rmtree(self.lastTmpDir)
        self.lastTmpDir = tempDir

        # If extraction occured with unblob, there will be a nested _extract subdir
        extractDir = tempDir
        for _file in listdir(extractDir):
            if path.isdir(path.join(extractDir, _file)) and _file.endswith("_extract"):
                extractDir = path.join(extractDir, _file)

        # Create the root item and set root index to the added root
        rootItem = QStandardItem()
        parents = {extractDir: rootItem}
        self.filesTreeModel.appendRow(rootItem)
        addedRoot = self.filesTreeModel.index(0, 0, QModelIndex())
        self.filesTreeModel.insertColumns(0, 3, addedRoot)
        self.filesTree.setRootIndex(addedRoot)

         # Populate the tree with information on the extracted files
        for root, _, files in walk(extractDir):
            parent = self.getParentItem(root, parents)
            for _file in files:
                fullpath = path.realpath(path.join(root, _file))
                reports = self.fileReports.get(fullpath)
                if not reports:
                    continue

                sr, fmr, _, _ = reports
                name = TextTreeItem(getMonospaceFont(self), _file, color=True)
                name.setCheckable(True)
                name.setCheckState(Qt.Unchecked)
                magic = TextTreeItem(getMonospaceFont(self), fmr.magic)
                size = TextTreeItem(getMonospaceFont(self), f"{str(ceil(sr.size / 1024))} KB")
                parent.appendRow([name, magic, size])

        self.filesTree.expandToDepth(1)
        self.filesTree.resizeColumnToContents(0)
        self.filesTree.setColumnWidth(1, 200)
        self.parents = parents
        self.extracted = True
        self.show()

    def runFileExtraction(self, data: BinaryView) -> None:
        """Run the file extraction task"""

        if self.extracted:
            return

        ExtractFilesTask(data, self.handleExtractResults).start()

class ExtractWidget(QWidget):
    """Qt widget for extracting files with unblob"""

    def __init__(self, data: BinaryView, parent=None) -> None:
        super(ExtractWidget, self).__init__(parent)
        self.data = data

        self.extractButton = QPushButton("Extract")
        self.extractButton.clicked.connect(self.handleExtractButton)
        self.statusLabel = StatusLabel("")
        self.resultsFrame = ExtractResultsFrame()

        layout = QGridLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(self.extractButton, 1, 0, Qt.AlignLeft)
        layout.addWidget(self.statusLabel, 1, 1, 1, 4, Qt.AlignLeft)
        layout.addWidget(self.resultsFrame, 2, 0)
        self.setLayout(layout)

    def handleExtractButton(self) -> None:
        """Extract button clicked"""

        self.resultsFrame.runFileExtraction(self.data)


class BlobsWidget(QWidget):
    """Qt widget for displaying interesting blobs in the container binary"""

    def __init__(self, data: BinaryView, parent=None) -> None:
        super(BlobsWidget, self).__init__(parent)
        self.data = data
        self.running = False

        layout = QGridLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(HeaderLabel("Embedded Blobs"), 0, 0, 1, 5)
        self.statusLabel = StatusLabel("")
        layout.addWidget(self.statusLabel, 1, 0, 1, 5)

        self.blobsTable = DataTable(["Start", "End", "Type", "Encrypted"])
        layout.addWidget(self.blobsTable, 2, 0, 1, 5)

        self.extractWidget = ExtractWidget(data)
        self.extractWidget.hide()  # Hide until we have identified blobs (implying the binary is a container)
        layout.addWidget(self.extractWidget, 3, 0, 1, 5)

        self.setLayout(layout)
        if data:
            self.runFindBlobsTask()

    def handleBlobIdResults(self, results: list) -> None:
        """Handle results from the blob extraction task"""

        self.blobsTable.clearContents()
        self.running = False
        if not results:
            self.statusLabel.setText("No interesting blobs found")
            return

        baseaddr = 0
        if self.data.segments:
            baseaddr = self.data.segments[0].start

        self.statusLabel.setText(f"Found ({len(results)}) interesting blob{("s" if len(results) > 1 else "")}")
        self.blobsTable.setRowCount(len(results))
        for i, report in enumerate(results):
            self.blobsTable.setItem(i, 0, IntegerTableItem(getMonospaceFont(self), baseaddr + report.start_offset))
            self.blobsTable.setItem(i, 1, IntegerTableItem(getMonospaceFont(self), baseaddr + report.end_offset))
            self.blobsTable.setItem(i, 2, TextTableItem(getMonospaceFont(self), report.handler_name))
            self.blobsTable.setItem(i, 3, TextTableItem(getMonospaceFont(self), "Yes" if report.is_encrypted else "No"))

        self.extractWidget.show()

    def runFindBlobsTask(self) -> None:
        """Run the blob extraction task and display the results"""

        if self.running:
            return

        self.running = True
        self.statusLabel.setText("Scanning for interesting blobs...")
        FindBlobsTask(self.data, self.handleBlobIdResults).start()

    def updateViewData(self, data: BinaryView) -> None:
        """New binary view (tab switch or binary loaded)"""

        self.data = data
        if not self.data:
            return

        self.runFindBlobsTask()


class BlobExtractorSidebar(SidebarWidget):
    """Sidebar Qt widget for the Blob Extractor plugin"""

    def __init__(self, frame: ViewFrame, data: BinaryView) -> None:
        # pylint: disable=W0613
        super().__init__("Blob Extractor")
        self.data = data

        layout = QVBoxLayout()
        self.blobWidget = BlobsWidget(self.data)
        layout.addWidget(self.blobWidget)
        self.setLayout(layout)

    def notifyViewChanged(self, frame: ViewFrame) -> None:
        """User changed focused to another view"""

        if frame is None:
            return

        view = frame.getCurrentViewInterface()
        if not view:
            return

        new_data = view.getData()
        if not new_data:
            return

        # We really only care if the file data changes (implying new binary load or tab switch)
        if self.data == new_data:
            return

        self.data = new_data
        self.blobWidget.updateViewData(self.data)


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
