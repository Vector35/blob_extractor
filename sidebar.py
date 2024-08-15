"""Blob Extractor sidebar user interface
"""

import platform
import subprocess
from os import path, listdir, walk, sep
from pathlib import Path
from shutil import rmtree, copyfile
from math import ceil
from binaryninja import log_alert, get_form_input, SaveFileNameField

from PySide6.QtCore import Qt, QModelIndex, QPoint
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
    QMenu,
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
    UIContext,
)

from .tasks import FindBlobsTask, ExtractFilesTask, import_files_into_project

# Use Qt conventions for variable and function names
# pylint: disable=C0103

class TreeModel(QStandardItemModel):
    """Model for tree views"""

    def __init__(self, headers: list, parent=None) -> None:
        super(TreeModel, self).__init__(parent)
        self.setHorizontalHeaderLabels(headers)


class TreeView(QTreeView):
    """Tree view for displaying results"""

    def __init__(self, headers: list, parent=None, multiSelect: bool = False) -> None:
        super(TreeView, self).__init__(parent)
        self.model = TreeModel(headers, parent)
        self.setEditTriggers(QTreeView.NoEditTriggers)
        if multiSelect:
            self.setSelectionMode(QTreeView.MultiSelection)
        else:
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

    def __init__(self, data: BinaryView, parent=None) -> None:
        super(ExtractResultsFrame, self).__init__(parent)
        self.lastTmpDir = None
        self.fileReports = None
        self.parents = None
        self.running = False
        self.extractButton = None
        self.data = data
        self.isProject = True if data.project else False

        layout = QGridLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.filesTree = TreeView(["Name", "Type", "Size"], parent=self, multiSelect=self.isProject)
        self.filesTree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.filesTree.customContextMenuRequested.connect(self.contextMenu)
        self.filesTree.doubleClicked.connect(self.openFileExternally)
        self.filesTree.setExpandsOnDoubleClick(False)
        self.filesTreeModel = self.filesTree.getModel()
        layout.addWidget(HeaderLabel("Extracted Files"), 0, 0, 1, 5)
        layout.addWidget(self.filesTree, 1, 0, 1, 5)
        self.setLayout(layout)

    def contextMenu(self, pos: QPoint) -> None:
        """Context menu for the extracted files tree view"""

        menu = QMenu()
        menu.addAction("Open file", lambda: self.openFileExternally(self.filesTree.indexAt(pos)))
        menu.addAction("Open containing folder", lambda: self.openContainingFolder(self.filesTree.indexAt(pos)))
        menu.addAction("Save file as...", lambda: self.saveFileAs(self.filesTree.indexAt(pos)))
        if self.isProject:
            menu.addAction("Import selected files", self.importFiles)
            menu.addAction("Select all", lambda: self.filesTree.selectAll())
            menu.addAction("Unselect all", lambda: self.filesTree.clearSelection())

        menu.exec_(self.filesTree.mapToGlobal(pos))

    def importFiles(self) -> None:
        """Import the selected files into the project"""

        selectedFiles = []
        selectedIndexes = self.filesTree.selectedIndexes()
        for parentDir, parentItem in self.parents.items():
            for i in range(parentItem.rowCount()):
                child = parentItem.child(i)
                if child.index() in selectedIndexes:
                    filepath = path.realpath(path.join(parentDir, child.text()))
                    if path.isdir(filepath) or path.islink(filepath):
                        continue

                    selectedFiles.append(self.fileReports[filepath])

        if not selectedFiles:
            log_alert("No files selected")
            return

        skipped, imported = import_files_into_project(selectedFiles, self.data.project)
        if skipped == imported == 0:
            log_alert("No files selected for import")
            return

        log_alert(f"({imported}) new files imported; ({skipped}) files previously imported")
        self.filesTree.clearSelection()

    def getFullFilepathFromIndex(self, index: QModelIndex) -> str:
        """Get the full file path from the QModelIndex"""

        for parentDir, parentItem in self.parents.items():
            for i in range(parentItem.rowCount()):
                child = parentItem.child(i)
                if child.index() == index:
                    return path.realpath(path.join(parentDir, child.text()))

        return None

    def openFile(self, filepath: str) -> None:
        """Open the file externally"""

        command = ["xdg-open", filepath]
        if platform.system() == "Darwin":
            if path.isdir(filepath):
                command = ["open", filepath]
            else:
                command = ["open", "-t", filepath]

        try:
            subprocess.call(command)
        except (FileNotFoundError, PermissionError) as ex:
            log_alert(f"Could not open file: {ex}")

    def saveFileAs(self, index: QModelIndex) -> None:
        """Save the selected file to disk"""

        filepath = self.getFullFilepathFromIndex(index)
        if not filepath:
            return

        outpathField = SaveFileNameField("Save file as...")
        if not get_form_input([outpathField], "Save file as..."):
            return

        outpath = outpathField.result
        copyfile(filepath, outpath)
        log_alert(f"File saved to: {outpath}")

    def openContainingFolder(self, index: QModelIndex) -> None:
        """Open the containing folder of the selected file"""

        filepath = self.getFullFilepathFromIndex(index)
        if not filepath:
            return

        folder = path.dirname(filepath)
        self.openFile(folder)

    def openFileExternally(self, index: QModelIndex) -> None:
        """Open the selected file in the user's default editor"""

        filepath = self.getFullFilepathFromIndex(index)
        if not filepath:
            return

        self.openFile(filepath)

    def getParentItem(self, _path, parents):
        """Get the parent item for the supplied file path"""

        parent = parents.get(_path)
        if parent:
            return parent

        grandParentPath, parentName = _path.rsplit(sep, 1)
        parentItem = TextTreeItem(getMonospaceFont(self), parentName)
        parentItem.setSelectable(False)
        parents[_path] = parentItem
        if path.isdir(_path) and list(x for x in Path(_path).iterdir() if x.is_file()):  # skip empty directories
            dirItem = TextTreeItem(getMonospaceFont(self), "directory")
            dirItem.setSelectable(False)
            blankItem = QStandardItem("")
            blankItem.setSelectable(False)
            self.getParentItem(grandParentPath, parents).appendRow([parentItem, dirItem, blankItem])

        return parentItem

    def fileReportsToDict(self, fileReports: list) -> dict:
        """Convert the file reports tuple to a dictionary"""

        fileDict = {}
        for reports in fileReports:
            fileDict[path.realpath(reports[0].path)] = reports

        return fileDict

    def handleExtractResults(self, fileReports: list, tempDir: str) -> None:
        """Handle the unblob extraction file reports and build directory tree"""

        self.filesTreeModel.removeRows(0, self.filesTreeModel.rowCount())
        if not fileReports:
            self.extractButton.setEnabled(True)
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
                magic = TextTreeItem(getMonospaceFont(self), fmr.magic)
                size = TextTreeItem(getMonospaceFont(self), f"{str(ceil(sr.size / 1024))} KB")
                parent.appendRow([name, magic, size])

        self.filesTree.expandToDepth(1)
        self.filesTree.resizeColumnToContents(0)
        self.filesTree.setColumnWidth(1, 200)
        self.parents = parents
        self.running = False
        self.show()

    def runFileExtraction(self, extractButton: QPushButton, data: BinaryView) -> None:
        """Run the file extraction task"""

        if self.running:
            return

        self.running = True
        self.extractButton = extractButton
        ExtractFilesTask(data, self.handleExtractResults).start()

class ExtractWidget(QWidget):
    """Qt widget for extracting files with unblob"""

    def __init__(self, data: BinaryView, parent=None) -> None:
        super(ExtractWidget, self).__init__(parent)
        self.data = data

        self.extractButton = QPushButton("Extract")
        self.extractButton.clicked.connect(self.handleExtractButton)
        self.statusLabel = StatusLabel("")
        self.resultsFrame = ExtractResultsFrame(data)

        layout = QGridLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(self.resultsFrame, 1, 0, 1, 5)
        layout.addWidget(self.extractButton, 2, 0, Qt.AlignLeft)
        layout.addWidget(self.statusLabel, 2, 1, 1, 4, Qt.AlignLeft)
        self.setLayout(layout)

    def handleExtractButton(self) -> None:
        """Extract button clicked"""

        self.extractButton.setEnabled(False)
        self.resultsFrame.runFileExtraction(self.extractButton, self.data)


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
        self.blobsTable.doubleClicked.connect(self.navigateToBlob)

        self.extractWidget = ExtractWidget(data)
        self.extractWidget.hide()  # Hide until we have identified blobs (implying the binary is a container)
        layout.addWidget(self.extractWidget, 3, 0, 1, 5)

        self.setLayout(layout)
        if data:
            self.runFindBlobsTask()

    def navigateToBlob(self, index: QModelIndex) -> None:
        """Navigate to the blob in the binary view"""

        column = index.column()
        if column > 1:
            column = 0

        start_addr = int(self.blobsTable.item(index.row(), column).text(), 16)
        UIContext.activeContext().getCurrentViewFrame().navigate(self.data, start_addr)

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
        extractable = False
        for i, report in enumerate(results):
            self.blobsTable.setItem(i, 0, IntegerTableItem(getMonospaceFont(self), baseaddr + report.start_offset))
            self.blobsTable.setItem(i, 1, IntegerTableItem(getMonospaceFont(self), baseaddr + report.end_offset))
            self.blobsTable.setItem(i, 2, TextTableItem(getMonospaceFont(self), report.handler_name))
            self.blobsTable.setItem(i, 3, TextTableItem(getMonospaceFont(self), "Yes" if report.is_encrypted else "No"))

            if (report.handler_name != "elf32" and report.start_offset != 0) and report.handler_name == "padding":
                extractable = True

        if extractable:
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
