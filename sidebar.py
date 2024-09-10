"""Blob Extractor sidebar user interface"""

import platform
import subprocess
from os import path, listdir, walk, sep
from pathlib import Path
from shutil import rmtree, copyfile
from math import ceil
from binaryninja import log_alert, get_form_input, SaveFileNameField, execute_on_main_thread, show_message_box

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

# Use Qt style / convention for variable and function names
# pylint: disable=C0103

class TreeModel(QStandardItemModel):
    """Model for tree views"""

    def __init__(self, headers: list, parent=None) -> None:
        QStandardItemModel.__init__(self, parent)
        self.setHorizontalHeaderLabels(headers)


class TreeView(QTreeView):
    """Tree view for displaying results"""

    def __init__(self, headers: list, parent=None, multiSelect: bool = False) -> None:
        QTreeView.__init__(self, parent)
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

    def __init__(self, font: QFont, text: str, color: bool = False) -> None:
        QStandardItem.__init__(self)
        self.setEditable(False)
        self.setText(text)
        self.setFont(font)
        if color:
            self.setForeground(getThemeColor(ThemeColor.AlphanumericHighlightColor))


class IntegerTableItem(QTableWidgetItem):
    """Styled QTableWidgetItem for integer values"""

    def __init__(self, font: QFont, addr: int, isDecimal: bool = False) -> None:
        QTableWidgetItem.__init__(self)
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
        QTableWidgetItem.__init__(self)
        if highlight:
            color = getThemeColor(ThemeColor.AlphanumericHighlightColor)
            self.setForeground(color)
        self.setText(text)
        self.setFont(font)


class StatusLabel(QLabel):
    """Styled label for status messages"""

    def __init__(self, text: str, parent=None, color = None) -> None:
        QLabel.__init__(self, parent)
        if color is None:
            color = getThemeColor(ThemeColor.AlphanumericHighlightColor)
        self.setStyleSheet(f"color: {color.name()}")
        self.setText(text)
        self.setAlignment(Qt.AlignTop)


class HeaderLabel(QLabel):
    """Styled label for widget headers"""

    def __init__(self, text: str, parent=None) -> None:
        QLabel.__init__(self, parent)
        self.setStyleSheet("font-size: 14px")
        self.setText(text)
        self.setAlignment(Qt.AlignLeft)
        self.setContentsMargins(0, 5, 0, 5)


class DataTable(QTableWidget):
    """Styled table widget for displaying data"""

    def __init__(self, headers, parent=None) -> None:
        QTableWidget.__init__(self, parent)
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
        QFrame.__init__(self, parent)
        self.tmpDir = None
        self.fileReports = None
        self.parents = None
        self.running = False
        self.taskCompleteCallback = None
        self.data = data
        self.isProject = True if data.project else False

        layout = QGridLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.filesTree = TreeView(["Name", "Type", "Size"], parent=self, multiSelect=self.isProject)
        self.filesTree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.filesTree.customContextMenuRequested.connect(self._contextMenu)
        self.filesTree.doubleClicked.connect(self._openFileExternally)
        self.filesTree.setExpandsOnDoubleClick(False)
        self.filesTreeModel = self.filesTree.getModel()
        layout.addWidget(HeaderLabel("Extracted Files", parent=self), 0, 0, 1, 5)
        layout.addWidget(self.filesTree, 1, 0, 1, 5)
        self.setLayout(layout)

    def __del__(self) -> None:
        if self.tmpDir is None:
            return

        rmtree(self.tmpDir)
        self.tmpDir = None

    def _contextMenu(self, pos: QPoint) -> None:
        menu = QMenu()
        menu.addAction("Open file", lambda: self._openFileExternally(self.filesTree.indexAt(pos)))
        menu.addAction("Open containing folder", lambda: self._openContainingFolder(self.filesTree.indexAt(pos)))
        menu.addAction("Save file as...", lambda: self._saveFileAs(self.filesTree.indexAt(pos)))
        if self.isProject:
            menu.addAction("Import selected files", self._importFiles)
            menu.addAction("Select all", lambda: self.filesTree.selectAll())
            menu.addAction("Unselect all", lambda: self.filesTree.clearSelection())

        menu.exec_(self.filesTree.mapToGlobal(pos))

    def _importFiles(self) -> None:
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

        show_message_box("Imported Files", f"({imported}) new files imported; ({skipped}) files previously imported")
        self.filesTree.clearSelection()

    def _getFullPathFromIndex(self, index: QModelIndex) -> str:
        for parentDir, parentItem in self.parents.items():
            for i in range(parentItem.rowCount()):
                child = parentItem.child(i)
                if child.index() == index:
                    return path.realpath(path.join(parentDir, child.text()))

        return None

    def _openFile(self, filepath: str) -> None:
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

    def _saveFileAs(self, index: QModelIndex) -> None:
        filepath = self._getFullPathFromIndex(index)
        if not filepath:
            return

        outpathField = SaveFileNameField("Save file as...")
        if not get_form_input([outpathField], "Save file as..."):
            return

        outpath = outpathField.result
        copyfile(filepath, outpath)
        show_message_box("File Saved", f"File saved to: {outpath}")

    def _openContainingFolder(self, index: QModelIndex) -> None:
        filepath = self._getFullPathFromIndex(index)
        if not filepath:
            return

        folder = path.dirname(filepath)
        self._openFile(folder)

    def _openFileExternally(self, index: QModelIndex) -> None:
        filepath = self._getFullPathFromIndex(index)
        if not filepath:
            return

        self._openFile(filepath)

    def _getParentItem(self, _path, parents):
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
            self._getParentItem(grandParentPath, parents).appendRow([parentItem, dirItem, blankItem])

        return parentItem

    def _fileReportsToDict(self, fileReports: list) -> dict:
        fileDict = {}
        for reports in fileReports:
            fileDict[path.realpath(reports[0].path)] = reports

        return fileDict

    def _handleExtractResults(self, fileReports: list, tempDir: str) -> None:
        self.filesTreeModel.removeRows(0, self.filesTreeModel.rowCount())
        if not fileReports:
            self.taskCompleteCallback(0)
            return

        self.fileReports = self._fileReportsToDict(fileReports)
        self.tmpDir = tempDir

        # Unblob creates a nested *_extract subdir
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
            parent = self._getParentItem(root, parents)
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
        self.taskCompleteCallback(len(fileReports))

    def runFileExtraction(self, taskCompleteCallback: callable, data: BinaryView) -> None:
        """Run the file extraction task"""

        if self.running:
            return

        self.running = True
        self.taskCompleteCallback = taskCompleteCallback
        def _handleResultsWrapper(fileReports: list, tempDir: str):
            execute_on_main_thread(lambda: self._handleExtractResults(fileReports, tempDir))
        ExtractFilesTask(data, _handleResultsWrapper).start()

class ExtractWidget(QWidget):
    """Qt widget for extracting files with unblob"""

    def __init__(self, data: BinaryView, parent=None) -> None:
        QWidget.__init__(self, parent)
        self.data = data

        self.extractButton = QPushButton("Start", parent=self)
        self.extractButton.clicked.connect(self._handleExtractButton)
        self.statusLabel = StatusLabel("Click \"Start\" to extract files", color=getThemeColor(ThemeColor.CommentColor), parent=self)
        self.resultsFrame = ExtractResultsFrame(data, parent=self)

        layout = QGridLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(self.resultsFrame, 0, 0, 1, 5)
        layout.addWidget(self.extractButton, 1, 0, Qt.AlignLeft)
        layout.addWidget(self.statusLabel, 1, 1, 1, 4, Qt.AlignRight | Qt.AlignVCenter)
        self.setLayout(layout)

    def _taskCompleteCallback(self, filecnt: int) -> None:
        if filecnt > 0:
            self.statusLabel.setText(f"Extracted ({filecnt}) files")
        else:
            self.statusLabel("No files could be extracted (see the Binary Ninja log)")
            self.extractButton.setEnabled(True) # Re-enable, in case the user wants to try again


    def _handleExtractButton(self) -> None:
        self.extractButton.setEnabled(False)
        self.statusLabel.setText("Running...")
        self.resultsFrame.runFileExtraction(self._taskCompleteCallback, self.data)


class BlobsWidget(QWidget):
    """Qt widget for displaying interesting blobs in the container binary"""

    def __init__(self, data: BinaryView, parent=None) -> None:
        QWidget.__init__(self, parent)
        self.data = data
        self.running = False

        layout = QGridLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(HeaderLabel("Embedded Blobs", parent=self), 0, 0, 1, 5)
        self.statusLabel = StatusLabel("", parent=self)
        layout.addWidget(self.statusLabel, 1, 0, 1, 5)

        self.blobsTable = DataTable(["Start", "End", "Type", "Encrypted"], parent=self)
        self.blobsTable.setContextMenuPolicy(Qt.CustomContextMenu)
        self.blobsTable.customContextMenuRequested.connect(self._contextMenu)
        layout.addWidget(self.blobsTable, 2, 0, 1, 5)
        self.blobsTable.doubleClicked.connect(self._navigateToBlob)

        self.extractWidget = ExtractWidget(data, parent=self)
        self.extractWidget.hide()  # Hide until we have identified blobs (implying the binary is a container)
        layout.addWidget(self.extractWidget, 3, 0, 1, 5)

        self.setLayout(layout)
        if data:
            self.runFindBlobsTask()

    def _saveBlobAs(self, index: QModelIndex) -> None:
        """Carve the blob and save it to disk"""

        baseaddr = 0
        if self.data.segments:
            baseaddr = self.data.segments[0].start

        start_offset = int(self.blobsTable.item(index.row(), 0).text(), 16) - baseaddr
        end_offset = int(self.blobsTable.item(index.row(), 1).text(), 16) - baseaddr
        size = end_offset - start_offset

        outpathField = SaveFileNameField("Save blob as...")
        if not get_form_input([outpathField], "Save blob as..."):
            return

        outpath = outpathField.result
        raw = self.data.get_view_of_type("Raw")
        if not raw:
            log_alert("Failed to carve blob (no raw view!?)")
            return

        data = raw.read(start_offset, size)
        with open(outpath, "wb") as f:
            f.write(data)

        show_message_box("Blob Saved", f"Blob saved to: {outpath}")

    def _contextMenu(self, pos: QPoint) -> None:
        menu = QMenu()
        menu.addAction("Save blob as...", lambda: self._saveBlobAs(self.blobsTable.indexAt(pos)))
        menu.exec_(self.blobsTable.mapToGlobal(pos))

    def _navigateToBlob(self, index: QModelIndex) -> None:
        column = index.column()
        if column > 1:
            column = 0

        start_addr = int(self.blobsTable.item(index.row(), column).text(), 16)
        UIContext.activeContext().getCurrentViewFrame().navigate(self.data, start_addr)

    def _handleBlobIdResults(self, results: list) -> None:
        self.blobsTable.clearContents()
        self.running = False
        if not results:
            self.statusLabel.setText("No interesting blobs found")
            return

        baseaddr = 0
        if self.data.segments:
            baseaddr = self.data.segments[0].start

        self.statusLabel.setText(f"Found ({len(results)}) interesting blob{('s' if len(results) > 1 else '')}")
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
        def _handleResultsWrapper(results: list):
            execute_on_main_thread(lambda: self._handleBlobIdResults(results))
        FindBlobsTask(self.data, _handleResultsWrapper).start()

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
        self.blobWidget = BlobsWidget(self.data, parent=self)
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
