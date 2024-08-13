"""Binary Ninja plugin for identifying and extracting files from container formats using Unblob
"""

from binaryninja import core_ui_enabled
from binaryninjaui import Sidebar

from .sidebar import BlobExtractorSidebarType

if core_ui_enabled() is True:
    Sidebar.addSidebarWidgetType(BlobExtractorSidebarType())
