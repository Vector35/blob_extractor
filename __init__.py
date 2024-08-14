"""Binary Ninja plugin for identifying and extracting files from container formats using Unblob
"""

import platform
from os import environ
from binaryninja import core_ui_enabled, log_warn
from binaryninjaui import Sidebar

from .sidebar import BlobExtractorSidebarType


def _set_path_environ() -> None:
    # This is a hack because unblob doesn't set shell=True when calling subprocess.run
    if platform.system() == "Darwin" and "/opt/homebrew/bin" not in environ["PATH"]:
        log_warn("adding /opt/homebrew/bin to PATH")
        environ["PATH"] += ":/opt/homebrew/bin"


_set_path_environ()

if core_ui_enabled() is True:
    Sidebar.addSidebarWidgetType(BlobExtractorSidebarType())
