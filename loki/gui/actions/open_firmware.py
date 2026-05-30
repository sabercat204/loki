"""File → Open Firmware Image action.

The action is a plain function so tests can call it directly with a
synthetic path, bypassing the file dialog.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QFileDialog, QMessageBox

from loki.models import FirmwareImage

if TYPE_CHECKING:
    from loki.gui.main_window import MainWindow

__all__ = ["compute_sha256", "open_firmware", "open_firmware_from_path"]


_HASH_CHUNK = 1024 * 1024  # 1 MiB


def compute_sha256(path: Path) -> str:
    """Return the lowercase SHA-256 hex digest of ``path``.

    Reads the file in 1 MiB chunks so a 100 MB firmware binary doesn't
    pin the entire file in memory.
    """

    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def open_firmware(window: MainWindow) -> FirmwareImage | None:
    """Show the file dialog, hash the chosen file, and open a tab.

    Returns the constructed :class:`FirmwareImage` on success, or ``None``
    if the user cancelled the dialog.
    """

    path_str, _filter = QFileDialog.getOpenFileName(
        window,
        "Open firmware image",
        str(Path.home()),
        "Firmware binaries (*.rom *.bin *.fd *.cap *.img);;All files (*)",
    )
    if not path_str:
        return None
    return open_firmware_from_path(window, Path(path_str))


def open_firmware_from_path(window: MainWindow, path: Path) -> FirmwareImage | None:
    """Construct a ``FirmwareImage`` from a real path and open a tab.

    Surfaces validator errors via ``QMessageBox`` rather than letting them
    bubble out and crash the event loop.
    """

    try:
        size = os.path.getsize(path)
        if size <= 0:
            raise ValueError(f"file is empty: {path}")
        file_hash = compute_sha256(path)
        image = FirmwareImage(
            file_path=str(path),
            file_hash=file_hash,
            file_size=size,
        )
    except (OSError, ValueError) as exc:
        QMessageBox.warning(
            window,
            "Could not open firmware image",
            f"{path}\n\n{exc}",
        )
        return None

    window.add_firmware_image(image)
    return image
