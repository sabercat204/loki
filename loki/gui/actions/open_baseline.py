"""View → Open Baseline Registry… action (R7.4).

Lets the user pick a single Baseline_File from anywhere on disk and
loads it into the workspace **without** persisting it to the
Storage_Directory. Mirrors the loosely-typed import semantics of
``loki baseline import``: a single-file ``load_one`` call, with
typed errors surfaced via ``QMessageBox.warning``.

The action is a plain function so tests can call it directly with a
synthetic path, bypassing the file dialog.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QFileDialog, QMessageBox

from loki.baseline import BaselineSerializationError, BaselineStoreError
from loki.models import BaselineRecord

if TYPE_CHECKING:
    from loki.gui.main_window import MainWindow

__all__ = ["open_baseline", "open_baseline_from_path"]


def open_baseline(window: MainWindow) -> BaselineRecord | None:
    """Show a file dialog rooted at the store's path, then load + open a tab.

    Returns the constructed :class:`BaselineRecord` on success, or
    ``None`` if the user cancelled the dialog or the load failed.
    R7.4: doesn't modify the Storage_Directory.
    """

    store = window.baseline_store
    initial_dir = str(store.storage_path) if store is not None else str(Path.home())

    path_str, _filter = QFileDialog.getOpenFileName(
        window,
        "Open baseline registry",
        initial_dir,
        "Baseline files (*.yaml);;All files (*)",
    )
    if not path_str:
        return None
    return open_baseline_from_path(window, Path(path_str))


def open_baseline_from_path(window: MainWindow, path: Path) -> BaselineRecord | None:
    """Load a Baseline_File at ``path`` and open a workspace tab for it.

    Surfaces typed errors via ``QMessageBox`` rather than crashing
    the event loop. R7.4: the Storage_Directory is not modified —
    the loaded baseline appears in the navigation pane like demo
    data, with no file written to disk.
    """

    store = window.baseline_store
    if store is None:
        QMessageBox.warning(
            window,
            "Could not open baseline registry",
            "No baseline store is configured for this session.",
        )
        return None

    try:
        record = store.load_one(path)
    except BaselineSerializationError as exc:
        QMessageBox.warning(
            window,
            "Could not open baseline registry",
            f"{path}\n\n{exc.message}",
        )
        return None
    except BaselineStoreError as exc:
        QMessageBox.warning(
            window,
            "Could not open baseline registry",
            f"{path}\n\n{exc}",
        )
        return None

    # R7.4: the loaded baseline isn't persisted; surfaces in the
    # navigation pane like demo data so the user can inspect it
    # without committing it to the Storage_Directory.
    window.add_baseline(record)
    return record
