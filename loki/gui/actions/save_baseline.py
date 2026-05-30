"""View → Save Baseline… action (R7.5-R7.7).

Saves the active workspace tab's :class:`BaselineRecord` to the
Storage_Directory via :meth:`BaselineStore.save`. Handles the two
typed-error confirmations the spec mandates:

- :class:`BaselineAlreadyExistsError` → prompt to overwrite
  (``force=True`` on confirmation, R7.6).
- :class:`BaselineConcurrentModificationError` → error dialog
  naming the path; no automatic retry (R7.7).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QMessageBox

from loki.baseline import (
    BaselineAlreadyExistsError,
    BaselineConcurrentModificationError,
    BaselineStoreError,
)
from loki.models import BaselineRecord

if TYPE_CHECKING:
    from loki.gui.main_window import MainWindow

__all__ = ["save_baseline"]


def save_baseline(window: MainWindow, record: BaselineRecord) -> Path | None:
    """Save ``record`` via the window's :class:`BaselineStore`.

    Returns the destination path on success, or ``None`` if the user
    cancelled an overwrite prompt or a typed error precluded the
    save. Surfaces other errors via ``QMessageBox.warning``.
    """

    store = window.baseline_store
    if store is None:
        QMessageBox.warning(
            window,
            "Could not save baseline",
            "No baseline store is configured for this session.",
        )
        return None

    try:
        return store.save(record)
    except BaselineAlreadyExistsError as exc:
        # R7.6: prompt to overwrite. ``force=True`` skips both the
        # existence check (R5.3) and the mtime check (R5.2).
        button = QMessageBox.question(
            window,
            "Overwrite existing baseline?",
            f"A Baseline_File already exists at:\n{exc.path}\n\nOverwrite it?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if button != QMessageBox.StandardButton.Yes:
            return None
        try:
            return store.save(record, force=True)
        except BaselineStoreError as exc2:
            QMessageBox.warning(
                window,
                "Could not save baseline",
                str(exc2),
            )
            return None
    except BaselineConcurrentModificationError as exc:
        # R7.7: error dialog, no automatic retry. The user can
        # re-open the registry, reload the baseline, and try again
        # if they want to proceed despite the conflict.
        QMessageBox.warning(
            window,
            "Concurrent modification detected",
            (
                f"The Baseline_File at:\n{exc.path}\n\n"
                "was modified by another process since this session "
                "loaded it. The save was aborted. Reload the registry "
                "to pick up the latest contents."
            ),
        )
        return None
    except BaselineStoreError as exc:
        QMessageBox.warning(
            window,
            "Could not save baseline",
            str(exc),
        )
        return None
