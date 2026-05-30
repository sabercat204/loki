"""Central tabbed workspace where opened items are rendered."""

from __future__ import annotations

from PyQt6.QtWidgets import QTabWidget, QWidget

__all__ = ["Workspace"]


class Workspace(QTabWidget):
    """A ``QTabWidget`` with closable tabs and a tiny convenience API.

    All tabs are closable via the ``X`` button. Internally we track tabs
    by an opaque ``key`` so navigation can focus an existing tab instead
    of opening a duplicate.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setTabsClosable(True)
        self.setMovable(True)
        self._keys: dict[str, QWidget] = {}
        self.tabCloseRequested.connect(self._on_close_requested)

    def open_tab(self, key: str, title: str, widget: QWidget) -> int:
        """Add ``widget`` as a new tab, or focus the existing tab for ``key``.

        Returns the index of the (focused or newly-added) tab.
        """

        existing = self._keys.get(key)
        if existing is not None:
            idx = self.indexOf(existing)
            if idx != -1:
                self.setCurrentIndex(idx)
                return idx
        idx = self.addTab(widget, title)
        self._keys[key] = widget
        self.setCurrentIndex(idx)
        return idx

    def has_tab(self, key: str) -> bool:
        """Return whether a tab with ``key`` is currently open."""
        widget = self._keys.get(key)
        return widget is not None and self.indexOf(widget) != -1

    def reset(self) -> None:
        """Close every tab. Used by ``View → Reset Workspace``."""
        while self.count() > 0:
            self.removeTab(0)
        self._keys.clear()

    def _on_close_requested(self, index: int) -> None:
        widget = self.widget(index)
        if widget is None:
            return
        # Drop from key map (any matching entries).
        stale_keys = [k for k, w in self._keys.items() if w is widget]
        for k in stale_keys:
            del self._keys[k]
        self.removeTab(index)
        widget.deleteLater()
