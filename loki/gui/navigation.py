"""Left-hand navigation pane: tree view of opened items grouped by kind."""

from __future__ import annotations

from typing import cast

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QWidget

__all__ = ["NavigationGroup", "NavigationPane"]


_GROUP_ORDER: tuple[str, ...] = ("Images", "Baselines", "Reports", "Fleet")


class NavigationGroup:
    """Sentinel class for the four top-level navigation groups."""

    IMAGES = "Images"
    BASELINES = "Baselines"
    REPORTS = "Reports"
    FLEET = "Fleet"


_PLACEHOLDERS: dict[str, str] = {
    "Images": "No images loaded yet",
    "Baselines": "No baselines loaded yet",
    "Reports": "No reports loaded yet",
    "Fleet": "No fleet data loaded yet",
}


class NavigationPane(QTreeWidget):
    """Tree of opened items.

    Top-level items are the four group names from
    :class:`NavigationGroup`. Each child carries a ``Qt.UserRole`` payload
    of ``(group_name, key)`` that the main window uses to focus the
    correct tab on double-click.
    """

    item_activated = pyqtSignal(str, str, str)
    """Emitted as ``(group, key, label)`` when a navigation entry is double-clicked."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setEditTriggers(QTreeWidget.EditTrigger.NoEditTriggers)
        self._groups: dict[str, QTreeWidgetItem] = {}
        for name in _GROUP_ORDER:
            top = QTreeWidgetItem([name])
            top.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.addTopLevelItem(top)
            self._groups[name] = top
            self._refresh_placeholder(name)
        self.expandAll()
        self.itemDoubleClicked.connect(self._on_item_double_clicked)

    def add_entry(self, group: str, key: str, label: str) -> None:
        """Add (or refresh) an entry under ``group`` with the given ``key``.

        If an entry with ``key`` already exists in that group its label is
        updated; otherwise a new child item is appended. Placeholder
        children are removed.
        """

        if group not in self._groups:
            raise ValueError(f"unknown navigation group: {group!r}")
        parent = self._groups[group]
        # Remove placeholder if present.
        self._remove_placeholder(group)
        # Update existing entry if same key.
        for idx in range(parent.childCount()):
            child = parent.child(idx)
            if child is None:  # pragma: no cover - guarded by childCount()
                continue
            stored = child.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(stored, tuple) and stored == (group, key):
                child.setText(0, label)
                return
        new_child = QTreeWidgetItem([label])
        new_child.setData(0, Qt.ItemDataRole.UserRole, (group, key))
        parent.addChild(new_child)
        parent.setExpanded(True)

    def reset(self) -> None:
        """Remove every entry and restore placeholder rows."""
        for name, parent in self._groups.items():
            while parent.childCount() > 0:
                parent.removeChild(parent.child(0))
            self._refresh_placeholder(name)

    def _refresh_placeholder(self, group: str) -> None:
        parent = self._groups[group]
        if parent.childCount() == 0:
            placeholder = QTreeWidgetItem([_PLACEHOLDERS[group]])
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            placeholder.setData(0, Qt.ItemDataRole.UserRole, ("__placeholder__", group))
            parent.addChild(placeholder)
            parent.setExpanded(True)

    def _remove_placeholder(self, group: str) -> None:
        parent = self._groups[group]
        for idx in range(parent.childCount()):
            child = parent.child(idx)
            if child is None:  # pragma: no cover - guarded by childCount()
                continue
            stored = child.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(stored, tuple) and stored[0] == "__placeholder__":
                parent.removeChild(child)
                return

    def _on_item_double_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        stored = item.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(stored, tuple) or stored[0] == "__placeholder__":
            return
        group_name = cast(str, stored[0])
        key = cast(str, stored[1])
        self.item_activated.emit(group_name, key, item.text(0))
