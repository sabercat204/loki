"""Read-only metadata table for a single :class:`FirmwareImage`."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from loki.models import FirmwareImage

__all__ = ["FirmwareImageView"]


class FirmwareImageView(QWidget):
    """Two-column metadata table plus a placeholder note about extraction.

    The placeholder is honest: this is scaffolding. The extraction
    pipeline that would populate components, manifests, and
    classifications is not yet implemented (scope C).
    """

    def __init__(self, image: FirmwareImage, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._image = image

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel(f"<b>{image.file_path}</b>")
        title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(title)

        table = QTableWidget(self)
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Field", "Value"])
        v_header = table.verticalHeader()
        assert v_header is not None
        v_header.setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        h_header = table.horizontalHeader()
        assert h_header is not None
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        rows: list[tuple[str, str]] = [
            ("image_id", str(image.image_id) if image.image_id is not None else "—"),
            ("file_path", image.file_path),
            ("file_hash", image.file_hash),
            ("file_size", f"{image.file_size:,} bytes"),
            ("vendor", image.vendor or "—"),
            ("model", image.model or "—"),
            ("firmware_version", image.firmware_version or "—"),
            (
                "extraction_timestamp",
                image.extraction_timestamp.isoformat() if image.extraction_timestamp else "—",
            ),
        ]
        table.setRowCount(len(rows))
        for row_idx, (field, value) in enumerate(rows):
            table.setItem(row_idx, 0, QTableWidgetItem(field))
            table.setItem(row_idx, 1, QTableWidgetItem(value))
        layout.addWidget(table, 1)

        note = QLabel(
            "<i>Extraction pipeline not yet implemented. "
            "Use <b>View → Load Demo Data</b> to preview the workflow with synthetic data.</i>"
        )
        note.setWordWrap(True)
        layout.addWidget(note)

    @property
    def image(self) -> FirmwareImage:
        """Return the firmware image rendered by this view."""
        return self._image
