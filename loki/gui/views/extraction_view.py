"""Read-only widget that renders an ``ExtractionManifest`` for the GUI.

Previously a ``(scaffold)`` placeholder; now backed by the real
extraction subsystem. When constructed with ``manifest=None`` it
falls back to the original placeholder so the navigation pane can
still surface "no extraction yet" state.
"""

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

from loki.models import ExtractionManifest

__all__ = ["ExtractionView"]

_HASH_PREFIX_LEN: int = 12


class ExtractionView(QWidget):
    """Render an :class:`ExtractionManifest` as a read-only summary."""

    def __init__(
        self,
        manifest: ExtractionManifest | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._manifest = manifest

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        if manifest is None:
            self._build_placeholder(layout)
            return

        self._build_summary(layout, manifest)
        self._build_components_table(layout, manifest)
        self._build_errors_section(layout, manifest)

    # ------------------------------------------------------------------
    # Placeholder fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _build_placeholder(layout: QVBoxLayout) -> None:
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        message = QLabel(
            "<b>Extraction view</b><br><br>"
            "No extraction has been run for this image yet.<br>"
            "Use <b>View → Extract Firmware Components…</b> to run "
            "the pipeline against the currently selected image."
        )
        message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        message.setWordWrap(True)
        layout.addWidget(message)

    # ------------------------------------------------------------------
    # Populated layout
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(layout: QVBoxLayout, manifest: ExtractionManifest) -> None:
        title = QLabel(f"<b>Extraction Manifest</b> — extractor {manifest.extractor_version}")
        title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(title)

        meta = QLabel(
            f"image_id: {manifest.source_image.image_id}<br>"
            f"file_path: {manifest.source_image.file_path}<br>"
            f"file_size: {manifest.source_image.file_size:,} bytes<br>"
            f"timestamp: {manifest.extraction_timestamp.isoformat()}<br>"
            f"components: {manifest.total_components} | "
            f"errors: {len(manifest.extraction_errors)}"
        )
        meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(meta)

    @staticmethod
    def _build_components_table(layout: QVBoxLayout, manifest: ExtractionManifest) -> None:
        layout.addWidget(QLabel("<b>Components</b>"))
        table = QTableWidget(len(manifest.components), 5)
        table.setHorizontalHeaderLabels(["Offset", "Size", "Type hint", "Name", "Hash (12)"])
        v_header = table.verticalHeader()
        assert v_header is not None
        v_header.setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        h_header = table.horizontalHeader()
        assert h_header is not None
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        h_header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        for row, component in enumerate(manifest.components):
            table.setItem(row, 0, QTableWidgetItem(component.offset))
            table.setItem(row, 1, QTableWidgetItem(f"{component.size:,}"))
            table.setItem(row, 2, QTableWidgetItem(component.component_type_hint or "—"))
            table.setItem(row, 3, QTableWidgetItem(component.name or "—"))
            table.setItem(row, 4, QTableWidgetItem(component.raw_hash[:_HASH_PREFIX_LEN]))
        layout.addWidget(table, 1)

    @staticmethod
    def _build_errors_section(layout: QVBoxLayout, manifest: ExtractionManifest) -> None:
        if not manifest.extraction_errors:
            return
        layout.addWidget(QLabel("<b>Extraction errors</b>"))
        table = QTableWidget(len(manifest.extraction_errors), 2)
        table.setHorizontalHeaderLabels(["Component ID", "Message"])
        v_header = table.verticalHeader()
        assert v_header is not None
        v_header.setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        h_header = table.horizontalHeader()
        assert h_header is not None
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for row, error in enumerate(manifest.extraction_errors):
            table.setItem(
                row,
                0,
                QTableWidgetItem(str(error.component_id) if error.component_id else "—"),
            )
            table.setItem(row, 1, QTableWidgetItem(error.error_message))
        layout.addWidget(table)

    @property
    def manifest(self) -> ExtractionManifest | None:
        """Return the manifest rendered by this view (or ``None``)."""
        return self._manifest
