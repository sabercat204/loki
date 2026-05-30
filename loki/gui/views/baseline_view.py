"""Read-only summary for a :class:`BaselineRecord` plus optional comparison."""

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

from loki.models import BaselineComparison, BaselineRecord

__all__ = ["BaselineView"]


class BaselineView(QWidget):
    """Show baseline metadata, manifest size, and (optionally) a comparison summary."""

    def __init__(
        self,
        baseline: BaselineRecord,
        comparison: BaselineComparison | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._baseline = baseline
        self._comparison = comparison

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel(f"<b>{baseline.name}</b>")
        title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(title)

        meta_table = self._build_metadata_table(baseline)
        layout.addWidget(meta_table)

        if comparison is not None:
            layout.addWidget(QLabel("<b>Baseline comparison summary</b>"))
            layout.addWidget(self._build_comparison_table(comparison))
        else:
            layout.addWidget(QLabel("<i>No comparison loaded for this baseline.</i>"))
        layout.addStretch(1)

    @staticmethod
    def _build_metadata_table(baseline: BaselineRecord) -> QTableWidget:
        rows: list[tuple[str, str]] = [
            ("baseline_id", str(baseline.baseline_id)),
            ("vendor", baseline.vendor),
            ("model", baseline.model),
            ("firmware_version", baseline.firmware_version),
            ("baseline_version", baseline.baseline_version),
            ("source_image_hash", baseline.source_image_hash),
            ("created_timestamp", baseline.created_timestamp.isoformat()),
            ("manifest_size", f"{len(baseline.component_manifest)} components"),
            ("notes", baseline.notes or "—"),
        ]
        table = QTableWidget(len(rows), 2)
        table.setHorizontalHeaderLabels(["Field", "Value"])
        v_header = table.verticalHeader()
        assert v_header is not None
        v_header.setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        h = table.horizontalHeader()
        assert h is not None
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for row_idx, (field, value) in enumerate(rows):
            table.setItem(row_idx, 0, QTableWidgetItem(field))
            table.setItem(row_idx, 1, QTableWidgetItem(value))
        return table

    @staticmethod
    def _build_comparison_table(comparison: BaselineComparison) -> QTableWidget:
        summary = comparison.summary
        ordered = sorted(summary.items(), key=lambda kv: kv[0].value)
        table = QTableWidget(len(ordered) + 1, 2)
        table.setHorizontalHeaderLabels(["Delta type", "Count"])
        v_header = table.verticalHeader()
        assert v_header is not None
        v_header.setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        h = table.horizontalHeader()
        assert h is not None
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for idx, (delta_type, count) in enumerate(ordered):
            table.setItem(idx, 0, QTableWidgetItem(delta_type.value))
            table.setItem(idx, 1, QTableWidgetItem(str(count)))
        total_idx = len(ordered)
        total_label = QTableWidgetItem("TOTAL")
        total_count = QTableWidgetItem(str(len(comparison.deviations)))
        total_label.setFlags(total_label.flags() & ~Qt.ItemFlag.ItemIsEditable)
        total_count.setFlags(total_count.flags() & ~Qt.ItemFlag.ItemIsEditable)
        table.setItem(total_idx, 0, total_label)
        table.setItem(total_idx, 1, total_count)
        return table

    @property
    def baseline(self) -> BaselineRecord:
        return self._baseline
