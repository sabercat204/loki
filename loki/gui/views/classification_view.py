"""Tree view for one or more :class:`ClassificationRecord` instances."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QLabel,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from loki.models import ClassificationRecord

__all__ = ["ClassificationView"]


class ClassificationView(QWidget):
    """Render a list of classification records as a tree.

    Top-level items are the classification records (by component_id);
    child items are the four axis classifications plus signature info
    and any matched CVEs.
    """

    def __init__(
        self,
        records: list[ClassificationRecord],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        header = QLabel(f"<b>{len(records)} classification record(s)</b>")
        header.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(header)

        tree = QTreeWidget(self)
        tree.setHeaderLabels(["Component / Field", "Value"])
        tree.setColumnWidth(0, 320)
        tree.setEditTriggers(QTreeWidget.EditTrigger.NoEditTriggers)

        for record in records:
            top = QTreeWidgetItem(
                [
                    f"{record.component_id} @ {record.extraction_offset}",
                    f"composite={record.composite_confidence:.2f} "
                    f"needs_review={record.needs_review}",
                ]
            )
            for axis_name, axis in (
                ("type_axis", record.type_axis),
                ("vendor_axis", record.vendor_axis),
                ("security_axis", record.security_axis),
                ("mutability_axis", record.mutability_axis),
            ):
                top.addChild(
                    QTreeWidgetItem(
                        [
                            axis_name,
                            f"{axis.label} (conf={axis.confidence:.2f}, method={axis.method})",
                        ]
                    )
                )
            if record.signature_info is not None:
                sig = record.signature_info
                top.addChild(
                    QTreeWidgetItem(
                        [
                            "signature",
                            f"present={sig.present} verified={sig.verified} "
                            f"signer={sig.signer or '—'}",
                        ]
                    )
                )
            if record.cve_matches:
                top.addChild(QTreeWidgetItem(["cve_matches", ", ".join(record.cve_matches)]))
            tree.addTopLevelItem(top)
            top.setExpanded(True)

        layout.addWidget(tree, 1)
