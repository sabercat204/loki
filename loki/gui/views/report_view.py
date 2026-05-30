"""Read-only summary panel for an :class:`ImageAnalysisReport`."""

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

from loki.models import ImageAnalysisReport

__all__ = ["ImageAnalysisReportView"]


class ImageAnalysisReportView(QWidget):
    """Show the report header, severity distribution, and findings list."""

    def __init__(
        self,
        report: ImageAnalysisReport,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._report = report

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel(f"<b>Analysis Report</b> — posture: <b>{report.posture_rating.value}</b>")
        title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(title)

        meta = QLabel(
            f"image_id: {report.image_id}<br>"
            f"analysis_version: {report.analysis_version}<br>"
            f"timestamp: {report.timestamp.isoformat()}"
        )
        meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(meta)

        layout.addWidget(QLabel("<b>Severity distribution</b>"))
        severity_table = QTableWidget(len(report.summary.findings_by_severity), 2, self)
        severity_table.setHorizontalHeaderLabels(["Severity", "Count"])
        sv_header = severity_table.verticalHeader()
        assert sv_header is not None
        sv_header.setVisible(False)
        severity_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        sh = severity_table.horizontalHeader()
        assert sh is not None
        sh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        sh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for idx, (severity, count) in enumerate(
            sorted(report.summary.findings_by_severity.items(), key=lambda kv: kv[0].value)
        ):
            severity_table.setItem(idx, 0, QTableWidgetItem(severity.value))
            severity_table.setItem(idx, 1, QTableWidgetItem(str(count)))
        layout.addWidget(severity_table)

        layout.addWidget(QLabel("<b>Findings</b>"))
        findings_table = QTableWidget(len(report.findings), 4, self)
        findings_table.setHorizontalHeaderLabels(
            ["Severity", "Category", "Title", "Recommended action"]
        )
        fv_header = findings_table.verticalHeader()
        assert fv_header is not None
        fv_header.setVisible(False)
        findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        fh = findings_table.horizontalHeader()
        assert fh is not None
        fh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        fh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        fh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        fh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for idx, finding in enumerate(report.findings):
            findings_table.setItem(idx, 0, QTableWidgetItem(finding.severity.value))
            findings_table.setItem(idx, 1, QTableWidgetItem(finding.category))
            findings_table.setItem(idx, 2, QTableWidgetItem(finding.title))
            findings_table.setItem(idx, 3, QTableWidgetItem(finding.recommended_action))
        layout.addWidget(findings_table, 1)

    @property
    def report(self) -> ImageAnalysisReport:
        return self._report
