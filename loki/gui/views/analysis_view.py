"""Analysis view showing ImageAnalysisReport findings and posture."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from loki.models.reports import ImageAnalysisReport

__all__ = ["AnalysisView"]


class AnalysisView(QWidget):
    """Display an ImageAnalysisReport with findings detail tree."""

    def __init__(
        self,
        report: ImageAnalysisReport,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._report = report

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel(
            f"<b>Analysis Report</b> — posture: "
            f"<b>{report.posture_rating.value}</b> — "
            f"{len(report.findings)} finding(s)"
        )
        title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(title)

        meta = QLabel(
            f"report_id: {report.report_id}<br>"
            f"image_id: {report.image_id}<br>"
            f"analysis_version: {report.analysis_version}<br>"
            f"timestamp: {report.timestamp.isoformat()}"
        )
        meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(meta)

        if report.summary.findings_by_severity:
            layout.addWidget(QLabel("<b>Severity distribution</b>"))
            sev_table = QTableWidget(len(report.summary.findings_by_severity), 2, self)
            sev_table.setHorizontalHeaderLabels(["Severity", "Count"])
            sv = sev_table.verticalHeader()
            assert sv is not None
            sv.setVisible(False)
            sev_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            sh = sev_table.horizontalHeader()
            assert sh is not None
            sh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            sh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            for idx, (severity, count) in enumerate(
                sorted(
                    report.summary.findings_by_severity.items(),
                    key=lambda kv: kv[0].value,
                )
            ):
                sev_table.setItem(idx, 0, QTableWidgetItem(severity.value))
                sev_table.setItem(idx, 1, QTableWidgetItem(str(count)))
            sev_table.setMaximumHeight(150)
            layout.addWidget(sev_table)

        layout.addWidget(QLabel("<b>Findings</b>"))
        tree = QTreeWidget(self)
        tree.setHeaderLabels(["Finding", "Detail"])
        tree.setColumnWidth(0, 350)
        tree.setEditTriggers(QTreeWidget.EditTrigger.NoEditTriggers)

        for finding in report.findings:
            top = QTreeWidgetItem(
                [
                    f"[{finding.severity.value}] {finding.category}",
                    finding.title,
                ]
            )
            top.addChild(QTreeWidgetItem(["description", finding.description]))
            top.addChild(QTreeWidgetItem(["recommended_action", finding.recommended_action]))
            top.addChild(QTreeWidgetItem(["component_id", str(finding.component_id)]))
            if finding.evidence.deviation_score is not None:
                ds = finding.evidence.deviation_score
                top.addChild(
                    QTreeWidgetItem(
                        [
                            "deviation_score",
                            f"composite={ds.composite_score:.2f} priority={ds.priority_rank}",
                        ]
                    )
                )
            if finding.evidence.matched_cve:
                top.addChild(QTreeWidgetItem(["matched_cve", finding.evidence.matched_cve]))
            tree.addTopLevelItem(top)

        layout.addWidget(tree, 1)

    @property
    def report(self) -> ImageAnalysisReport:
        return self._report
