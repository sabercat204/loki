"""Fleet analysis view showing FleetAnalysisReport posture and rollups."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHeaderView,
    QLabel,
    QListWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from loki.models.reports import FleetAnalysisReport

__all__ = ["FleetAnalysisView"]


class FleetAnalysisView(QWidget):
    """Display a FleetAnalysisReport with posture, outliers, and risks."""

    def __init__(
        self,
        report: FleetAnalysisReport,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._report = report

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel(
            f"<b>Fleet Analysis Report</b> — fleet: <b>{report.fleet_id}</b> — "
            f"{report.image_count} image(s)"
        )
        title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(title)

        meta = QLabel(f"report_id: {report.report_id}<br>timestamp: {report.timestamp.isoformat()}")
        meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(meta)

        layout.addWidget(QLabel("<b>Posture distribution</b>"))
        posture_table = QTableWidget(len(report.fleet_posture), 2, self)
        posture_table.setHorizontalHeaderLabels(["Posture", "Count"])
        pv = posture_table.verticalHeader()
        assert pv is not None
        pv.setVisible(False)
        posture_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        ph = posture_table.horizontalHeader()
        assert ph is not None
        ph.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        ph.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for idx, (rating, count) in enumerate(report.fleet_posture.items()):
            posture_table.setItem(idx, 0, QTableWidgetItem(rating.value))
            posture_table.setItem(idx, 1, QTableWidgetItem(str(count)))
        posture_table.setMaximumHeight(160)
        layout.addWidget(posture_table)

        if report.outlier_images:
            layout.addWidget(QLabel(f"<b>Outlier images ({len(report.outlier_images)})</b>"))
            outlier_list = QListWidget(self)
            for oid in report.outlier_images:
                outlier_list.addItem(str(oid))
            outlier_list.setMaximumHeight(100)
            layout.addWidget(outlier_list)

        if report.systemic_risks:
            layout.addWidget(QLabel(f"<b>Systemic risks ({len(report.systemic_risks)})</b>"))
            risk_list = QListWidget(self)
            for risk in report.systemic_risks:
                risk_list.addItem(risk)
            risk_list.setMaximumHeight(100)
            layout.addWidget(risk_list)

        if report.common_findings:
            layout.addWidget(QLabel(f"<b>Common findings ({len(report.common_findings)})</b>"))
            common_table = QTableWidget(len(report.common_findings), 3, self)
            common_table.setHorizontalHeaderLabels(["Severity", "Category", "Title"])
            cv = common_table.verticalHeader()
            assert cv is not None
            cv.setVisible(False)
            common_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            ch = common_table.horizontalHeader()
            assert ch is not None
            ch.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            ch.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            ch.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
            for idx, finding in enumerate(report.common_findings):
                common_table.setItem(idx, 0, QTableWidgetItem(finding.severity.value))
                common_table.setItem(idx, 1, QTableWidgetItem(finding.category))
                common_table.setItem(idx, 2, QTableWidgetItem(finding.title))
            layout.addWidget(common_table)

        if report.recommended_actions:
            layout.addWidget(
                QLabel(f"<b>Recommended actions ({len(report.recommended_actions)})</b>")
            )
            actions_table = QTableWidget(len(report.recommended_actions), 3, self)
            actions_table.setHorizontalHeaderLabels(["Action type", "Description", "Reference"])
            av = actions_table.verticalHeader()
            assert av is not None
            av.setVisible(False)
            actions_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            ah = actions_table.horizontalHeader()
            assert ah is not None
            ah.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            ah.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            ah.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            for idx, action in enumerate(report.recommended_actions):
                actions_table.setItem(idx, 0, QTableWidgetItem(action.action_type))
                actions_table.setItem(idx, 1, QTableWidgetItem(action.description))
                actions_table.setItem(idx, 2, QTableWidgetItem(action.reference or "—"))
            layout.addWidget(actions_table, 1)
        elif not report.common_findings:
            layout.addStretch(1)

    @property
    def report(self) -> FleetAnalysisReport:
        return self._report
