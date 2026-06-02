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

from loki.models.analysis import FindingRecord
from loki.models.baseline import BaselineComparison
from loki.models.reports import ImageAnalysisReport

__all__ = ["AnalysisView"]


class AnalysisView(QWidget):
    """Display an ImageAnalysisReport with findings detail tree.

    Surfaces every public field on :class:`ImageAnalysisReport`:

    - Posture, summary counts, identifying metadata.
    - Severity distribution (table).
    - Findings (tree) with the full per-finding evidence shape:
      classification_record axis breakdown (replaces the dedicated
      ClassificationView removed in OT-LK-004 wave A); deviation_score
      full per-axis breakdown (analysis-engine R9.1); matched
      rule/CVE/signature; raw_indicators.
    - Recommended actions (table).
    - Baseline comparison (sub-section showing summary counts +
      deviation list when ``report.baseline_comparison`` is populated).
    """

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
            tree.addTopLevelItem(_build_finding_item(finding))

        layout.addWidget(tree, 1)

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
            actions_table.setMaximumHeight(200)
            layout.addWidget(actions_table)

        if report.baseline_comparison is not None:
            layout.addWidget(_build_baseline_comparison_widget(report.baseline_comparison, self))

    @property
    def report(self) -> ImageAnalysisReport:
        return self._report


def _build_finding_item(finding: FindingRecord) -> QTreeWidgetItem:
    """Build a top-level QTreeWidgetItem for a single finding.

    Renders every populated field on the finding plus its
    :class:`FindingEvidence` payload — classification axes, deviation
    score breakdown, matched rule/CVE/signature, raw indicators.
    """
    top = QTreeWidgetItem(
        [
            f"[{finding.severity.value}] {finding.category}",
            finding.title,
        ]
    )
    top.addChild(QTreeWidgetItem(["finding_id", str(finding.finding_id)]))
    top.addChild(QTreeWidgetItem(["component_id", str(finding.component_id)]))
    top.addChild(QTreeWidgetItem(["description", finding.description]))
    top.addChild(QTreeWidgetItem(["recommended_action", finding.recommended_action]))

    evidence = finding.evidence
    if evidence.classification_record is not None:
        record = evidence.classification_record
        cls_node = QTreeWidgetItem(
            [
                "classification_record",
                f"composite={record.composite_confidence:.2f} needs_review={record.needs_review}",
            ]
        )
        for axis_name, axis in (
            ("type_axis", record.type_axis),
            ("vendor_axis", record.vendor_axis),
            ("security_axis", record.security_axis),
            ("mutability_axis", record.mutability_axis),
        ):
            cls_node.addChild(
                QTreeWidgetItem(
                    [
                        axis_name,
                        f"{axis.label} (conf={axis.confidence:.2f}, method={axis.method})",
                    ]
                )
            )
        if record.signature_info is not None:
            sig = record.signature_info
            cls_node.addChild(
                QTreeWidgetItem(
                    [
                        "signature",
                        f"present={sig.present} verified={sig.verified} signer={sig.signer or '—'}",
                    ]
                )
            )
        if record.cve_matches:
            cls_node.addChild(QTreeWidgetItem(["cve_matches", ", ".join(record.cve_matches)]))
        top.addChild(cls_node)

    if evidence.deviation_score is not None:
        ds = evidence.deviation_score
        ds_node = QTreeWidgetItem(
            [
                "deviation_score",
                f"composite={ds.composite_score:.2f} priority={ds.priority_rank}",
            ]
        )
        ds_node.addChild(QTreeWidgetItem(["base_severity", ds.base_severity.value]))
        ds_node.addChild(
            QTreeWidgetItem(["component_criticality", f"{ds.component_criticality:.2f}"])
        )
        ds_node.addChild(QTreeWidgetItem(["security_direction", ds.security_direction.value]))
        ds_node.addChild(QTreeWidgetItem(["signature_delta", ds.signature_delta.value]))
        ds_node.addChild(QTreeWidgetItem(["cve_introduced", str(ds.cve_introduced)]))
        ds_node.addChild(QTreeWidgetItem(["mutability_change", ds.mutability_change.value]))
        top.addChild(ds_node)

    if evidence.matched_rule is not None:
        top.addChild(QTreeWidgetItem(["matched_rule", evidence.matched_rule]))
    if evidence.matched_cve is not None:
        top.addChild(QTreeWidgetItem(["matched_cve", evidence.matched_cve]))
    if evidence.matched_signature is not None:
        top.addChild(QTreeWidgetItem(["matched_signature", evidence.matched_signature]))
    if evidence.raw_indicators:
        top.addChild(QTreeWidgetItem(["raw_indicators", ", ".join(evidence.raw_indicators)]))

    return top


def _build_baseline_comparison_widget(
    comparison: BaselineComparison,
    parent: QWidget,
) -> QWidget:
    """Build a section widget for the optional baseline_comparison field."""
    container = QWidget(parent)
    container_layout = QVBoxLayout(container)
    container_layout.setContentsMargins(0, 0, 0, 0)

    container_layout.addWidget(
        QLabel(
            f"<b>Baseline comparison</b> — baseline_id: {comparison.baseline_id} — "
            f"{len(comparison.deviations)} deviation(s)"
        )
    )

    if comparison.summary:
        summary_table = QTableWidget(len(comparison.summary), 2, container)
        summary_table.setHorizontalHeaderLabels(["Delta type", "Count"])
        sv = summary_table.verticalHeader()
        assert sv is not None
        sv.setVisible(False)
        summary_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        sh = summary_table.horizontalHeader()
        assert sh is not None
        sh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        sh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for idx, (delta, count) in enumerate(
            sorted(comparison.summary.items(), key=lambda kv: kv[0].value)
        ):
            summary_table.setItem(idx, 0, QTableWidgetItem(delta.value))
            summary_table.setItem(idx, 1, QTableWidgetItem(str(count)))
        summary_table.setMaximumHeight(140)
        container_layout.addWidget(summary_table)

    if comparison.deviations:
        deviations_table = QTableWidget(len(comparison.deviations), 3, container)
        deviations_table.setHorizontalHeaderLabels(["Delta type", "Component", "Description"])
        dv = deviations_table.verticalHeader()
        assert dv is not None
        dv.setVisible(False)
        deviations_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        dh = deviations_table.horizontalHeader()
        assert dh is not None
        dh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        dh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        dh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for idx, dev in enumerate(comparison.deviations):
            deviations_table.setItem(idx, 0, QTableWidgetItem(dev.delta_type.value))
            deviations_table.setItem(idx, 1, QTableWidgetItem(str(dev.component_id)))
            deviations_table.setItem(idx, 2, QTableWidgetItem(dev.description))
        deviations_table.setMaximumHeight(220)
        container_layout.addWidget(deviations_table)

    return container
