"""Public API for the Fleet analysis engine."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from loki.fleet.aggregation import (
    compute_common_findings,
    compute_cve_rollup,
    compute_posture_distribution,
    compute_risk_ranking,
    detect_outliers,
)
from loki.fleet.errors import FleetConfigError
from loki.models.firmware import LOKI_NAMESPACE
from loki.models.reports import FleetAnalysisReport, ImageAnalysisReport

__all__: list[str] = ["analyze_fleet"]


def analyze_fleet(
    reports: Sequence[ImageAnalysisReport],
    fleet_id: str,
) -> FleetAnalysisReport:
    """Aggregate per-image reports into a fleet-level analysis report.

    Raises FleetConfigError if reports is empty.
    """
    if not reports:
        raise FleetConfigError("Cannot analyze empty fleet: no reports provided")

    timestamp = datetime.now(tz=UTC)
    report_id = uuid.uuid5(LOKI_NAMESPACE, f"{fleet_id}:{timestamp.isoformat()}")

    fleet_posture = compute_posture_distribution(reports)
    common_findings = compute_common_findings(reports)
    systemic_risks = compute_cve_rollup(reports)
    outlier_images = detect_outliers(reports, fleet_posture)
    recommended_actions = compute_risk_ranking(reports)

    return FleetAnalysisReport(
        report_id=report_id,
        timestamp=timestamp,
        fleet_id=fleet_id,
        image_count=len(reports),
        fleet_posture=fleet_posture,
        common_findings=common_findings,
        outlier_images=outlier_images,
        systemic_risks=systemic_risks,
        recommended_actions=recommended_actions,
    )
