"""Determinism and backward-compatibility tests for fleet analysis."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from loki.fleet.api import analyze_fleet
from loki.models.enums import PostureRating
from loki.models.firmware import FirmwareImage
from loki.models.reports import ImageAnalysisReport


def _make_image(
    idx: int, *, posture: PostureRating = PostureRating.BASELINE
) -> ImageAnalysisReport:
    file_hash = f"{idx:064x}"
    image = FirmwareImage(
        file_path=f"/firmware/img-{idx}.bin",
        file_hash=file_hash,
        file_size=1024,
    )
    assert image.image_id is not None
    return ImageAnalysisReport(
        report_id=uuid.uuid4(),
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        analysis_version="1.0.0",
        image_id=image.image_id,
        image_metadata=image,
        posture_rating=posture,
        findings=[],
    )


class TestDeterminism:
    def test_same_inputs_same_output_modulo_timestamp(self) -> None:
        reports = [
            _make_image(0, posture=PostureRating.BASELINE),
            _make_image(1, posture=PostureRating.DEGRADED),
            _make_image(2, posture=PostureRating.AT_RISK),
        ]
        r1 = analyze_fleet(reports=reports, fleet_id="det")
        r2 = analyze_fleet(reports=reports, fleet_id="det")

        assert r1.fleet_id == r2.fleet_id
        assert r1.image_count == r2.image_count
        assert r1.fleet_posture == r2.fleet_posture
        assert r1.common_findings == r2.common_findings
        assert r1.outlier_images == r2.outlier_images
        assert r1.systemic_risks == r2.systemic_risks
        assert r1.recommended_actions == r2.recommended_actions

    def test_all_empty_findings_produces_valid_report(self) -> None:
        reports = [_make_image(i) for i in range(3)]
        result = analyze_fleet(reports=reports, fleet_id="empty-findings")

        assert result.image_count == 3
        assert result.common_findings == []
        assert result.systemic_risks == []
        assert result.outlier_images == []
        assert sum(result.fleet_posture.values()) == 3
        assert len(result.recommended_actions) == 3
