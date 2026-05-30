"""Tests for the analyze_fleet public API."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from loki.fleet.api import analyze_fleet
from loki.fleet.errors import FleetConfigError
from loki.models.analysis import DeviationScore, FindingEvidence, FindingRecord
from loki.models.enums import (
    MutabilityChange,
    PostureRating,
    SecurityDirection,
    SeverityLevel,
    SignatureDelta,
)
from loki.models.firmware import FirmwareImage
from loki.models.reports import ImageAnalysisReport


def _make_image(
    *,
    posture: PostureRating = PostureRating.BASELINE,
    findings: list[FindingRecord] | None = None,
) -> ImageAnalysisReport:
    file_hash = uuid.uuid4().hex + uuid.uuid4().hex[:32]
    image = FirmwareImage(
        file_path="/firmware/test.bin",
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
        findings=findings or [],
    )


def _make_finding(
    *,
    severity: SeverityLevel = SeverityLevel.HIGH,
    matched_cve: str | None = None,
) -> FindingRecord:
    return FindingRecord(
        finding_id=uuid.uuid4(),
        component_id=uuid.uuid4(),
        severity=severity,
        category="classification_mismatch",
        title="test finding",
        description="desc",
        evidence=FindingEvidence(
            matched_cve=matched_cve,
            deviation_score=DeviationScore(
                base_severity=severity,
                component_criticality=0.5,
                security_direction=SecurityDirection.DEGRADED,
                signature_delta=SignatureDelta.NONE,
                cve_introduced=False,
                mutability_change=MutabilityChange.NONE,
                composite_score=5.0,
                priority_rank=1,
            ),
        ),
        recommended_action="Investigate",
    )


class TestAnalyzeFleet:
    def test_success_path(self) -> None:
        reports = [
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.DEGRADED),
        ]
        result = analyze_fleet(reports=reports, fleet_id="test-fleet")

        assert result.fleet_id == "test-fleet"
        assert result.image_count == 2
        assert sum(result.fleet_posture.values()) == 2
        assert result.report_id is not None
        assert result.timestamp is not None

    def test_empty_fleet_raises(self) -> None:
        with pytest.raises(FleetConfigError, match="empty fleet"):
            analyze_fleet(reports=[], fleet_id="empty")

    def test_single_image(self) -> None:
        reports = [_make_image()]
        result = analyze_fleet(reports=reports, fleet_id="solo")
        assert result.image_count == 1
        assert result.outlier_images == []

    def test_determinism(self) -> None:
        reports = [
            _make_image(posture=PostureRating.BASELINE, findings=[_make_finding()]),
            _make_image(posture=PostureRating.DEGRADED, findings=[_make_finding()]),
        ]
        r1 = analyze_fleet(reports=reports, fleet_id="det")
        r2 = analyze_fleet(reports=reports, fleet_id="det")
        assert r1.image_count == r2.image_count
        assert r1.fleet_posture == r2.fleet_posture
        assert r1.common_findings == r2.common_findings
        assert r1.outlier_images == r2.outlier_images
        assert r1.systemic_risks == r2.systemic_risks

    def test_cve_rollup_populated(self) -> None:
        finding = _make_finding(matched_cve="CVE-2024-9999")
        reports = [
            _make_image(findings=[finding]),
            _make_image(findings=[finding]),
        ]
        result = analyze_fleet(reports=reports, fleet_id="cve-test")
        assert len(result.systemic_risks) == 1
        assert "CVE-2024-9999" in result.systemic_risks[0]

    def test_fleet_posture_all_ratings_present(self) -> None:
        reports = [_make_image()]
        result = analyze_fleet(reports=reports, fleet_id="full-posture")
        for rating in PostureRating:
            assert rating in result.fleet_posture
