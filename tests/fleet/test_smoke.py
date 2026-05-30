"""End-to-end smoke test for fleet analysis."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from loki.fleet.api import analyze_fleet
from loki.models.analysis import (
    DeviationScore,
    FindingEvidence,
    FindingRecord,
)
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
    idx: int,
    *,
    posture: PostureRating,
    findings: list[FindingRecord],
) -> ImageAnalysisReport:
    file_hash = f"{idx:064x}"
    image = FirmwareImage(
        file_path=f"/firmware/device-{idx}.bin",
        file_hash=file_hash,
        file_size=2048,
    )
    assert image.image_id is not None
    return ImageAnalysisReport(
        report_id=uuid.uuid4(),
        timestamp=datetime(2025, 6, 1, tzinfo=UTC),
        analysis_version="1.0.0",
        image_id=image.image_id,
        image_metadata=image,
        posture_rating=posture,
        findings=findings,
    )


def _common_finding(title: str = "Unsigned driver loaded") -> FindingRecord:
    return FindingRecord(
        finding_id=uuid.uuid4(),
        component_id=uuid.uuid4(),
        severity=SeverityLevel.HIGH,
        category="classification_mismatch",
        title=title,
        description="Driver is unsigned in target but signed in baseline",
        evidence=FindingEvidence(
            matched_cve="CVE-2024-5678",
            deviation_score=DeviationScore(
                base_severity=SeverityLevel.HIGH,
                component_criticality=0.8,
                security_direction=SecurityDirection.DEGRADED,
                signature_delta=SignatureDelta.LOST,
                cve_introduced=True,
                mutability_change=MutabilityChange.NONE,
                composite_score=7.5,
                priority_rank=1,
            ),
        ),
        recommended_action="Re-sign or remove the driver",
    )


def _critical_finding() -> FindingRecord:
    return FindingRecord(
        finding_id=uuid.uuid4(),
        component_id=uuid.uuid4(),
        severity=SeverityLevel.CRITICAL,
        category="classification_mismatch",
        title="Rootkit signature detected",
        description="Known malicious pattern found",
        evidence=FindingEvidence(
            deviation_score=DeviationScore(
                base_severity=SeverityLevel.CRITICAL,
                component_criticality=1.0,
                security_direction=SecurityDirection.DEGRADED,
                signature_delta=SignatureDelta.LOST,
                cve_introduced=False,
                mutability_change=MutabilityChange.BECAME_MUTABLE,
                composite_score=9.8,
                priority_rank=1,
            ),
        ),
        recommended_action="Isolate device immediately",
    )


def test_smoke_fleet_analysis() -> None:
    """E2E: 5 images with varying postures, common findings, outlier, CVE."""
    common = _common_finding()
    reports = [
        _make_image(0, posture=PostureRating.BASELINE, findings=[]),
        _make_image(1, posture=PostureRating.BASELINE, findings=[common]),
        _make_image(2, posture=PostureRating.DEGRADED, findings=[common]),
        _make_image(
            3,
            posture=PostureRating.AT_RISK,
            findings=[common, _critical_finding()],
        ),
        _make_image(
            4,
            posture=PostureRating.COMPROMISED,
            findings=[common, _critical_finding(), _critical_finding()],
        ),
    ]

    result = analyze_fleet(reports=reports, fleet_id="smoke-fleet")

    assert result.fleet_id == "smoke-fleet"
    assert result.image_count == 5

    assert result.fleet_posture[PostureRating.BASELINE] == 2
    assert result.fleet_posture[PostureRating.DEGRADED] == 1
    assert result.fleet_posture[PostureRating.AT_RISK] == 1
    assert result.fleet_posture[PostureRating.COMPROMISED] == 1
    assert sum(result.fleet_posture.values()) == 5

    assert len(result.common_findings) >= 1
    assert any(
        "fleet_count=" in ind for f in result.common_findings for ind in f.evidence.raw_indicators
    )

    assert len(result.outlier_images) >= 1
    input_ids = {r.image_id for r in reports}
    for oid in result.outlier_images:
        assert oid in input_ids

    assert len(result.systemic_risks) >= 1
    assert any("CVE-2024-5678" in risk for risk in result.systemic_risks)

    assert len(result.recommended_actions) >= 1
    assert result.recommended_actions[0].action_type == "INVESTIGATE"
