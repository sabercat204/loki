"""Performance test for fleet analysis (R10.2: 100 images x 1000 findings < 10s)."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

import pytest

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

_POSTURES = list(PostureRating)
_SEVERITIES = list(SeverityLevel)


def _make_finding(idx: int) -> FindingRecord:
    severity = _SEVERITIES[idx % len(_SEVERITIES)]
    return FindingRecord(
        finding_id=uuid.uuid4(),
        component_id=uuid.uuid4(),
        severity=severity,
        category="classification_mismatch",
        title=f"Finding pattern {idx % 10}",
        description="perf test",
        evidence=FindingEvidence(
            matched_cve=f"CVE-2024-{idx % 50:04d}" if idx % 3 == 0 else None,
            deviation_score=DeviationScore(
                base_severity=severity,
                component_criticality=0.5,
                security_direction=SecurityDirection.DEGRADED,
                signature_delta=SignatureDelta.NONE,
                cve_introduced=False,
                mutability_change=MutabilityChange.NONE,
                composite_score=float(idx % 10),
                priority_rank=1,
            ),
        ),
        recommended_action="investigate",
    )


def _make_image(idx: int) -> ImageAnalysisReport:
    file_hash = f"{idx:064x}"
    image = FirmwareImage(
        file_path=f"/firmware/image-{idx}.bin",
        file_hash=file_hash,
        file_size=1024 * (idx + 1),
    )
    assert image.image_id is not None
    findings = [_make_finding(f_idx) for f_idx in range(1000)]
    return ImageAnalysisReport(
        report_id=uuid.uuid4(),
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        analysis_version="1.0.0",
        image_id=image.image_id,
        image_metadata=image,
        posture_rating=_POSTURES[idx % len(_POSTURES)],
        findings=findings,
    )


@pytest.mark.slow
def test_fleet_performance_100_images() -> None:
    """100 images x 1000 findings must complete in under 10 seconds."""
    reports = [_make_image(i) for i in range(100)]

    start = time.perf_counter()
    result = analyze_fleet(reports=reports, fleet_id="perf-fleet")
    elapsed = time.perf_counter() - start

    assert result.image_count == 100
    assert elapsed < 10.0, f"Fleet analysis took {elapsed:.2f}s (budget: 10s)"
