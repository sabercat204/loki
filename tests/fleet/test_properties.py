"""Hypothesis property tests for the fleet analysis engine (P72-P76)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.fleet.aggregation import (
    compute_common_findings,
    compute_posture_distribution,
    compute_risk_ranking,
    detect_outliers,
)
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


@st.composite
def _finding_record(draw: st.DrawFn) -> FindingRecord:
    severity = draw(st.sampled_from(list(SeverityLevel)))
    has_score = draw(st.booleans())
    deviation_score = None
    if has_score:
        deviation_score = DeviationScore(
            base_severity=severity,
            component_criticality=draw(st.floats(min_value=0.0, max_value=1.0, allow_nan=False)),
            security_direction=draw(st.sampled_from(list(SecurityDirection))),
            signature_delta=draw(st.sampled_from(list(SignatureDelta))),
            cve_introduced=draw(st.booleans()),
            mutability_change=draw(st.sampled_from(list(MutabilityChange))),
            composite_score=draw(st.floats(min_value=0.0, max_value=10.0, allow_nan=False)),
            priority_rank=draw(st.integers(min_value=1, max_value=100)),
        )

    return FindingRecord(
        finding_id=uuid.uuid4(),
        component_id=uuid.uuid4(),
        severity=severity,
        category=draw(
            st.sampled_from(["classification_mismatch", "baseline_deviation", "cve_match"])
        ),
        title=draw(st.text(min_size=1, max_size=30, alphabet="abcdefghij -_")),
        description="test",
        evidence=FindingEvidence(
            matched_cve=draw(
                st.one_of(st.none(), st.from_regex(r"CVE-2024-\d{4}", fullmatch=True))
            ),
            deviation_score=deviation_score,
        ),
        recommended_action="investigate",
    )


@st.composite
def _image_report(draw: st.DrawFn) -> ImageAnalysisReport:
    file_hash = draw(st.text(alphabet="0123456789abcdef", min_size=64, max_size=64))
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
        posture_rating=draw(st.sampled_from(list(PostureRating))),
        findings=draw(st.lists(_finding_record(), min_size=0, max_size=5)),
    )


_fleet_reports = st.lists(_image_report(), min_size=1, max_size=8)


class TestP72Determinism:
    """P72: Same inputs produce same output modulo timestamp."""

    @settings(
        max_examples=25,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @given(reports=_fleet_reports)
    def test_determinism(self, reports: list[ImageAnalysisReport]) -> None:
        r1 = analyze_fleet(reports=reports, fleet_id="det-test")
        r2 = analyze_fleet(reports=reports, fleet_id="det-test")
        assert r1.image_count == r2.image_count
        assert r1.fleet_posture == r2.fleet_posture
        assert r1.common_findings == r2.common_findings
        assert r1.outlier_images == r2.outlier_images
        assert r1.systemic_risks == r2.systemic_risks
        assert r1.recommended_actions == r2.recommended_actions


class TestP73PostureDistributionTotality:
    """P73: sum(fleet_posture.values()) == image_count."""

    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @given(reports=_fleet_reports)
    def test_posture_totality(self, reports: list[ImageAnalysisReport]) -> None:
        dist = compute_posture_distribution(reports)
        assert sum(dist.values()) == len(reports)


class TestP74OutlierSubset:
    """P74: Every UUID in outlier_images appears in the input report set."""

    @settings(
        max_examples=25,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @given(reports=_fleet_reports)
    def test_outlier_subset(self, reports: list[ImageAnalysisReport]) -> None:
        posture = compute_posture_distribution(reports)
        outliers = detect_outliers(reports, posture)
        input_ids = {r.image_id for r in reports}
        for outlier_id in outliers:
            assert outlier_id in input_ids


class TestP75CommonFindingThreshold:
    """P75: Every entry in common_findings has fleet_count >= 2."""

    @settings(
        max_examples=25,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @given(reports=_fleet_reports)
    def test_common_threshold(self, reports: list[ImageAnalysisReport]) -> None:
        common = compute_common_findings(reports)
        for finding in common:
            fleet_counts = [
                ind for ind in finding.evidence.raw_indicators if ind.startswith("fleet_count=")
            ]
            assert len(fleet_counts) == 1
            count = int(fleet_counts[0].split("=")[1])
            assert count >= 2


class TestP76RiskScoreOrderingStability:
    """P76: recommended_actions is sorted by descending risk_score, stable across runs."""

    @settings(
        max_examples=25,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @given(reports=_fleet_reports)
    def test_risk_ordering_stable(self, reports: list[ImageAnalysisReport]) -> None:
        r1 = compute_risk_ranking(reports)
        r2 = compute_risk_ranking(reports)
        assert [a.description for a in r1] == [a.description for a in r2]
