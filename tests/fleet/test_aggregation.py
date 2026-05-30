"""Tests for fleet aggregation functions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from loki.fleet.aggregation import (
    compute_common_findings,
    compute_cve_rollup,
    compute_posture_distribution,
    compute_risk_ranking,
    detect_outliers,
)
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
    *,
    posture: PostureRating = PostureRating.BASELINE,
    findings: list[FindingRecord] | None = None,
    image_id: uuid.UUID | None = None,
) -> ImageAnalysisReport:
    """Create a minimal ImageAnalysisReport for testing."""
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
        image_id=image_id if image_id else image.image_id,
        image_metadata=image,
        posture_rating=posture,
        findings=findings or [],
    )


def _make_finding(
    *,
    category: str = "classification_mismatch",
    severity: SeverityLevel = SeverityLevel.HIGH,
    title: str = "test finding",
    matched_cve: str | None = None,
    composite_score: float | None = None,
) -> FindingRecord:
    """Create a minimal FindingRecord for testing."""
    deviation_score = None
    if composite_score is not None:
        deviation_score = DeviationScore(
            base_severity=severity,
            component_criticality=0.5,
            security_direction=SecurityDirection.DEGRADED,
            signature_delta=SignatureDelta.NONE,
            cve_introduced=False,
            mutability_change=MutabilityChange.NONE,
            composite_score=composite_score,
            priority_rank=1,
        )

    return FindingRecord(
        finding_id=uuid.uuid4(),
        component_id=uuid.uuid4(),
        severity=severity,
        category=category,
        title=title,
        description="Test finding description",
        evidence=FindingEvidence(
            matched_cve=matched_cve,
            deviation_score=deviation_score,
        ),
        recommended_action="Investigate",
    )


# --------------------------------------------------------------------------
# Posture distribution
# --------------------------------------------------------------------------


class TestPostureDistribution:
    def test_all_ratings_present(self) -> None:
        reports = [_make_image(posture=PostureRating.BASELINE)]
        dist = compute_posture_distribution(reports)
        for rating in PostureRating:
            assert rating in dist

    def test_sum_equals_image_count(self) -> None:
        reports = [
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.DEGRADED),
            _make_image(posture=PostureRating.BASELINE),
        ]
        dist = compute_posture_distribution(reports)
        assert sum(dist.values()) == 3

    def test_correct_counts(self) -> None:
        reports = [
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.DEGRADED),
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.COMPROMISED),
        ]
        dist = compute_posture_distribution(reports)
        assert dist[PostureRating.BASELINE] == 2
        assert dist[PostureRating.DEGRADED] == 1
        assert dist[PostureRating.COMPROMISED] == 1
        assert dist[PostureRating.AT_RISK] == 0
        assert dist[PostureRating.HARDENED] == 0

    def test_single_image(self) -> None:
        reports = [_make_image(posture=PostureRating.AT_RISK)]
        dist = compute_posture_distribution(reports)
        assert dist[PostureRating.AT_RISK] == 1
        assert sum(dist.values()) == 1


# --------------------------------------------------------------------------
# Common findings
# --------------------------------------------------------------------------


class TestCommonFindings:
    def test_no_common_findings_when_unique(self) -> None:
        finding_a = _make_finding(title="unique-a")
        finding_b = _make_finding(title="unique-b")
        reports = [
            _make_image(findings=[finding_a]),
            _make_image(findings=[finding_b]),
        ]
        result = compute_common_findings(reports)
        assert result == []

    def test_common_finding_detected(self) -> None:
        finding = _make_finding(
            category="classification_mismatch",
            severity=SeverityLevel.HIGH,
            title="Suspicious driver",
        )
        reports = [
            _make_image(findings=[finding]),
            _make_image(findings=[finding]),
        ]
        result = compute_common_findings(reports)
        assert len(result) == 1
        indicators = result[0].evidence.raw_indicators
        assert any("fleet_count=2" in ind for ind in indicators)

    def test_normalization_groups_uuid_titles(self) -> None:
        uid_a = str(uuid.uuid4())
        uid_b = str(uuid.uuid4())
        finding_a = _make_finding(title=f"Driver {uid_a} changed")
        finding_b = _make_finding(title=f"Driver {uid_b} changed")
        reports = [
            _make_image(findings=[finding_a]),
            _make_image(findings=[finding_b]),
        ]
        result = compute_common_findings(reports)
        assert len(result) == 1

    def test_sorting_by_count_then_severity(self) -> None:
        high_finding = _make_finding(
            category="cat", severity=SeverityLevel.HIGH, title="common high"
        )
        critical_finding = _make_finding(
            category="cat", severity=SeverityLevel.CRITICAL, title="common critical"
        )
        reports = [
            _make_image(findings=[high_finding, critical_finding]),
            _make_image(findings=[high_finding, critical_finding]),
            _make_image(findings=[high_finding]),
        ]
        result = compute_common_findings(reports)
        assert len(result) == 2
        assert result[0].title == "common high"
        assert result[1].title == "common critical"

    def test_same_finding_in_same_image_counted_once(self) -> None:
        finding = _make_finding(title="repeated")
        reports = [
            _make_image(findings=[finding, finding]),
            _make_image(findings=[finding]),
        ]
        result = compute_common_findings(reports)
        assert len(result) == 1
        indicators = result[0].evidence.raw_indicators
        assert any("fleet_count=2" in ind for ind in indicators)


# --------------------------------------------------------------------------
# CVE rollup
# --------------------------------------------------------------------------


class TestCveRollup:
    def test_no_cves(self) -> None:
        reports = [_make_image(findings=[_make_finding()])]
        result = compute_cve_rollup(reports)
        assert result == []

    def test_single_cve_in_one_image_excluded(self) -> None:
        finding = _make_finding(matched_cve="CVE-2024-1234")
        reports = [_make_image(findings=[finding])]
        result = compute_cve_rollup(reports)
        assert result == []

    def test_cve_in_multiple_images(self) -> None:
        finding = _make_finding(matched_cve="CVE-2024-1234")
        reports = [
            _make_image(findings=[finding]),
            _make_image(findings=[finding]),
            _make_image(findings=[finding]),
        ]
        result = compute_cve_rollup(reports)
        assert len(result) == 1
        assert result[0] == "CVE-2024-1234 affects 3 images"

    def test_multiple_cves_sorted(self) -> None:
        f1 = _make_finding(matched_cve="CVE-2024-0001")
        f2 = _make_finding(matched_cve="CVE-2024-0002")
        reports = [
            _make_image(findings=[f1, f2]),
            _make_image(findings=[f1, f2]),
            _make_image(findings=[f1]),
        ]
        result = compute_cve_rollup(reports)
        assert len(result) == 2
        assert "CVE-2024-0001 affects 3 images" == result[0]
        assert "CVE-2024-0002 affects 2 images" == result[1]


# --------------------------------------------------------------------------
# Outlier detection
# --------------------------------------------------------------------------


class TestOutlierDetection:
    def test_fewer_than_3_images_skips(self) -> None:
        reports = [
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.COMPROMISED),
        ]
        posture = compute_posture_distribution(reports)
        result = detect_outliers(reports, posture)
        assert result == []

    def test_all_same_posture_no_outliers(self) -> None:
        reports = [
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.BASELINE),
        ]
        posture = compute_posture_distribution(reports)
        result = detect_outliers(reports, posture)
        assert result == []

    def test_outlier_detected(self) -> None:
        reports = [
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.COMPROMISED),
        ]
        posture = compute_posture_distribution(reports)
        result = detect_outliers(reports, posture)
        assert len(result) == 1
        assert result[0] == reports[2].image_id

    def test_sorting_by_severity_then_id(self) -> None:
        id_a = uuid.UUID("00000000-0000-0000-0000-000000000001")
        id_b = uuid.UUID("00000000-0000-0000-0000-000000000002")
        reports = [
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.BASELINE),
            _make_image(posture=PostureRating.AT_RISK, image_id=id_b),
            _make_image(posture=PostureRating.COMPROMISED, image_id=id_a),
        ]
        posture = compute_posture_distribution(reports)
        result = detect_outliers(reports, posture)
        assert result[0] == id_a
        assert result[1] == id_b


# --------------------------------------------------------------------------
# Risk ranking
# --------------------------------------------------------------------------


class TestRiskRanking:
    def test_top_3_limit(self) -> None:
        reports = [
            _make_image(findings=[_make_finding(severity=SeverityLevel.CRITICAL)]) for _ in range(5)
        ]
        result = compute_risk_ranking(reports)
        assert len(result) == 3

    def test_ranking_order(self) -> None:
        low_risk = _make_image(findings=[_make_finding(severity=SeverityLevel.LOW)])
        high_risk = _make_image(
            findings=[
                _make_finding(severity=SeverityLevel.CRITICAL, composite_score=5.0),
                _make_finding(severity=SeverityLevel.CRITICAL, composite_score=3.0),
            ]
        )
        reports = [low_risk, high_risk]
        result = compute_risk_ranking(reports)
        assert len(result) == 2
        assert str(high_risk.image_id) in result[0].description
        assert str(low_risk.image_id) in result[1].description

    def test_action_type_is_investigate(self) -> None:
        reports = [_make_image(findings=[_make_finding(severity=SeverityLevel.HIGH)])]
        result = compute_risk_ranking(reports)
        assert result[0].action_type == "INVESTIGATE"

    def test_deterministic_ties(self) -> None:
        reports = [_make_image() for _ in range(4)]
        result_a = compute_risk_ranking(reports)
        result_b = compute_risk_ranking(reports)
        assert [a.description for a in result_a] == [b.description for b in result_b]

    def test_empty_findings_zero_score(self) -> None:
        reports = [_make_image()]
        result = compute_risk_ranking(reports)
        assert "risk_score=0.0" in result[0].description
