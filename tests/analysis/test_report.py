"""Tests for ``loki.analysis.report`` (task 18)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from loki.analysis import (
    ANALYSIS_VERSION,
    AnalysisReportConstructionError,
)
from loki.analysis.findings import (
    emit_classification_mismatch,
    emit_unexpected_component,
)
from loki.analysis.report import (
    assemble_report,
    assign_priority_ranks,
    derive_report_id,
)
from loki.models import (
    ComponentTypeLabel,
    FindingRecord,
    PostureRating,
    VendorLabel,
)
from loki.models.firmware import LOKI_NAMESPACE
from tests.analysis._helpers import (
    VALID_WEIGHTS,
    make_baseline_record,
    make_image,
    make_record,
)

# --- assign_priority_ranks ---


def test_assign_priority_ranks_descending_composite_score() -> None:
    """R9.10: highest composite_score gets rank 1."""
    bid = uuid.uuid4()
    # Build three classification_mismatch findings with composite_scores
    # 4.0, 7.0, 1.0; expected ranks: 2, 1, 3.
    cid_low = uuid.UUID(int=1)
    cid_high = uuid.UUID(int=2)
    cid_mid = uuid.UUID(int=3)

    target_low = make_record(component_id=cid_low, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_low = make_record(component_id=cid_low, type_label=ComponentTypeLabel.OS_KERNEL)
    target_high = make_record(
        component_id=cid_high,
        type_label=ComponentTypeLabel.UEFI_DRIVER,
        vendor_label=VendorLabel.INTEL,
    )
    baseline_high = make_record(
        component_id=cid_high,
        type_label=ComponentTypeLabel.OS_KERNEL,
        vendor_label=VendorLabel.AMD,
    )
    target_mid = make_record(component_id=cid_mid, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_mid = make_record(component_id=cid_mid, type_label=ComponentTypeLabel.OS_KERNEL)

    # Custom weights to get the target spread of composite scores.
    weights_low = {"type": 0.4, "vendor": 0.2, "security_posture": 0.3, "mutability": 0.1}
    finding_low = emit_classification_mismatch(
        target=target_low,
        baseline=baseline_low,
        matched_baseline_id=bid,
        severity_weights=weights_low,
    )  # type only -> 4.0
    finding_high = emit_classification_mismatch(
        target=target_high,
        baseline=baseline_high,
        matched_baseline_id=bid,
        severity_weights={
            "type": 0.4,
            "vendor": 0.3,
            "security_posture": 0.2,
            "mutability": 0.1,
        },
    )  # type+vendor -> 7.0
    finding_mid = emit_classification_mismatch(
        target=target_mid,
        baseline=baseline_mid,
        matched_baseline_id=bid,
        severity_weights={
            "type": 0.1,
            "vendor": 0.4,
            "security_posture": 0.4,
            "mutability": 0.1,
        },
    )  # type only at weight 0.1 -> 1.0

    findings = [finding_low, finding_high, finding_mid]
    assign_priority_ranks(findings)

    assert finding_high.evidence.deviation_score is not None
    assert finding_high.evidence.deviation_score.priority_rank == 1
    assert finding_low.evidence.deviation_score is not None
    assert finding_low.evidence.deviation_score.priority_rank == 2
    assert finding_mid.evidence.deviation_score is not None
    assert finding_mid.evidence.deviation_score.priority_rank == 3


def test_assign_priority_ranks_ties_break_by_ascending_component_id() -> None:
    """R9.10: ties broken by ascending component_id."""
    bid = uuid.uuid4()
    cid_a = uuid.UUID(int=1)
    cid_b = uuid.UUID(int=2)

    # Both produce composite_score = 4.0 (type only at weight 0.4).
    target_a = make_record(component_id=cid_a, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_a = make_record(component_id=cid_a, type_label=ComponentTypeLabel.OS_KERNEL)
    target_b = make_record(component_id=cid_b, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_b = make_record(component_id=cid_b, type_label=ComponentTypeLabel.OS_KERNEL)

    finding_a = emit_classification_mismatch(
        target=target_a,
        baseline=baseline_a,
        matched_baseline_id=bid,
        severity_weights=VALID_WEIGHTS,
    )
    finding_b = emit_classification_mismatch(
        target=target_b,
        baseline=baseline_b,
        matched_baseline_id=bid,
        severity_weights=VALID_WEIGHTS,
    )
    # Pass them in B-first order; the sort must reorder A-first by component_id.
    findings = [finding_b, finding_a]
    assign_priority_ranks(findings)

    assert finding_a.evidence.deviation_score is not None
    assert finding_a.evidence.deviation_score.priority_rank == 1
    assert finding_b.evidence.deviation_score is not None
    assert finding_b.evidence.deviation_score.priority_rank == 2


def test_assign_priority_ranks_leaves_non_mismatch_findings_untouched() -> None:
    """R9.11: only classification_mismatch findings carry a DeviationScore."""
    target = make_record()
    unexpected = emit_unexpected_component(target=target, matched_baseline_id=uuid.uuid4())
    findings = [unexpected]
    assign_priority_ranks(findings)
    # unexpected_component findings have evidence.deviation_score == None;
    # the function leaves them untouched.
    assert unexpected.evidence.deviation_score is None


def test_assign_priority_ranks_empty_findings_no_op() -> None:
    findings: list[FindingRecord] = []
    assign_priority_ranks(findings)
    assert findings == []


# --- derive_report_id ---


def test_derive_report_id_deterministic() -> None:
    image_id = uuid.uuid4()
    baseline_id = uuid.uuid4()
    a = derive_report_id(
        target_image_id=image_id,
        baseline_id=baseline_id,
        analysis_version="1.0.0",
    )
    b = derive_report_id(
        target_image_id=image_id,
        baseline_id=baseline_id,
        analysis_version="1.0.0",
    )
    assert a == b


def test_derive_report_id_different_versions_produce_different_ids() -> None:
    """R15.8: a bump to ANALYSIS_VERSION changes every report_id."""
    image_id = uuid.uuid4()
    baseline_id = uuid.uuid4()
    v1 = derive_report_id(
        target_image_id=image_id, baseline_id=baseline_id, analysis_version="1.0.0"
    )
    v2 = derive_report_id(
        target_image_id=image_id, baseline_id=baseline_id, analysis_version="1.1.0"
    )
    assert v1 != v2


def test_derive_report_id_matches_documented_formula() -> None:
    image_id = uuid.uuid4()
    baseline_id = uuid.uuid4()
    expected = uuid.uuid5(LOKI_NAMESPACE, f"{image_id}:{baseline_id}:1.0.0")
    assert (
        derive_report_id(
            target_image_id=image_id,
            baseline_id=baseline_id,
            analysis_version="1.0.0",
        )
        == expected
    )


# --- assemble_report ---


def test_assemble_report_happy_path() -> None:
    target = make_image()
    baseline = make_baseline_record()
    report = assemble_report(
        target_image=target,
        matched_baseline=baseline,
        findings=[],
        run_started_at=datetime.now(UTC),
        posture_rating=PostureRating.BASELINE,
        analysis_version=ANALYSIS_VERSION,
    )
    assert report.image_metadata is target
    assert report.image_id == target.image_id
    assert report.posture_rating is PostureRating.BASELINE
    assert report.findings == []
    assert report.recommended_actions == []  # R17.3 default
    assert report.baseline_comparison is not None
    assert report.baseline_comparison.baseline_id == baseline.baseline_id
    assert report.baseline_comparison.target_image_id == target.image_id
    assert report.baseline_comparison.deviations == []  # R17.4 v1 contract


def test_assemble_report_timestamps_in_lockstep() -> None:
    """R17.4 post-HARDEN: BaselineComparison.comparison_timestamp == ImageAnalysisReport.timestamp."""
    target = make_image()
    baseline = make_baseline_record()
    run_started_at = datetime.now(UTC)
    report = assemble_report(
        target_image=target,
        matched_baseline=baseline,
        findings=[],
        run_started_at=run_started_at,
        posture_rating=PostureRating.BASELINE,
        analysis_version=ANALYSIS_VERSION,
    )
    assert report.timestamp == run_started_at
    assert report.baseline_comparison is not None
    assert report.baseline_comparison.comparison_timestamp == run_started_at


def test_assemble_report_carries_findings() -> None:
    target = make_image()
    baseline = make_baseline_record()
    target_record = make_record()
    finding = emit_unexpected_component(
        target=target_record, matched_baseline_id=baseline.baseline_id
    )
    report = assemble_report(
        target_image=target,
        matched_baseline=baseline,
        findings=[finding],
        run_started_at=datetime.now(UTC),
        posture_rating=PostureRating.DEGRADED,
        analysis_version=ANALYSIS_VERSION,
    )
    assert report.findings == [finding]


def test_assemble_report_round_trip_through_json() -> None:
    """R15.5 + R17.6: lossless JSON round-trip."""
    from loki.models import ImageAnalysisReport

    target = make_image()
    baseline = make_baseline_record()
    report = assemble_report(
        target_image=target,
        matched_baseline=baseline,
        findings=[],
        run_started_at=datetime.now(UTC),
        posture_rating=PostureRating.BASELINE,
        analysis_version=ANALYSIS_VERSION,
    )
    restored = ImageAnalysisReport.model_validate_json(report.model_dump_json())
    assert restored.report_id == report.report_id
    assert restored.image_id == report.image_id
    assert restored.posture_rating is PostureRating.BASELINE


def test_assemble_report_uses_derive_report_id() -> None:
    """The assembled report's report_id matches derive_report_id's output."""
    target = make_image()
    baseline = make_baseline_record()
    report = assemble_report(
        target_image=target,
        matched_baseline=baseline,
        findings=[],
        run_started_at=datetime.now(UTC),
        posture_rating=PostureRating.BASELINE,
        analysis_version=ANALYSIS_VERSION,
    )
    expected = derive_report_id(
        target_image_id=target.image_id,  # type: ignore[arg-type]
        baseline_id=baseline.baseline_id,
        analysis_version=ANALYSIS_VERSION,
    )
    assert report.report_id == expected


# --- AnalysisReportConstructionError wrapping ---


def test_construction_error_wraps_pydantic_failure() -> None:
    """R16.5: Pydantic validation failures surface as AnalysisReportConstructionError.

    Force a failure by passing a malformed posture_rating value.
    """
    target = make_image()
    baseline = make_baseline_record()
    with pytest.raises(AnalysisReportConstructionError) as excinfo:
        assemble_report(
            target_image=target,
            matched_baseline=baseline,
            findings=[],
            run_started_at=datetime.now(UTC),
            posture_rating="NOT_A_VALID_POSTURE",  # type: ignore[arg-type]
            analysis_version=ANALYSIS_VERSION,
        )
    assert "posture_rating" in str(excinfo.value)
    assert excinfo.value.loc[0] == "posture_rating"


# --- Two-run determinism (modulo timestamp) ---


def test_two_runs_with_same_timestamp_produce_equal_reports() -> None:
    """The fixed-timestamp invariant: same inputs + same timestamp -> equal reports."""
    target = make_image()
    baseline = make_baseline_record()
    timestamp = datetime.now(UTC)
    report_a = assemble_report(
        target_image=target,
        matched_baseline=baseline,
        findings=[],
        run_started_at=timestamp,
        posture_rating=PostureRating.BASELINE,
        analysis_version=ANALYSIS_VERSION,
    )
    report_b = assemble_report(
        target_image=target,
        matched_baseline=baseline,
        findings=[],
        run_started_at=timestamp,
        posture_rating=PostureRating.BASELINE,
        analysis_version=ANALYSIS_VERSION,
    )
    assert report_a.model_dump(mode="json") == report_b.model_dump(mode="json")
