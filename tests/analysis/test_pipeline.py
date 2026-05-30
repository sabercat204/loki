"""Tests for ``loki.analysis.pipeline.AnalysisPipeline`` (task 19)."""

from __future__ import annotations

import logging
import uuid

import pytest

from loki.analysis import (
    AnalysisConfigError,
    AnalysisInputError,
    BaselineNotFoundError,
)
from loki.analysis.findings import ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID
from loki.analysis.pipeline import AnalysisPipeline
from loki.models import (
    AnalysisConfig,
    BaselineRegistry,
    ComponentTypeLabel,
    MatchStrategy,
    PostureRating,
    SeverityLevel,
)
from tests.analysis._helpers import (
    VALID_WEIGHTS,
    make_baseline_record,
    make_image,
    make_record,
    make_signature_info,
)


def _config(
    *,
    severity_weights: dict[str, float] | None = None,
    match_strategy: MatchStrategy = MatchStrategy.AUTO,
    confidence_gap_threshold: float = 0.6,
    baseline_id: uuid.UUID | None = None,
) -> AnalysisConfig:
    """Build a valid ``AnalysisConfig`` for pipeline tests."""
    return AnalysisConfig(
        severity_weights=severity_weights or dict(VALID_WEIGHTS),
        default_severity_threshold=SeverityLevel.MEDIUM,
        match_strategy=match_strategy,
        confidence_gap_threshold=confidence_gap_threshold,
        baseline_id=baseline_id,
    )


# --- Constructor: fail-fast on invalid inputs ---


def test_constructor_raises_on_invalid_severity_weights() -> None:
    """Invalid severity_weights keyset -> AnalysisConfigError."""
    bad_weights = {"vendor": 1.0}  # missing 3 keys
    cfg = _config(severity_weights=bad_weights)
    registry = BaselineRegistry(baselines=[make_baseline_record()])
    image = make_image()
    with pytest.raises(AnalysisConfigError) as excinfo:
        AnalysisPipeline(
            target_records=[],
            registry=registry,
            target_image=image,
            config=cfg,
        )
    assert excinfo.value.field_name == "severity_weights"


def test_constructor_raises_on_baseline_lookup_miss() -> None:
    """AUTO match_strategy with no matching baseline -> BaselineNotFoundError."""
    cfg = _config(match_strategy=MatchStrategy.AUTO)
    other = make_baseline_record(vendor="Other", model="M", firmware_version="9.9.9")
    registry = BaselineRegistry(baselines=[other])
    image = make_image(vendor="Intel", model="X1", firmware_version="1.0.0")
    with pytest.raises(BaselineNotFoundError):
        AnalysisPipeline(
            target_records=[],
            registry=registry,
            target_image=image,
            config=cfg,
        )


def test_constructor_raises_on_target_duplicate_component_id() -> None:
    """Duplicate component_id on target side -> AnalysisInputError(side="target")."""
    cfg = _config()
    baseline = make_baseline_record()
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    dup = uuid.uuid4()
    targets = [make_record(component_id=dup), make_record(component_id=dup)]
    with pytest.raises(AnalysisInputError) as excinfo:
        AnalysisPipeline(
            target_records=targets,
            registry=registry,
            target_image=image,
            config=cfg,
        )
    assert excinfo.value.side == "target"


def test_constructor_raises_on_baseline_duplicate_component_id() -> None:
    """Duplicate component_id on baseline side -> AnalysisInputError(side="baseline")."""
    cfg = _config()
    dup = uuid.uuid4()
    baseline_manifest = [make_record(component_id=dup), make_record(component_id=dup)]
    baseline = make_baseline_record(component_manifest=baseline_manifest)
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    with pytest.raises(AnalysisInputError) as excinfo:
        AnalysisPipeline(
            target_records=[],
            registry=registry,
            target_image=image,
            config=cfg,
        )
    assert excinfo.value.side == "baseline"


# --- Empty target_records (R1.3) ---


def test_empty_target_records_returns_baseline_posture() -> None:
    """R1.3: empty target_records still resolves matched baseline; no findings emitted."""
    cfg = _config()
    baseline = make_baseline_record()
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=[],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report = pipeline.run()
    # Baseline manifest has one record; that record is unpaired -> missing_required.
    assert len(report.findings) == 1
    assert report.findings[0].category == "missing_required_component"
    assert report.posture_rating is PostureRating.COMPROMISED  # missing_required triggers


def test_empty_target_records_empty_baseline_returns_baseline_posture() -> None:
    """Truly empty: no targets and an empty baseline manifest -> BASELINE."""
    cfg = _config()
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=[],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report = pipeline.run()
    assert report.findings == []
    assert report.posture_rating is PostureRating.BASELINE


# --- Per-pair finding emission ---


def test_paired_disagreement_emits_classification_mismatch() -> None:
    cfg = _config()
    cid = uuid.uuid4()
    target = make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_record = make_record(component_id=cid, type_label=ComponentTypeLabel.OS_KERNEL)
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report = pipeline.run()
    categories = [f.category for f in report.findings]
    assert "classification_mismatch" in categories


def test_paired_signature_change_emits_signature_regression() -> None:
    cfg = _config()
    cid = uuid.uuid4()
    target = make_record(component_id=cid, signature_info=make_signature_info(present=False))
    baseline_record = make_record(
        component_id=cid, signature_info=make_signature_info(present=True)
    )
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report = pipeline.run()
    categories = [f.category for f in report.findings]
    assert "signature_regression" in categories


def test_unpaired_target_emits_unexpected_component() -> None:
    cfg = _config()
    target = make_record()  # different component_id from any baseline record
    baseline = make_baseline_record()  # contains a different component_id
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report = pipeline.run()
    categories = [f.category for f in report.findings]
    assert "unexpected_component" in categories


def test_unpaired_baseline_emits_missing_required() -> None:
    cfg = _config()
    baseline_record = make_record()
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=[],  # nothing to pair
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report = pipeline.run()
    categories = [f.category for f in report.findings]
    assert "missing_required_component" in categories


def test_low_confidence_target_emits_classification_gap() -> None:
    """R10.1: composite_confidence < threshold -> classification_gap."""
    cfg = _config(confidence_gap_threshold=0.6)
    cid = uuid.uuid4()
    # confidence 0.4 < 0.6 threshold -> gap fires.
    target = make_record(component_id=cid, confidence=0.4)
    baseline_record = make_record(component_id=cid, confidence=1.0)
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report = pipeline.run()
    categories = [f.category for f in report.findings]
    assert "classification_gap" in categories


# --- Combined per-pair findings ---


def test_combined_per_pair_findings() -> None:
    """R4.8: a paired component can produce multiple findings simultaneously."""
    cfg = _config(confidence_gap_threshold=0.6)
    cid = uuid.uuid4()
    target = make_record(
        component_id=cid,
        type_label=ComponentTypeLabel.UEFI_DRIVER,
        confidence=0.4,  # below threshold -> gap
        signature_info=make_signature_info(present=False),
    )
    baseline_record = make_record(
        component_id=cid,
        type_label=ComponentTypeLabel.OS_KERNEL,  # disagrees -> mismatch
        confidence=1.0,
        signature_info=make_signature_info(present=True),  # different -> regression
    )
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report = pipeline.run()
    categories = sorted({f.category for f in report.findings})
    # Three distinct findings on the same component_id.
    assert "classification_mismatch" in categories
    assert "signature_regression" in categories
    assert "classification_gap" in categories
    # All three findings carry the same component_id.
    component_ids = {f.component_id for f in report.findings}
    assert component_ids == {cid}


# --- Cancellation contract (R7) ---


def test_cancellation_emits_marker_as_last_finding() -> None:
    """R7.6: Cancellation_Marker is the LAST entry in findings."""
    cfg = _config()
    targets = [make_record() for _ in range(5)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )

    # Cancel after the third target_record.
    call_count = [0]

    def cancel() -> bool:
        call_count[0] += 1
        return call_count[0] > 3

    report = pipeline.run(cancel=cancel)
    assert report.findings[-1].category == "analysis_cancelled"
    assert report.findings[-1].component_id == ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID


def test_cancellation_skips_missing_required_pass() -> None:
    """R7.1: no missing_required_component findings emitted after cancellation."""
    cfg = _config()
    targets = [make_record() for _ in range(2)]
    # Baseline has unpaired records that would normally produce missing_required.
    baseline_extras = [make_record() for _ in range(3)]
    baseline = make_baseline_record(component_manifest=baseline_extras)
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )

    def cancel() -> bool:
        return True  # cancel on first check

    report = pipeline.run(cancel=cancel)
    categories = [f.category for f in report.findings]
    # Cancellation_Marker is the only finding; no missing_required emitted.
    assert categories == ["analysis_cancelled"]


def test_cancellation_marker_carries_correct_index() -> None:
    """R7.4: evidence.raw_indicators[0] == "cancelled-at-index=N"."""
    cfg = _config()
    targets = [make_record() for _ in range(10)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )

    call_count = [0]

    def cancel() -> bool:
        call_count[0] += 1
        return call_count[0] > 5

    report = pipeline.run(cancel=cancel)
    marker = report.findings[-1]
    # The 6th call to cancel() returns True; index 6 was about to be processed.
    assert marker.evidence.raw_indicators == ["cancelled-at-index=6"]


def test_no_cancellation_token_means_no_marker() -> None:
    """R7.9: omitted token -> no Cancellation_Marker, even on internal interruption."""
    cfg = _config()
    targets = [make_record() for _ in range(3)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report = pipeline.run()
    categories = [f.category for f in report.findings]
    assert "analysis_cancelled" not in categories


# --- Progress callback contract (R19) ---


def test_progress_called_once_per_target_record() -> None:
    cfg = _config()
    targets = [make_record() for _ in range(4)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )

    seen: list[tuple[int, int]] = []

    def progress(index: int, total: int) -> None:
        seen.append((index, total))

    pipeline.run(progress=progress)
    assert seen == [(1, 4), (2, 4), (3, 4), (4, 4)]


def test_progress_not_called_after_cancellation() -> None:
    """When cancellation fires before progress emission, progress is not invoked."""
    cfg = _config()
    targets = [make_record() for _ in range(5)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )

    seen: list[int] = []

    def progress(index: int, total: int) -> None:
        seen.append(index)

    call_count = [0]

    def cancel() -> bool:
        call_count[0] += 1
        return call_count[0] > 2

    pipeline.run(progress=progress, cancel=cancel)
    # Cancellation fires on the third check (call_count == 3); progress was
    # only called for indices 1 and 2.
    assert seen == [1, 2]


# --- Determinism smoke ---


def test_two_runs_equal_modulo_timestamp() -> None:
    """R15.1: two runs on the same inputs produce equal reports modulo timestamp."""
    cfg = _config()
    cid = uuid.uuid4()
    target = make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_record = make_record(component_id=cid, type_label=ComponentTypeLabel.OS_KERNEL)
    baseline = make_baseline_record(component_manifest=[baseline_record])
    image = make_image()

    def run_once() -> dict[str, object]:
        registry = BaselineRegistry(baselines=[baseline])
        pipeline = AnalysisPipeline(
            target_records=[target],
            registry=registry,
            target_image=image,
            config=cfg,
        )
        return pipeline.run().model_dump(mode="json")

    a = run_once()
    b = run_once()
    # Strip both timestamp fields (R15.1 + R17.4 lockstep).
    a.pop("timestamp")
    b.pop("timestamp")
    bc_a = a.get("baseline_comparison")
    bc_b = b.get("baseline_comparison")
    if isinstance(bc_a, dict):
        bc_a.pop("comparison_timestamp", None)
    if isinstance(bc_b, dict):
        bc_b.pop("comparison_timestamp", None)
    assert a == b


# --- R20.1 + R20.2 log records ---


def test_run_start_log_carries_documented_fields(caplog: pytest.LogCaptureFixture) -> None:
    """R20.1: run-start INFO log carries (vendor, model, firmware_version, baseline_version)."""
    cfg = _config()
    baseline = make_baseline_record(vendor="Intel", model="X1", firmware_version="1.0.0")
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image(vendor="Intel", model="X1", firmware_version="1.0.0")
    pipeline = AnalysisPipeline(
        target_records=[],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    with caplog.at_level(logging.INFO, logger="loki.analysis"):
        pipeline.run()

    starting_records = [rec for rec in caplog.records if "starting" in rec.getMessage()]
    assert len(starting_records) == 1
    msg = starting_records[0].getMessage()
    assert "Intel" in msg
    assert "X1" in msg
    assert "1.0.0" in msg
    # baseline_version is "1.0.0" too (the helper default).
    # Forbidden_Leakage_Field_Set: must NOT contain baseline_id or source_image_hash.
    assert str(baseline.baseline_id) not in msg
    assert "0" * 64 not in msg  # source_image_hash


def test_run_finish_log_carries_per_category_counts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """R20.2: run-finish INFO log carries per-category finding counts + duration."""
    cfg = _config()
    cid = uuid.uuid4()
    target = make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_record = make_record(component_id=cid, type_label=ComponentTypeLabel.OS_KERNEL)
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()
    pipeline = AnalysisPipeline(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    with caplog.at_level(logging.INFO, logger="loki.analysis"):
        pipeline.run()

    finished_records = [rec for rec in caplog.records if "finished" in rec.getMessage()]
    assert len(finished_records) == 1
    msg = finished_records[0].getMessage()
    assert "duration_ms=" in msg
    assert "classification_mismatch=1" in msg
    assert "analysis_cancelled=0" in msg
