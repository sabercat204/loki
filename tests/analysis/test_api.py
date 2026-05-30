"""Tests for ``loki.analysis.api`` — public entry point (task 20)."""

from __future__ import annotations

import dataclasses
import threading
import uuid

import pytest

from loki.analysis import (
    ANALYSIS_VERSION,
    AnalysisProgressEvent,
    analyze_image,
)
from loki.analysis.findings import ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID
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
)


def _config() -> AnalysisConfig:
    """Build a valid ``AnalysisConfig`` for API tests."""
    return AnalysisConfig(
        severity_weights=dict(VALID_WEIGHTS),
        default_severity_threshold=SeverityLevel.MEDIUM,
        match_strategy=MatchStrategy.AUTO,
    )


# --- Public surface smoke ---


def test_public_surface_importable() -> None:
    """Every name in the documented re-export list is importable from loki.analysis."""
    from loki.analysis import (  # noqa: F401
        ANALYSIS_VERSION,
        AnalysisCancellationToken,
        AnalysisConfigError,
        AnalysisError,
        AnalysisInputError,
        AnalysisProgressCallback,
        AnalysisProgressEvent,
        AnalysisReportConstructionError,
        BaselineNotFoundError,
        analyze_image,
    )


def test_analysis_progress_event_dataclass_strips_component_id() -> None:
    """D6 default: AnalysisProgressEvent does not carry component_id."""
    event = AnalysisProgressEvent(index=1, total=10)
    assert event.index == 1
    assert event.total == 10
    # The dataclass has exactly two fields: index and total.
    assert hasattr(event, "index")
    assert hasattr(event, "total")
    assert not hasattr(event, "component_id")


def test_analysis_progress_event_is_frozen() -> None:
    """The dataclass is frozen; consumers cannot mutate the event in-flight."""
    event = AnalysisProgressEvent(index=1, total=10)
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.index = 999  # type: ignore[misc]


# --- Happy-path call ---


def test_analyze_image_returns_validated_report() -> None:
    """analyze_image with valid inputs returns an ImageAnalysisReport."""
    cfg = _config()
    cid = uuid.uuid4()
    target = make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_record = make_record(component_id=cid, type_label=ComponentTypeLabel.OS_KERNEL)
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    report = analyze_image(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    assert report.analysis_version == ANALYSIS_VERSION
    assert report.image_id == image.image_id
    assert report.baseline_comparison is not None
    assert report.baseline_comparison.baseline_id == baseline.baseline_id
    # Type axis disagreement -> classification_mismatch finding.
    categories = [f.category for f in report.findings]
    assert "classification_mismatch" in categories


def test_analyze_image_with_no_findings_returns_baseline_posture() -> None:
    cfg = _config()
    cid = uuid.uuid4()
    record = make_record(component_id=cid)
    baseline = make_baseline_record(component_manifest=[record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    report = analyze_image(
        target_records=[record],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    assert report.findings == []
    assert report.posture_rating is PostureRating.BASELINE


# --- Cancellation contract (R7) ---


def test_analyze_image_does_not_raise_on_cancellation() -> None:
    """R16.6: cooperative cancellation is a return-path, not a throw-path."""
    cfg = _config()
    targets = [make_record() for _ in range(5)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    def cancel() -> bool:
        return True  # cancel immediately

    report = analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
        cancel=cancel,
    )
    # Partial report; last finding is the Cancellation_Marker.
    assert report.findings[-1].category == "analysis_cancelled"
    assert report.findings[-1].component_id == ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID


# --- Progress callback contract ---


def test_progress_callback_receives_progress_events() -> None:
    cfg = _config()
    targets = [make_record() for _ in range(3)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    seen: list[AnalysisProgressEvent] = []

    def progress(event: AnalysisProgressEvent) -> None:
        seen.append(event)

    analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
        progress=progress,
    )
    assert len(seen) == 3
    assert seen[0].index == 1
    assert seen[0].total == 3
    assert seen[1].index == 2
    assert seen[2].index == 3


def test_progress_callback_runs_on_calling_thread() -> None:
    """R19.3: progress callback is invoked from the calling thread only."""
    cfg = _config()
    target = make_record()
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    calling_thread_id = threading.get_ident()
    callback_thread_id: list[int] = []

    def progress(event: AnalysisProgressEvent) -> None:
        callback_thread_id.append(threading.get_ident())

    analyze_image(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
        progress=progress,
    )
    assert callback_thread_id == [calling_thread_id]


# --- No loki.gui import (R1.9) ---


def test_loki_analysis_import_does_not_pull_in_loki_gui() -> None:
    """R1.9: importing loki.analysis must not transitively import loki.gui.

    We can't fully guarantee no other test session imported gui earlier;
    instead we verify the module sources under loki.analysis don't
    reference loki.gui at all.
    """
    import inspect

    import loki.analysis
    import loki.analysis.api
    import loki.analysis.errors
    import loki.analysis.findings
    import loki.analysis.matching
    import loki.analysis.pairing
    import loki.analysis.pipeline
    import loki.analysis.posture
    import loki.analysis.report
    import loki.analysis.scoring
    import loki.analysis.timing
    import loki.analysis.version

    for module in [
        loki.analysis,
        loki.analysis.api,
        loki.analysis.errors,
        loki.analysis.findings,
        loki.analysis.matching,
        loki.analysis.pairing,
        loki.analysis.pipeline,
        loki.analysis.posture,
        loki.analysis.report,
        loki.analysis.scoring,
        loki.analysis.timing,
        loki.analysis.version,
    ]:
        source = inspect.getsource(module)
        # The substring check is loose but adequate; loki.gui imports
        # would all use the prefix "loki.gui".
        assert "loki.gui" not in source, f"{module.__name__} contains a reference to loki.gui"
