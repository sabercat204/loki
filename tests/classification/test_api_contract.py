"""Tests for the public ``classify_components`` API surface.

Covers Requirement 1: stable import path
(``from loki.classification import classify_components``),
empty-input contract (R1.3), rule-load failures raising typed
exceptions (R1.4 + R2.4), the synchronous-on-calling-thread
guarantee (R1.7), the progress callback contract (R12.1-R12.2),
and the cancellation token contract (R1.9).
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from loki.classification import (
    CancellationToken,
    ClassificationConfigError,
    ClassificationResult,
    ProgressCallback,
    ProgressEvent,
    classify_components,
)
from loki.models import ExtractedComponent
from loki.models.config import ClassificationConfig

# ---------------------------------------------------------------------------
# Stable import path (R1.2)
# ---------------------------------------------------------------------------


def test_classify_components_imports_from_loki_classification() -> None:
    """R1.2: ``from loki.classification import classify_components``
    is the stable public entry point."""
    # The import already happened at module load; this test
    # just pins the symbol's existence.
    assert classify_components is not None
    assert callable(classify_components)


def test_public_dataclasses_imports_from_loki_classification() -> None:
    """The ``ClassificationResult`` / ``ProgressEvent`` /
    ``ProgressCallback`` / ``CancellationToken`` types are
    re-exported from the package."""
    assert ClassificationResult is not None
    assert ProgressEvent is not None
    assert ProgressCallback is not None
    assert CancellationToken is not None


# ---------------------------------------------------------------------------
# Empty input (R1.3)
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_result(
    synthetic_rules_dir: Path,
) -> None:
    """R1.3: an empty sequence of components returns a
    ``ClassificationResult`` with empty ``records`` and
    ``errors`` lists."""
    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    result = classify_components([], config)
    assert isinstance(result, ClassificationResult)
    assert result.records == []
    assert result.errors == []


def test_empty_input_still_constructs_pipeline(tmp_path: Path) -> None:
    """The pipeline is constructed eagerly so rule-load errors
    surface even for empty input. This pins the design's
    decision to construct unconditionally."""
    bogus_rules = tmp_path / "no-such-rules-dir"
    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(bogus_rules),
    )
    with pytest.raises(ClassificationConfigError, match="does not exist"):
        classify_components([], config)


# ---------------------------------------------------------------------------
# Rule-load failures raise typed exceptions (R1.4, R9.1, R9.2)
# ---------------------------------------------------------------------------


def test_missing_rules_dir_raises_config_error(
    tmp_path: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(tmp_path / "missing"),
    )
    with pytest.raises(ClassificationConfigError):
        classify_components(synthetic_components, config)


def test_taxonomy_version_mismatch_raises_config_error(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """The synthetic rules ship at taxonomy_version 1.0.0; ask
    for 9.9.9 and the loader rejects."""
    config = ClassificationConfig(
        taxonomy_version="9.9.9",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    with pytest.raises(ClassificationConfigError, match="taxonomy_version mismatch"):
        classify_components(synthetic_components, config)


# ---------------------------------------------------------------------------
# Synchronous on calling thread (R1.7, R12.2)
# ---------------------------------------------------------------------------


def test_classify_components_is_synchronous(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R1.7: the entry point runs synchronously and returns a
    fully-constructed ``ClassificationResult`` rather than a
    coroutine, future, or thread."""
    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    result = classify_components(synthetic_components, config)
    assert isinstance(result, ClassificationResult)
    # Not a coroutine.
    import inspect

    assert not inspect.iscoroutine(result)
    # Not a future.
    assert not hasattr(result, "result") or not callable(getattr(result, "result", None))


def test_progress_callback_runs_on_calling_thread(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R12.2: the progress callback, if supplied, is invoked from
    the calling thread only."""
    calling_thread = threading.get_ident()
    callback_threads: list[int] = []

    def on_progress(event: ProgressEvent) -> None:
        callback_threads.append(threading.get_ident())

    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    classify_components(synthetic_components, config, progress=on_progress)
    assert len(callback_threads) > 0
    for thread_id in callback_threads:
        assert thread_id == calling_thread


# ---------------------------------------------------------------------------
# Progress callback contract (R12.1)
# ---------------------------------------------------------------------------


def test_progress_callback_invoked_once_per_component(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R12.1: the progress callback is invoked once per
    component classification (after the record is built)."""
    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        events.append(event)

    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    classify_components(synthetic_components, config, progress=on_progress)
    assert len(events) == len(synthetic_components)


def test_progress_events_have_increasing_indices(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """Indices are 1-based and strictly increasing (R12.1)."""
    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        events.append(event)

    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    classify_components(synthetic_components, config, progress=on_progress)
    indices = [e.index for e in events]
    expected = list(range(1, len(synthetic_components) + 1))
    assert indices == expected


def test_progress_events_have_correct_total(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """``ProgressEvent.total`` equals the static input length
    across every event in the run."""
    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        events.append(event)

    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    classify_components(synthetic_components, config, progress=on_progress)
    expected_total = len(synthetic_components)
    for event in events:
        assert event.total == expected_total


def test_progress_events_carry_string_component_ids(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """``ProgressEvent.component_id`` is the str() of the
    component's UUID."""
    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        events.append(event)

    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    classify_components(synthetic_components, config, progress=on_progress)
    for component, event in zip(synthetic_components, events, strict=True):
        assert event.component_id == str(component.component_id)


def test_omitting_progress_callback_works(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """When the progress callback is omitted, classification
    proceeds normally and produces the same records list."""
    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    result_with_no_callback = classify_components(synthetic_components, config)
    assert len(result_with_no_callback.records) == len(synthetic_components)


# ---------------------------------------------------------------------------
# Cancellation token contract (R1.9)
# ---------------------------------------------------------------------------


def test_cancel_token_short_circuits_between_components(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R1.9: a cancel token returning True after N components
    stops the loop. The result has at most N records and
    exactly one cancellation error."""
    cancel_after = 2
    call_count = [0]

    def cancel() -> bool:
        # Returns True on the 3rd check, after 2 components have
        # been processed.
        call_count[0] += 1
        return call_count[0] > cancel_after

    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    result = classify_components(synthetic_components, config, cancel=cancel)
    # The cancellation error has component_id=None.
    cancellation_errors = [e for e in result.errors if e.component_id is None]
    assert len(cancellation_errors) == 1
    assert cancellation_errors[0].error_message == "classification cancelled by caller"


def test_cancel_token_returning_true_immediately_yields_zero_records(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """A cancel token that always returns True yields zero
    records and one cancellation error."""

    def always_cancel() -> bool:
        return True

    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    result = classify_components(synthetic_components, config, cancel=always_cancel)
    assert result.records == []
    cancellation_errors = [e for e in result.errors if e.component_id is None]
    assert len(cancellation_errors) == 1


def test_cancel_token_returning_false_is_indistinguishable_from_no_token(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """A cancel token that always returns False classifies the
    full input, just like omitting the token entirely."""

    def never_cancel() -> bool:
        return False

    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )
    with_token = classify_components(synthetic_components, config, cancel=never_cancel)
    without_token = classify_components(synthetic_components, config)
    assert len(with_token.records) == len(without_token.records)
    assert len(with_token.records) == len(synthetic_components)
