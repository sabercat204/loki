"""Progress callback tests for the classification pipeline.

Covers Requirements 12.1 and 12.2: the progress callback is
invoked exactly once per *successfully classified* component,
in input order, on the calling thread. Wave 5's
``test_api_contract.py`` covered the basics; this file pins
the per-component-success invariants and the
no-progress-on-failure rule.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest

from loki.classification import ProgressEvent, classify_components
from loki.models import LOKI_NAMESPACE, ExtractedComponent
from loki.models.config import ClassificationConfig


def _config(rules_dir: Path) -> ClassificationConfig:
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


def _make_component_with_raw_file(*, tmp_path: Path, index: int) -> ExtractedComponent:
    raw_file = tmp_path / f"comp-{index}.bin"
    raw_file.write_bytes(b"\x00" * 64)
    return ExtractedComponent(
        component_id=uuid.uuid5(LOKI_NAMESPACE, f"progress-test-{index}"),
        source_image_id=uuid.uuid5(LOKI_NAMESPACE, "progress-image"),
        offset=f"0x{index * 0x1000:x}",
        size=64,
        raw_hash="0" * 64,
        component_type_hint="dxe_driver",
        guid=str(uuid.uuid5(LOKI_NAMESPACE, f"progress-guid-{index}")),
        name=f"COMP_{index:03d}",
        raw_path=str(raw_file),
    )


# ---------------------------------------------------------------------------
# Progress events fire in input order with correct indices
# ---------------------------------------------------------------------------


def test_progress_indices_match_input_order(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """R12.1: progress events have ``index`` in 1..N order
    matching the input-sequence position."""
    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(5)]
    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        events.append(event)

    config = _config(synthetic_rules_dir)
    classify_components(components, config, progress=on_progress)

    indices = [e.index for e in events]
    assert indices == [1, 2, 3, 4, 5]


def test_progress_component_ids_match_input_order(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """The progress event's ``component_id`` is the
    str-formatted UUID of the component being processed at
    that index."""
    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(4)]
    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        events.append(event)

    config = _config(synthetic_rules_dir)
    classify_components(components, config, progress=on_progress)

    for component, event in zip(components, events, strict=True):
        assert event.component_id == str(component.component_id)


def test_progress_total_is_static_input_length(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """``ProgressEvent.total`` equals the static input length
    across every event in the run, regardless of per-component
    failures."""
    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(7)]
    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        events.append(event)

    config = _config(synthetic_rules_dir)
    classify_components(components, config, progress=on_progress)

    for event in events:
        assert event.total == 7


# ---------------------------------------------------------------------------
# Progress callback runs on the calling thread (R12.2)
# ---------------------------------------------------------------------------


def test_progress_callback_thread_id_matches_caller(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """R12.2: every progress callback invocation carries the
    same thread id as the call site of ``classify_components``.
    This pins the synchronous-on-calling-thread guarantee
    (R1.7) extended to the callback (R12.2)."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(3)]
    caller_thread_id = threading.get_ident()
    callback_thread_ids: list[int] = []

    def on_progress(event: ProgressEvent) -> None:
        callback_thread_ids.append(threading.get_ident())

    config = _config(synthetic_rules_dir)
    classify_components(components, config, progress=on_progress)

    assert len(callback_thread_ids) == 3
    for tid in callback_thread_ids:
        assert tid == caller_thread_id


# ---------------------------------------------------------------------------
# Progress callback NOT invoked for failed components
# ---------------------------------------------------------------------------


def test_progress_not_invoked_when_axis_evaluation_crashes(
    synthetic_rules_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a component fails per-component classification (axis
    evaluation crash), the progress callback is NOT invoked
    for that component. The progress callback fires only after
    successful record append per the design's classify-flow.

    This is the implementation's choice: progress events
    represent successful classifications, not "components
    processed". Test 4 components, fail the middle one, expect
    3 progress events for the 3 successes."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(4)]
    failing_id = components[1].component_id

    from loki.classification.rules.matcher import matches as real_matches

    def selectively_crashing_matches(rule: object, component: ExtractedComponent) -> bool:
        if component.component_id == failing_id:
            raise RuntimeError("synthetic crash")
        return real_matches(rule, component)  # type: ignore[arg-type]

    monkeypatch.setattr("loki.classification.classifier.matches", selectively_crashing_matches)

    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        events.append(event)

    config = _config(synthetic_rules_dir)
    classify_components(components, config, progress=on_progress)

    # 3 successes -> 3 progress events.
    assert len(events) == 3
    # The failing component_id must not appear in any progress event.
    failing_id_str = str(failing_id)
    for event in events:
        assert event.component_id != failing_id_str


# ---------------------------------------------------------------------------
# Empty input produces no progress events
# ---------------------------------------------------------------------------


def test_empty_input_produces_no_progress_events(
    synthetic_rules_dir: Path,
) -> None:
    """An empty component sequence does not invoke the
    progress callback at all."""
    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        events.append(event)

    config = _config(synthetic_rules_dir)
    classify_components([], config, progress=on_progress)
    assert events == []


# ---------------------------------------------------------------------------
# Omitting the callback is well-defined
# ---------------------------------------------------------------------------


def test_omitting_progress_callback_does_not_change_records(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """The result with and without the progress callback are
    equivalent (modulo timestamps). The callback is purely a
    side-channel for the caller; omitting it does not change
    the records."""
    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(3)]

    def noop(event: ProgressEvent) -> None:
        return None

    config = _config(synthetic_rules_dir)
    with_callback = classify_components(components, config, progress=noop)
    without_callback = classify_components(components, config)

    assert len(with_callback.records) == len(without_callback.records)
    for r1, r2 in zip(with_callback.records, without_callback.records, strict=True):
        assert r1.component_id == r2.component_id
        assert r1.type_axis == r2.type_axis
        assert r1.vendor_axis == r2.vendor_axis
        assert r1.security_axis == r2.security_axis
        assert r1.mutability_axis == r2.mutability_axis
