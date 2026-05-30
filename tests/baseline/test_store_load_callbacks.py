"""Tests for the optional load-time callbacks on ``BaselineStore.load``.

Covers R2.8 (progress callback), R2.9 (cancellation token), and
R2.10 (no-observable-difference invariant when callbacks are
omitted vs. stub-implemented).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from loki.baseline import (
    BaselineStore,
    LoadProgressEvent,
    LoadResult,
)
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.fixtures import synthetic_baseline


@pytest.fixture()
def populated_store(tmp_path: Path) -> Iterator[BaselineStore]:
    """A :class:`BaselineStore` with five baselines on disk.

    Five files comfortably exceeds the early-exit cancellation
    boundaries the tests need to hit, while staying small enough
    that the synchronous load completes in milliseconds.
    """
    storage = tmp_path / "baselines"
    storage.mkdir()
    config = BaselineConfig(storage_path=str(storage), auto_match=False)
    store = BaselineStore(config)
    for index in range(5):
        record = synthetic_baseline.build(
            vendor="INTEL",
            model=f"DEMO-X{index}",
            firmware_version="1.0",
            classification_count=2,
        )
        store.save(record)
    yield store


# ---------------------------------------------------------------------
# R2.8: progress callback
# ---------------------------------------------------------------------


def test_progress_callback_invoked_per_baseline_file(populated_store: BaselineStore) -> None:
    """R2.8: progress fires exactly once before each Baseline_File parse."""
    events: list[LoadProgressEvent] = []
    result = populated_store.load(progress=events.append)

    assert isinstance(result, LoadResult)
    assert len(events) == 5, f"expected 5 events, got {len(events)}"
    # Index is 1-based and total is fixed across the run.
    assert [e.index for e in events] == [1, 2, 3, 4, 5]
    assert all(e.total == 5 for e in events)


def test_progress_callback_paths_are_real(populated_store: BaselineStore) -> None:
    """R2.8: each event's path points at a real Baseline_File."""
    events: list[LoadProgressEvent] = []
    populated_store.load(progress=events.append)

    for event in events:
        assert event.path.is_file(), f"event.path missing: {event.path}"
        assert event.path.suffix == ".yaml"


def test_progress_callback_paths_are_lex_sorted(populated_store: BaselineStore) -> None:
    """R2.8: events arrive in lexicographic Baseline_Filename order (R2.7's discovery sort)."""
    events: list[LoadProgressEvent] = []
    populated_store.load(progress=events.append)

    names = [e.path.name for e in events]
    assert names == sorted(names), "progress events should match the discovery scan's lex order"


def test_progress_callback_skipped_for_non_yaml_files(
    populated_store: BaselineStore,
) -> None:
    """R2.8: files filtered out by the extension check (R1.4) do not produce events."""
    # Drop a non-yaml sibling into the storage directory.
    (populated_store.storage_path / "README.txt").write_text("not a baseline")
    (populated_store.storage_path / "scratch.tmp").write_text("orphan temp")

    events: list[LoadProgressEvent] = []
    populated_store.load(progress=events.append)

    assert len(events) == 5, "non-yaml siblings should not appear in the progress stream"


def test_progress_callback_omitted_does_not_raise(populated_store: BaselineStore) -> None:
    """R2.8: load with progress=None matches the no-callback path (R2.10)."""
    result = populated_store.load(progress=None)
    assert len(result.registry.baselines) == 5


# ---------------------------------------------------------------------
# R2.9: cancellation token
# ---------------------------------------------------------------------


def test_cancellation_token_stops_after_first_file(populated_store: BaselineStore) -> None:
    """R2.9: cancel returning True after one file produces a partial result."""
    events: list[LoadProgressEvent] = []
    cancel_after_first = [False]

    def cancel() -> bool:
        # The check happens before each file's progress event.
        # Returning False on the first call lets file 1 in, then
        # True on subsequent calls stops the loop.
        decision = cancel_after_first[0]
        cancel_after_first[0] = True
        return decision

    result = populated_store.load(progress=events.append, cancel=cancel)

    # Only the first file ever ran — cancellation fired before file 2.
    assert len(result.registry.baselines) == 1
    assert len(events) == 1


def test_cancellation_token_returns_partial_result(populated_store: BaselineStore) -> None:
    """R2.9: a cancelled load returns the records accumulated before cancellation."""
    seen_count = 0

    def cancel() -> bool:
        nonlocal seen_count
        seen_count += 1
        # Cancel before file 4 so files 1-3 have processed.
        return seen_count >= 4

    result = populated_store.load(cancel=cancel)
    assert len(result.registry.baselines) == 3, (
        f"expected 3 records before cancellation, got {len(result.registry.baselines)}"
    )


def test_cancellation_emits_no_post_cancel_progress(populated_store: BaselineStore) -> None:
    """R2.9: no progress callback fires for files past the cancellation boundary."""
    events: list[LoadProgressEvent] = []
    cancel_at = [0]

    def cancel() -> bool:
        cancel_at[0] += 1
        return cancel_at[0] >= 3

    populated_store.load(progress=events.append, cancel=cancel)
    assert len(events) == 2, f"expected 2 progress events before cancel, got {len(events)}"


def test_cancellation_token_always_false_processes_all(populated_store: BaselineStore) -> None:
    """R2.9: cancel returning False always lets the full load run."""
    events: list[LoadProgressEvent] = []
    result = populated_store.load(progress=events.append, cancel=lambda: False)
    assert len(result.registry.baselines) == 5
    assert len(events) == 5


# ---------------------------------------------------------------------
# R2.10: no-observable-difference invariant
# ---------------------------------------------------------------------


def test_load_with_stub_callbacks_matches_no_callbacks(
    populated_store: BaselineStore,
) -> None:
    """R2.10: result with stub callbacks equals result with no callbacks under model_dump."""
    events: list[LoadProgressEvent] = []
    with_callbacks = populated_store.load(
        progress=events.append,
        cancel=lambda: False,
    )
    plain = populated_store.load()

    # Compare the registry payloads. We can't compare LoadResult
    # directly because duration_ms differs by run.
    payload_a = [r.model_dump(mode="json") for r in with_callbacks.registry.baselines]
    payload_b = [r.model_dump(mode="json") for r in plain.registry.baselines]
    assert payload_a == payload_b


def test_load_with_only_progress_matches_no_callbacks(
    populated_store: BaselineStore,
) -> None:
    """R2.10: progress alone (no cancel) doesn't change the result either."""
    events: list[LoadProgressEvent] = []
    with_progress = populated_store.load(progress=events.append)
    plain = populated_store.load()

    payload_a = [r.model_dump(mode="json") for r in with_progress.registry.baselines]
    payload_b = [r.model_dump(mode="json") for r in plain.registry.baselines]
    assert payload_a == payload_b
    assert len(events) == 5


# ---------------------------------------------------------------------
# Smoke: cancel-on-empty
# ---------------------------------------------------------------------


def test_cancellation_on_empty_storage_is_no_op(tmp_path: Path) -> None:
    """An empty Storage_Directory cancels cleanly with no events."""
    storage = tmp_path / "empty"
    storage.mkdir()
    config = BaselineConfig(storage_path=str(storage), auto_match=False)
    store = BaselineStore(config)

    events: list[LoadProgressEvent] = []
    cancel_called = [0]

    def cancel() -> bool:
        cancel_called[0] += 1
        return True

    result = store.load(progress=events.append, cancel=cancel)
    assert len(result.registry.baselines) == 0
    assert len(events) == 0
    assert cancel_called[0] == 0, "cancel should not be polled when there are zero candidates"


# ---------------------------------------------------------------------
# LoadProgressEvent dataclass invariants
# ---------------------------------------------------------------------


def test_progress_event_is_frozen() -> None:
    """The LoadProgressEvent dataclass is frozen so callers can't mutate it."""
    from dataclasses import FrozenInstanceError

    event = LoadProgressEvent(path=Path("/tmp/x.yaml"), index=1, total=5)
    with pytest.raises(FrozenInstanceError):
        event.index = 99  # type: ignore[misc]


def test_progress_event_carries_index_and_total() -> None:
    """LoadProgressEvent.index is 1-based and total matches the candidate count."""
    event = LoadProgressEvent(path=Path("/tmp/foo.yaml"), index=3, total=10)
    assert event.index == 3
    assert event.total == 10


# ---------------------------------------------------------------------
# Type signature smoke (R2 contract advertises keyword-only callbacks)
# ---------------------------------------------------------------------


def test_load_keyword_only_callbacks(populated_store: BaselineStore) -> None:
    """progress and cancel must be keyword-only arguments on load()."""
    # Passing positionally raises TypeError — confirms the design
    # decision that the callbacks aren't part of the positional
    # signature.
    with pytest.raises(TypeError):
        populated_store.load(lambda _: None)  # type: ignore[misc]


# ---------------------------------------------------------------------
# Defensive: cancel-token exception propagates
# ---------------------------------------------------------------------


def test_cancel_callback_exception_propagates(populated_store: BaselineStore) -> None:
    """If cancel() itself raises, the exception propagates out of load()."""

    def cancel() -> bool:
        raise RuntimeError("cancel callback exploded")

    with pytest.raises(RuntimeError, match="exploded"):
        populated_store.load(cancel=cancel)


def test_progress_callback_exception_propagates(populated_store: BaselineStore) -> None:
    """If progress() itself raises, the exception propagates out of load()."""

    def progress(_event: LoadProgressEvent) -> None:
        raise ValueError("progress callback exploded")

    with pytest.raises(ValueError, match="exploded"):
        populated_store.load(progress=progress)


# ---------------------------------------------------------------------
# Smoke: BaselineRecord references
# ---------------------------------------------------------------------


def test_loaded_baselines_are_pydantic_validated(populated_store: BaselineStore) -> None:
    """Sanity check that the records produced via the new code path still validate.

    A regression where the new branching in load() somehow returned
    non-validated records would manifest here.
    """
    result = populated_store.load(progress=lambda _: None, cancel=lambda: False)
    for record in result.registry.baselines:
        assert isinstance(record, BaselineRecord)
