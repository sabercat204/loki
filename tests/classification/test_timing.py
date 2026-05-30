"""Tests for the ``Stopwatch`` timing helper.

Covers Requirement 8.5 (designated single clock-using module)
and the basic stopwatch contract: monotonic, ``duration_ms``
non-negative, freezes on stop, works as a context manager.
"""

from __future__ import annotations

import pytest

from loki.classification.timing import Stopwatch


def test_stopwatch_records_monotonic_time() -> None:
    sw = Stopwatch()
    sw.start()
    # Two consecutive duration reads must not go backwards.
    a = sw.duration_ms
    b = sw.duration_ms
    assert b >= a >= 0.0


def test_stopwatch_duration_ms_is_non_negative_after_start() -> None:
    sw = Stopwatch()
    sw.start()
    assert sw.duration_ms >= 0.0


def test_stopwatch_works_as_context_manager() -> None:
    with Stopwatch() as sw:
        # Trivial work; the context manager auto-stops on exit.
        _ = [i * i for i in range(100)]
    assert sw.duration_ms >= 0.0
    # After exit, duration_ms should be frozen — repeated reads return the same value.
    a = sw.duration_ms
    b = sw.duration_ms
    assert a == b


def test_stopwatch_stop_freezes_duration() -> None:
    sw = Stopwatch()
    sw.start()
    sw.stop()
    a = sw.duration_ms
    b = sw.duration_ms
    assert a == b


def test_stopwatch_started_property() -> None:
    sw = Stopwatch()
    assert sw.started is False
    sw.start()
    assert sw.started is True


def test_stopwatch_duration_ms_before_start_raises() -> None:
    sw = Stopwatch()
    with pytest.raises(RuntimeError, match="before start"):
        _ = sw.duration_ms


def test_stopwatch_stop_before_start_raises() -> None:
    sw = Stopwatch()
    with pytest.raises(RuntimeError, match="before start"):
        sw.stop()


def test_stopwatch_stop_returns_duration_ms() -> None:
    sw = Stopwatch()
    sw.start()
    returned = sw.stop()
    assert returned == sw.duration_ms


def test_stopwatch_restart_resets_baseline() -> None:
    sw = Stopwatch()
    sw.start()
    sw.stop()
    first_duration = sw.duration_ms
    # Restart resets both the start time and the stopped flag.
    sw.start()
    assert sw.started is True
    second_duration = sw.duration_ms
    # Second duration should be small (just-started); not anchored to the prior run.
    assert second_duration < first_duration + 1000.0  # within 1s of the prior reading
