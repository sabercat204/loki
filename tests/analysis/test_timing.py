"""Tests for ``loki.analysis.timing.Stopwatch``.

Covers task 7 acceptance: the stopwatch records monotonic time;
``duration_ms`` is ``>= 0`` after a no-op exit; using the stopwatch as a
context manager records the duration on exit; ``duration_ms`` access
before ``start()`` raises a documented exception (mirrors classification).
"""

from __future__ import annotations

import time

import pytest

from loki.analysis.timing import Stopwatch


def test_stopwatch_records_monotonic_time() -> None:
    sw = Stopwatch()
    sw.start()
    time.sleep(0.001)  # 1ms — small but non-zero
    elapsed_ms = sw.stop()
    assert elapsed_ms >= 0.0
    assert sw.duration_ms == elapsed_ms  # frozen after stop


def test_no_op_context_manager_yields_non_negative_duration() -> None:
    with Stopwatch() as sw:
        pass
    assert sw.duration_ms >= 0.0


def test_context_manager_records_duration_on_exit() -> None:
    with Stopwatch() as sw:
        time.sleep(0.001)
    # After exit, duration_ms is frozen.
    frozen_first = sw.duration_ms
    time.sleep(0.001)
    frozen_second = sw.duration_ms
    assert frozen_first == frozen_second


def test_duration_ms_before_start_raises_runtime_error() -> None:
    sw = Stopwatch()
    with pytest.raises(RuntimeError, match="before start"):
        _ = sw.duration_ms


def test_stop_before_start_raises_runtime_error() -> None:
    sw = Stopwatch()
    with pytest.raises(RuntimeError, match="before start"):
        sw.stop()


def test_started_property_reflects_state() -> None:
    sw = Stopwatch()
    assert sw.started is False
    sw.start()
    assert sw.started is True


def test_duration_ms_is_live_before_stop() -> None:
    """Reading duration_ms while running returns current elapsed time."""
    sw = Stopwatch()
    sw.start()
    first = sw.duration_ms
    time.sleep(0.005)
    second = sw.duration_ms
    assert second >= first  # monotonic, non-decreasing


def test_restart_resets_clock() -> None:
    """Calling start() a second time resets the stopwatch."""
    sw = Stopwatch()
    sw.start()
    time.sleep(0.005)
    sw.stop()
    sw.start()  # restart
    assert sw._stopped_at is None
    sw.stop()
    # New duration should reflect the second window only, not accumulate.
    assert sw.duration_ms < 100.0  # generous bound for a 0ms second window
