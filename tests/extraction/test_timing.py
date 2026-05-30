"""Tests for the timing helpers (task 6)."""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import patch

import pytest

from loki.extraction.timing import (
    Stopwatch,
    check_global_budget,
    global_timeout_budget,
)


@pytest.fixture()
def fake_clock() -> Iterator[list[float]]:
    """Patch ``time.monotonic`` to return values from a controllable list.

    The fixture yields a mutable list; tests append values to drive the
    clock forward without actually sleeping.
    """
    values = [0.0]

    def next_value() -> float:
        return values[-1]

    with patch("loki.extraction.timing.time.monotonic", side_effect=next_value):
        yield values


# ---------------------------------------------------------------------
# Stopwatch
# ---------------------------------------------------------------------


def test_stopwatch_records_elapsed(fake_clock: list[float]) -> None:
    sw = Stopwatch()
    sw.start()
    assert sw.started is True
    fake_clock.append(2.5)
    elapsed = sw.stop()
    assert elapsed == pytest.approx(2.5)
    assert sw.elapsed == pytest.approx(2.5)


def test_stopwatch_context_manager_stops_on_exit(fake_clock: list[float]) -> None:
    sw = Stopwatch()
    with sw:
        fake_clock.append(1.0)
    fake_clock.append(99.0)  # post-exit time should be ignored
    assert sw.elapsed == pytest.approx(1.0)


def test_stopwatch_elapsed_is_live_until_stop(fake_clock: list[float]) -> None:
    sw = Stopwatch()
    sw.start()
    fake_clock.append(0.5)
    assert sw.elapsed == pytest.approx(0.5)
    fake_clock.append(2.0)
    assert sw.elapsed == pytest.approx(2.0)
    sw.stop()
    fake_clock.append(99.0)
    assert sw.elapsed == pytest.approx(2.0)


def test_stopwatch_stop_before_start_raises() -> None:
    with pytest.raises(RuntimeError):
        Stopwatch().stop()


def test_stopwatch_elapsed_before_start_raises() -> None:
    with pytest.raises(RuntimeError):
        _ = Stopwatch().elapsed


# ---------------------------------------------------------------------
# global_timeout_budget
# ---------------------------------------------------------------------


def test_global_timeout_budget_basic() -> None:
    """R5.9: 10 * timeout * max(components, 1)."""
    assert global_timeout_budget(60, 5) == pytest.approx(3000.0)


def test_global_timeout_budget_zero_components_floors_to_one() -> None:
    """When the detector hasn't seen anything, the floor of 1 keeps the budget non-zero."""
    assert global_timeout_budget(60, 0) == pytest.approx(600.0)


def test_global_timeout_budget_rejects_non_positive_timeout() -> None:
    with pytest.raises(ValueError, match=r"timeout_per_component must be > 0"):
        global_timeout_budget(0, 1)
    with pytest.raises(ValueError, match=r"timeout_per_component must be > 0"):
        global_timeout_budget(-1, 1)


def test_global_timeout_budget_rejects_negative_components() -> None:
    with pytest.raises(ValueError, match=r"expected_components must be >= 0"):
        global_timeout_budget(60, -1)


def test_global_timeout_budget_accepts_floats() -> None:
    """``timeout_per_component`` is a ``float``; verify subseconds work."""
    assert global_timeout_budget(0.5, 4) == pytest.approx(20.0)


# ---------------------------------------------------------------------
# check_global_budget
# ---------------------------------------------------------------------


def test_check_global_budget_true_while_under(fake_clock: list[float]) -> None:
    sw = Stopwatch()
    sw.start()
    fake_clock.append(0.5)
    assert check_global_budget(sw, budget_seconds=1.0) is True


def test_check_global_budget_false_when_over(fake_clock: list[float]) -> None:
    sw = Stopwatch()
    sw.start()
    fake_clock.append(1.0)
    assert check_global_budget(sw, budget_seconds=1.0) is False


def test_check_global_budget_rejects_non_positive_budget() -> None:
    sw = Stopwatch()
    sw.start()
    with pytest.raises(ValueError, match=r"budget_seconds must be > 0"):
        check_global_budget(sw, budget_seconds=0.0)


def test_check_global_budget_requires_started_stopwatch() -> None:
    with pytest.raises(RuntimeError):
        check_global_budget(Stopwatch(), budget_seconds=1.0)
