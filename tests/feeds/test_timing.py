"""Tests for loki.feeds.timing — Stopwatch context manager."""

from __future__ import annotations

import time

import pytest

from loki.feeds.timing import Stopwatch


class TestStopwatch:
    def test_context_manager_records_duration(self) -> None:
        with Stopwatch() as sw:
            time.sleep(0.01)
        assert sw.duration_ms >= 0

    def test_duration_ms_non_negative(self) -> None:
        sw = Stopwatch()
        sw.start()
        sw.stop()
        assert sw.duration_ms >= 0

    def test_stop_before_start_raises(self) -> None:
        sw = Stopwatch()
        with pytest.raises(RuntimeError, match="before start"):
            sw.stop()

    def test_duration_before_start_raises(self) -> None:
        sw = Stopwatch()
        with pytest.raises(RuntimeError, match="before start"):
            _ = sw.duration_ms

    def test_live_duration_while_running(self) -> None:
        sw = Stopwatch()
        sw.start()
        time.sleep(0.005)
        live = sw.duration_ms
        assert live >= 0
        sw.stop()
        assert sw.duration_ms >= live

    def test_context_manager_stops_on_exit(self) -> None:
        with Stopwatch() as sw:
            pass
        d1 = sw.duration_ms
        time.sleep(0.005)
        d2 = sw.duration_ms
        assert d1 == d2
