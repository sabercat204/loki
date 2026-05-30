"""Designated module for ``time.monotonic()`` access.

The single permitted clock-using module inside ``loki.feeds``.
Provides a ``Stopwatch`` context manager mirroring the pattern in
``loki.analysis.timing``.
"""

from __future__ import annotations

import time
from types import TracebackType

__all__ = ["Stopwatch"]


class Stopwatch:
    """Monotonic-clock stopwatch used as a context manager."""

    def __init__(self) -> None:
        self._started_at: float | None = None
        self._stopped_at: float | None = None

    def start(self) -> None:
        self._started_at = time.monotonic()
        self._stopped_at = None

    def stop(self) -> float:
        if self._started_at is None:
            raise RuntimeError("Stopwatch.stop() called before start()")
        self._stopped_at = time.monotonic()
        return self.duration_ms

    def __enter__(self) -> Stopwatch:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._started_at is not None and self._stopped_at is None:
            self.stop()

    @property
    def duration_ms(self) -> float:
        if self._started_at is None:
            raise RuntimeError("Stopwatch.duration_ms accessed before start()")
        end = self._stopped_at if self._stopped_at is not None else time.monotonic()
        return (end - self._started_at) * 1000.0
