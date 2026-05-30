"""Designated module for ``time.monotonic()`` access.

The single permitted clock-using module inside ``loki.analysis``
(mirrors the pattern in ``loki.extraction.timing`` and
``loki.classification.timing``). Provides a ``Stopwatch`` context
manager used by ``AnalysisPipeline.run`` to record run duration for
the R20.2 finish-line INFO log. The no-side-channels AST audit
(Property 51) pins this as the only file inside ``loki.analysis``
that may import or call ``time.monotonic()``.
"""

from __future__ import annotations

import time
from types import TracebackType

__all__ = ["Stopwatch"]


class Stopwatch:
    """Monotonic-clock stopwatch used as a context manager.

    Examples::

        with Stopwatch() as sw:
            do_work()
        ms = sw.duration_ms

    The ``duration_ms`` property returns the wall-clock duration in
    milliseconds. Reading it before the stopwatch has stopped
    returns the live elapsed time. Reading it before ``start()`` has
    been called raises ``RuntimeError``.
    """

    def __init__(self) -> None:
        self._started_at: float | None = None
        self._stopped_at: float | None = None

    def start(self) -> None:
        """Start (or restart) the stopwatch."""
        self._started_at = time.monotonic()
        self._stopped_at = None

    def stop(self) -> float:
        """Stop the stopwatch and return ``duration_ms`` milliseconds."""
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
        """Wall-clock duration in milliseconds.

        Live (current ``time.monotonic()`` minus start) when the
        stopwatch has been started but not stopped; frozen at the
        stop time once :meth:`stop` has been called.
        """
        if self._started_at is None:
            raise RuntimeError("Stopwatch.duration_ms accessed before start()")
        end = self._stopped_at if self._stopped_at is not None else time.monotonic()
        return (end - self._started_at) * 1000.0

    @property
    def started(self) -> bool:
        return self._started_at is not None
