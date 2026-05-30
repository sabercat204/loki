"""Per-component and global timeout helpers.

The pipeline enforces two wall-clock budgets:

- A **per-component** timeout that the
  :class:`~loki.extraction.tools.base.SubprocessToolWrapper` passes
  to ``subprocess.run`` (R8.4). Pure-Python extractors check the
  same budget at component boundaries via :class:`Stopwatch`.
- A **global** timeout that aborts the whole run when the pipeline
  has been busy for ``10 * timeout_per_component * expected_components``
  seconds (R5.9).

Both budgets are expressed in *seconds* (``float``) and are evaluated
against :func:`time.monotonic` so they're immune to wall-clock jumps.
"""

from __future__ import annotations

import time
from types import TracebackType

__all__ = [
    "Stopwatch",
    "check_global_budget",
    "global_timeout_budget",
]


class Stopwatch:
    """Monotonic-clock stopwatch used as a context manager.

    Examples::

        with Stopwatch() as sw:
            do_work()
        elapsed = sw.elapsed
    """

    def __init__(self) -> None:
        self._started_at: float | None = None
        self._stopped_at: float | None = None

    def start(self) -> None:
        """Start (or restart) the stopwatch."""
        self._started_at = time.monotonic()
        self._stopped_at = None

    def stop(self) -> float:
        """Stop the stopwatch and return ``elapsed`` seconds."""
        if self._started_at is None:
            raise RuntimeError("Stopwatch.stop() called before start()")
        self._stopped_at = time.monotonic()
        return self._stopped_at - self._started_at

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
    def elapsed(self) -> float:
        """Seconds since :meth:`start`. Live until :meth:`stop` is called."""
        if self._started_at is None:
            raise RuntimeError("Stopwatch.elapsed accessed before start()")
        end = self._stopped_at if self._stopped_at is not None else time.monotonic()
        return end - self._started_at

    @property
    def started(self) -> bool:
        return self._started_at is not None


def global_timeout_budget(
    timeout_per_component: float,
    expected_components: int,
) -> float:
    """Return the global wall-clock budget for one extraction run.

    Implements R5.9: the global timeout is
    ``10 * timeout_per_component * max(expected_components, 1)``
    seconds. The ``max(..., 1)`` floor keeps the budget non-zero even
    when the format detector hasn't seen any components yet.

    Args:
        timeout_per_component: Per-component timeout from
            ``ExtractionConfig.timeout_per_component``.
            Must be ``> 0``.
        expected_components: Detector's running estimate of the number
            of components. Must be ``>= 0``; clamped to a floor of 1
            for the calculation.

    Returns:
        The global budget in seconds (``float``).

    Raises:
        ValueError: ``timeout_per_component <= 0`` or
            ``expected_components < 0``.
    """

    if timeout_per_component <= 0:
        raise ValueError(f"timeout_per_component must be > 0, got {timeout_per_component}")
    if expected_components < 0:
        raise ValueError(f"expected_components must be >= 0, got {expected_components}")
    return 10.0 * float(timeout_per_component) * float(max(expected_components, 1))


def check_global_budget(stopwatch: Stopwatch, budget_seconds: float) -> bool:
    """Return ``True`` if ``stopwatch.elapsed`` is still under ``budget_seconds``.

    Used by the pipeline between components to decide whether to keep
    extracting or to short-circuit per R5.9.

    Args:
        stopwatch: A started :class:`Stopwatch`.
        budget_seconds: Result of :func:`global_timeout_budget`.

    Returns:
        ``True`` while there's still budget remaining; ``False`` once
        ``elapsed >= budget_seconds``.

    Raises:
        ValueError: ``budget_seconds <= 0``.
        RuntimeError: ``stopwatch`` has not been started.
    """

    if budget_seconds <= 0:
        raise ValueError(f"budget_seconds must be > 0, got {budget_seconds}")
    return stopwatch.elapsed < budget_seconds
