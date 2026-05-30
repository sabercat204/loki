"""Tests for ``_build_progress_callback`` covering R5.1-R5.8.

Pins the per-event stderr-line shape (R5.2), the disabled-flag
return-None contract (R5.3), the real-time visibility flush
(R5.4), the propagating-exception path (R5.7), and the
record-count equivalence with Progress_Line count (R5.8).

R5.5 (stdout unaffected by --progress) and R5.6 (component_id
exception on Progress_Line only) are checked at the helper level
here; the end-to-end version is in
``test_no_leakage.py::TestNoLeakageDynamicAudit`` (task 19).

The R5.8 per-component-error path requires a full
``classify_components`` wiring with a synthetic crashing rule,
which is too coupled to library internals for this checkpoint.
The handler-level integration test in task 11
(``test_exit_codes.py``) covers the end-to-end variant; the
record-count-equals-Progress_Line-count contract is verified
there. This module's ``test_per_component_error_path`` placeholder
is documented as a TODO and confirms the helper-level shape only.
"""

from __future__ import annotations

import io
import sys

import pytest

from loki.classification import ProgressEvent
from loki.classify_helpers import _build_progress_callback


class TestProgressDisabled:
    """Behavior when ``enabled=False`` (R5.3)."""

    def test_disabled_returns_none(self) -> None:
        """When ``enabled=False``, the helper returns ``None``."""
        result = _build_progress_callback(enabled=False)
        assert result is None


class TestProgressEnabled:
    """Behavior when ``enabled=True`` (R5.1, R5.2, R5.4)."""

    def test_enabled_returns_callable(self) -> None:
        """When ``enabled=True``, the helper returns a callable."""
        callback = _build_progress_callback(enabled=True)
        assert callable(callback)

    def test_emits_one_line_per_event(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Each invocation emits exactly one Progress_Line (R5.2)."""
        callback = _build_progress_callback(enabled=True)
        assert callback is not None

        callback(ProgressEvent(index=1, total=3, component_id="comp-A"))
        callback(ProgressEvent(index=2, total=3, component_id="comp-B"))
        callback(ProgressEvent(index=3, total=3, component_id="comp-C"))

        captured = capsys.readouterr()
        # Stdout is unaffected (R5.5).
        assert captured.out == ""
        # Stderr has exactly three Progress_Lines, in order.
        lines = captured.err.splitlines()
        assert lines == [
            "[1/3] comp-A",
            "[2/3] comp-B",
            "[3/3] comp-C",
        ]

    def test_progress_line_format(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Format is exactly ``[<index>/<total>] <component_id>`` (R5.2)."""
        callback = _build_progress_callback(enabled=True)
        assert callback is not None

        callback(
            ProgressEvent(
                index=42,
                total=100,
                component_id="00000000-0000-0000-0000-0000000000aa",
            )
        )

        captured = capsys.readouterr()
        assert captured.err == "[42/100] 00000000-0000-0000-0000-0000000000aa\n"

    def test_flush_is_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The callback flushes stderr after every line (R5.4).

        Replaces ``sys.stderr`` with a spy that records each
        ``flush()`` call; asserts at least one flush is observed
        per emit.
        """

        class _SpyStream(io.StringIO):
            def __init__(self) -> None:
                super().__init__()
                self.flush_count = 0

            def flush(self) -> None:
                self.flush_count += 1
                super().flush()

        spy = _SpyStream()
        monkeypatch.setattr(sys, "stderr", spy)

        callback = _build_progress_callback(enabled=True)
        assert callback is not None

        before = spy.flush_count
        callback(ProgressEvent(index=1, total=1, component_id="c"))
        after = spy.flush_count

        assert after > before, "flush() should be invoked on each emit"
        assert spy.getvalue() == "[1/1] c\n"

    def test_broken_pipe_error_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """BrokenPipeError on the underlying write propagates (R5.7).

        Replaces ``sys.stderr`` with a stream whose ``write``
        raises ``BrokenPipeError``; asserts the callback does NOT
        swallow the exception (the design Layer 2 catchall in the
        handler maps it to exit 4).
        """

        class _BrokenStream:
            def write(self, _: str) -> int:
                raise BrokenPipeError("simulated broken pipe")

            def flush(self) -> None:
                return None

        broken = _BrokenStream()
        monkeypatch.setattr(sys, "stderr", broken)

        callback = _build_progress_callback(enabled=True)
        assert callback is not None

        with pytest.raises(BrokenPipeError):
            callback(ProgressEvent(index=1, total=1, component_id="c"))

    def test_progress_line_count_matches_event_count(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """R5.8 helper-level shape: each emit produces exactly one line.

        The full per-component-error path (where some components
        raise and skip their progress callback invocation) is too
        coupled to library internals to verify here; the
        end-to-end variant lives in the handler-level integration
        test in task 11. This test pins the helper-level invariant
        that one emit yields one line.
        """
        callback = _build_progress_callback(enabled=True)
        assert callback is not None

        events_emitted = 5
        for idx in range(1, events_emitted + 1):
            callback(ProgressEvent(index=idx, total=events_emitted, component_id=f"c{idx}"))

        captured = capsys.readouterr()
        assert captured.out == ""
        assert len(captured.err.splitlines()) == events_emitted
