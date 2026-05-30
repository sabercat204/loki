"""Tests for the tool wrapper base layer (task 8).

Covers the three subprocess outcomes (success, timeout, failed),
the TIMED_OUT precedence rule from R4.9, and the stderr redaction
policy.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from loki.extraction.errors import ToolFailedError, ToolTimedOutError
from loki.extraction.tools.base import (
    STDERR_EXCERPT_LIMIT,
    SubprocessToolWrapper,
    ToolStatus,
    ToolWrapper,
    redact_stderr,
)


class _StubWrapper(SubprocessToolWrapper):
    """Minimal concrete wrapper used to exercise the base class."""

    name = "stub-tool"
    required = False

    def probe(self) -> ToolStatus:
        return ToolStatus.AVAILABLE


# ---------------------------------------------------------------------
# redact_stderr
# ---------------------------------------------------------------------


def test_redact_stderr_truncates_at_limit() -> None:
    payload = b"A" * (STDERR_EXCERPT_LIMIT + 50)
    out = redact_stderr(payload)
    assert len(out) <= STDERR_EXCERPT_LIMIT


def test_redact_stderr_strips_control_chars() -> None:
    out = redact_stderr(b"hello\x00\x01world\n")
    assert "\x00" not in out and "\x01" not in out
    assert "hello" in out and "world" in out


def test_redact_stderr_masks_64_char_hex() -> None:
    digest = "a" * 64
    out = redact_stderr(f"the file hashed to {digest}".encode())
    assert "<hash:64>" in out
    assert digest not in out


def test_redact_stderr_masks_32_char_hex() -> None:
    digest = "f" * 32
    out = redact_stderr(f"chunk {digest} failed".encode())
    assert "<hash:32>" in out
    assert digest not in out


def test_redact_stderr_replaces_scratch_path(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    inner = scratch / "leaked.bin"
    out = redact_stderr(
        f"could not parse {inner}".encode(),
        scratch_dir=scratch,
    )
    assert "<scratch>" in out
    assert str(scratch) not in out


def test_redact_stderr_handles_invalid_utf8() -> None:
    """Non-UTF-8 bytes are replaced rather than blowing up."""
    out = redact_stderr(b"\xff\xff\xfe")
    # Each invalid byte produces a replacement character.
    assert out  # non-empty after stripping
    assert all(ord(c) > 0 for c in out)


# ---------------------------------------------------------------------
# SubprocessToolWrapper.run_subprocess
# ---------------------------------------------------------------------


def test_run_subprocess_success_returns_completed_process(tmp_path: Path) -> None:
    completed = subprocess.CompletedProcess(
        args=["stub", "--ok"], returncode=0, stdout=b"ok\n", stderr=b""
    )
    with patch("loki.extraction.tools.base.subprocess.run", return_value=completed):
        result = _StubWrapper().run_subprocess(
            ["stub", "--ok"], timeout_seconds=5.0, scratch_dir=tmp_path
        )
    assert result.returncode == 0
    assert result.stdout == b"ok\n"


def test_run_subprocess_timeout_raises_timed_out(tmp_path: Path) -> None:
    timeout = subprocess.TimeoutExpired(cmd=["stub"], timeout=2.0, output=b"", stderr=b"slow")
    with patch("loki.extraction.tools.base.subprocess.run", side_effect=timeout):
        with pytest.raises(ToolTimedOutError) as excinfo:
            _StubWrapper().run_subprocess(["stub"], timeout_seconds=2.0, scratch_dir=tmp_path)
    err = excinfo.value
    assert err.status == "TIMED_OUT"
    assert err.exit_status is None
    assert err.timeout_seconds == 2.0
    assert "slow" in err.stderr_excerpt


def test_run_subprocess_failure_raises_failed(tmp_path: Path) -> None:
    completed = subprocess.CompletedProcess(
        args=["stub"], returncode=2, stdout=b"", stderr=b"bad input"
    )
    with patch("loki.extraction.tools.base.subprocess.run", return_value=completed):
        with pytest.raises(ToolFailedError) as excinfo:
            _StubWrapper().run_subprocess(["stub"], timeout_seconds=5.0, scratch_dir=tmp_path)
    err = excinfo.value
    assert err.status == "FAILED"
    assert err.exit_status == 2
    assert "bad input" in err.stderr_excerpt


def test_run_subprocess_timeout_takes_precedence_over_failed(
    tmp_path: Path,
) -> None:
    """R4.9: when the subprocess both times out and exits non-zero,
    TIMED_OUT must win.

    The stdlib raises ``TimeoutExpired`` *before* observing the exit
    status, so the FAILED branch is never reached. This test pins
    that semantic in case a future refactor accidentally swaps the
    branches.
    """

    timeout = subprocess.TimeoutExpired(
        cmd=["stub"], timeout=1.0, output=b"", stderr=b"timed out then crashed"
    )
    with patch("loki.extraction.tools.base.subprocess.run", side_effect=timeout):
        with pytest.raises(ToolTimedOutError) as excinfo:
            _StubWrapper().run_subprocess(["stub"], timeout_seconds=1.0, scratch_dir=tmp_path)
    assert excinfo.value.status == "TIMED_OUT"
    # Critically, no FAILED-shaped exception is raised even though the
    # tool *would* have exited non-zero after the timeout signal.


def test_run_subprocess_invokes_with_hardened_defaults(tmp_path: Path) -> None:
    """R4.6 / R4.10: shell=False, argv as list, cwd=scratch_dir."""
    completed = subprocess.CompletedProcess(args=["stub"], returncode=0, stdout=b"", stderr=b"")
    with patch("loki.extraction.tools.base.subprocess.run", return_value=completed) as mock_run:
        _StubWrapper().run_subprocess(
            ["stub", "--flag", "value"],
            timeout_seconds=10.0,
            scratch_dir=tmp_path,
        )
    args, kwargs = mock_run.call_args
    assert args[0] == ["stub", "--flag", "value"]
    assert kwargs["shell"] is False
    assert kwargs["check"] is False
    assert kwargs["cwd"] == str(tmp_path)
    assert kwargs["timeout"] == 10.0


# ---------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------


def test_tool_wrapper_protocol_runtime_check() -> None:
    """The :class:`ToolWrapper` protocol is ``runtime_checkable``."""

    class _Concrete:
        name = "x"
        required = False

        def probe(self) -> ToolStatus:
            return ToolStatus.AVAILABLE

        def shutdown(self) -> None:
            pass

    assert isinstance(_Concrete(), ToolWrapper)
