"""Tool wrapper boundary primitives.

All third-party tool access in :mod:`loki.extraction` flows through
this module. Concrete wrappers (:mod:`loki.extraction.tools.uefi_firmware`,
:mod:`loki.extraction.tools.uefitool`, :mod:`loki.extraction.tools.chipsec`)
are the *only* places in the subsystem that import ``subprocess``,
``shutil``, ``uefi_firmware``, or ``chipsec``.

The :class:`SubprocessToolWrapper` ABC centralizes subprocess
invocation so the TIMED_OUT vs FAILED status precedence (R4.7-4.9)
and the stderr redaction policy (R4.7, R10.5) live in exactly one
place. The Python stdlib's ``subprocess.TimeoutExpired`` is raised
*before* observing the child's exit status, so TIMED_OUT precedence
emerges naturally from the control flow — no explicit branch is
needed.
"""

from __future__ import annotations

import re
import subprocess
from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Protocol, runtime_checkable

from loki.extraction.errors import ToolFailedError, ToolTimedOutError

__all__ = [
    "STDERR_EXCERPT_LIMIT",
    "SubprocessToolWrapper",
    "ToolStatus",
    "ToolWrapper",
    "redact_stderr",
]


class ToolStatus(StrEnum):
    """Outcome of a :meth:`ToolWrapper.probe` call."""

    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    DEGRADED = "DEGRADED"


@runtime_checkable
class ToolWrapper(Protocol):
    """Common interface every tool wrapper implements.

    ``required = True`` wrappers cause the pipeline to abort on probe
    failure; ``required = False`` wrappers fall back gracefully (R4.5).
    """

    name: ClassVar[str]
    required: ClassVar[bool]

    def probe(self) -> ToolStatus:
        """Return the wrapper's current availability status."""
        ...

    def shutdown(self) -> None:
        """Idempotent cleanup hook called when the pipeline finishes."""
        ...


#: Maximum bytes of stderr we retain in any error message. Truncation
#: lives at the wrapper layer so messages never grow unboundedly even
#: under chatty subprocess failures.
STDERR_EXCERPT_LIMIT: int = 512


_CONTROL_CHARS = re.compile(rb"[\x00-\x08\x0b-\x1f\x7f]")
_HEX_RUN_64 = re.compile(rb"\b[0-9a-fA-F]{64}\b")
_HEX_RUN_32 = re.compile(rb"\b[0-9a-fA-F]{32}\b")


def redact_stderr(stderr_bytes: bytes, *, scratch_dir: Path | None = None) -> str:
    """Return a redacted, length-bounded UTF-8 excerpt of ``stderr_bytes``.

    Implements the R4.7 / R10.5 redaction policy from the design's
    "Stderr redaction" section:

    - Trim to :data:`STDERR_EXCERPT_LIMIT` bytes.
    - Strip ASCII control characters except whitespace.
    - Replace any path under ``scratch_dir`` with ``<scratch>/...``.
    - Mask any 32- or 64-character hex run with ``<hash:N>``.

    The result is always a printable UTF-8 string (control chars
    stripped, non-UTF-8 bytes replaced).
    """

    truncated = stderr_bytes[:STDERR_EXCERPT_LIMIT]
    cleaned = _CONTROL_CHARS.sub(b"", truncated)
    cleaned = _HEX_RUN_64.sub(b"<hash:64>", cleaned)
    cleaned = _HEX_RUN_32.sub(b"<hash:32>", cleaned)
    text = cleaned.decode("utf-8", errors="replace")

    if scratch_dir is not None:
        scratch_str = str(scratch_dir.resolve())
        if scratch_str and scratch_str in text:
            text = text.replace(scratch_str, "<scratch>")

    return text.strip()


class SubprocessToolWrapper:
    """Base class for wrappers that invoke an external CLI tool.

    Concrete wrappers (:class:`UefitoolWrapper`, :class:`ChipsecWrapper`)
    inherit from this class and use :meth:`run_subprocess` rather than
    calling :func:`subprocess.run` directly. The class is intentionally
    not abstract — :meth:`probe` raises ``NotImplementedError`` so the
    base behaves as if it were abstract for that one method, but
    leaving the other methods concrete keeps the wrapper composable
    (a wrapper that doesn't need a custom ``shutdown`` simply inherits
    the no-op).
    """

    name: ClassVar[str] = "<unset>"
    required: ClassVar[bool] = False

    def run_subprocess(
        self,
        argv: list[str],
        *,
        timeout_seconds: float,
        scratch_dir: Path,
    ) -> subprocess.CompletedProcess[bytes]:
        """Run ``argv`` under ``cwd=scratch_dir`` with hardened defaults.

        Enforces R4.6 (no shell, explicit argv list), R4.7 / R4.9
        (TIMED_OUT precedence via stdlib semantics), R4.8 (FAILED on
        non-zero exit), and R4.10 (sandboxed cwd).

        Args:
            argv: Argument vector. ``argv[0]`` is the program;
                arguments are passed as a list rather than a shell
                string.
            timeout_seconds: Wall-clock timeout. Forwarded to
                :func:`subprocess.run`.
            scratch_dir: Directory the pipeline owns; used as ``cwd``
                so the child cannot scribble outside the sandbox.

        Returns:
            The completed process when the child exits with status 0.

        Raises:
            ToolTimedOutError: timeout tripped (R4.7).
            ToolFailedError: child exited non-zero without timing out
                (R4.8).
        """

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout_seconds,
                cwd=str(scratch_dir),
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stderr_bytes = exc.stderr if isinstance(exc.stderr, bytes) else b""
            raise ToolTimedOutError(
                tool_name=self.name,
                stderr_excerpt=redact_stderr(stderr_bytes, scratch_dir=scratch_dir),
                timeout_seconds=float(timeout_seconds),
            ) from exc

        if proc.returncode != 0:
            raise ToolFailedError(
                tool_name=self.name,
                exit_status=int(proc.returncode),
                stderr_excerpt=redact_stderr(proc.stderr, scratch_dir=scratch_dir),
            )

        return proc

    def probe(self) -> ToolStatus:  # pragma: no cover - overridden
        raise NotImplementedError

    def shutdown(self) -> None:
        """No-op cleanup; concrete wrappers override when needed.

        Empty by design — most wrappers own no resources that need
        explicit teardown. Concrete subclasses that *do* own resources
        override this method.
        """
        return None
