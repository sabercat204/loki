"""Typed exception hierarchy for the extraction subsystem.

Three exception classes leave the subsystem boundary:

- :class:`InvalidInputError` — pre-condition failure
  (path missing, not a regular file, empty); R1.3, R1.4.
- :class:`ManifestConstructionError` — final ``ExtractionManifest``
  failed Pydantic validation; R6.6.
- :class:`ExtractionPipelineError` — generic parent class for the two
  above plus any subsystem-internal failure that escaped expected
  handling.

Three tool-wrapper exception classes are caught *inside* the pipeline
and converted into ``ExtractionError`` records via
``ManifestBuilder.record_error`` (R5.2):

- :class:`ToolWrapperError` — parent class for tool failures.
- :class:`ToolTimedOutError` — subprocess hit its timeout
  (R4.7, R4.9: TIMED_OUT precedence).
- :class:`ToolFailedError` — subprocess exited non-zero without
  timing out (R4.8).

These are control-flow exceptions, not data models — plain
``Exception`` subclasses with typed ``__init__`` signatures.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

__all__ = [
    "ExtractionPipelineError",
    "InvalidInputError",
    "ManifestConstructionError",
    "ToolFailedError",
    "ToolStatus",
    "ToolTimedOutError",
    "ToolWrapperError",
]

ToolStatus = Literal["TIMED_OUT", "FAILED"]


class ExtractionPipelineError(Exception):
    """Base class for every error raised by ``loki.extraction``."""


class InvalidInputError(ExtractionPipelineError):
    """The input path failed pre-conditions (R1.3, R1.4).

    Carries the offending path and a human-readable message.
    """

    def __init__(self, path: Path | str, message: str) -> None:
        self.path = Path(path)
        self.message = message
        super().__init__(f"{message}: {self.path}")


class ManifestConstructionError(ExtractionPipelineError):
    """The final ``ExtractionManifest`` failed Pydantic validation (R6.6).

    Carries the offending field path (when available) and the underlying
    exception so callers can inspect the validation failure.
    """

    def __init__(
        self,
        message: str,
        *,
        field_path: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        self.message = message
        self.field_path = field_path
        self.__cause__ = cause
        prefix = f"{field_path}: " if field_path else ""
        super().__init__(f"{prefix}{message}")


class ToolWrapperError(ExtractionPipelineError):
    """A third-party tool wrapper raised an error (R4.7-4.9).

    Carries the tool name, status (TIMED_OUT or FAILED), the subprocess
    exit status when known, and a redacted excerpt of the tool's stderr.
    Subclasses :class:`ToolTimedOutError` and :class:`ToolFailedError`
    pin a specific status; constructing a ``ToolWrapperError`` directly
    is reserved for unusual cases that don't fit either subclass.
    """

    def __init__(
        self,
        *,
        tool_name: str,
        status: ToolStatus,
        exit_status: int | None,
        stderr_excerpt: str,
    ) -> None:
        self.tool_name = tool_name
        self.status: ToolStatus = status
        self.exit_status = exit_status
        self.stderr_excerpt = stderr_excerpt
        super().__init__(
            f"{tool_name} {status}"
            + (f" (exit {exit_status})" if exit_status is not None else "")
            + (f": {stderr_excerpt}" if stderr_excerpt else "")
        )


class ToolTimedOutError(ToolWrapperError):
    """A tool subprocess hit its timeout (R4.7, R4.9).

    R4.9 (subprocess both timed out and exited non-zero) is handled by
    Python's stdlib semantics: ``subprocess.run(timeout=…)`` raises
    ``TimeoutExpired`` *before* observing the exit status, so this
    class is always raised for timeouts and the FAILED branch is
    skipped — TIMED_OUT precedence is automatic.
    """

    def __init__(
        self,
        *,
        tool_name: str,
        stderr_excerpt: str,
        timeout_seconds: float,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        super().__init__(
            tool_name=tool_name,
            status="TIMED_OUT",
            exit_status=None,
            stderr_excerpt=stderr_excerpt,
        )


class ToolFailedError(ToolWrapperError):
    """A tool subprocess exited non-zero without timing out (R4.8)."""

    def __init__(
        self,
        *,
        tool_name: str,
        exit_status: int,
        stderr_excerpt: str,
    ) -> None:
        super().__init__(
            tool_name=tool_name,
            status="FAILED",
            exit_status=exit_status,
            stderr_excerpt=stderr_excerpt,
        )
