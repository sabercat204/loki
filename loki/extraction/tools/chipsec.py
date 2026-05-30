"""Optional wrapper around the chipsec CLI (``chipsec_util``).

Same shape as :class:`UefitoolWrapper`: optional, probe via
``shutil.which``, capture a version string when cheap, fall back to
:attr:`ToolStatus.DEGRADED` if the version probe fails.

**v1 scope.** Probe + version capture only. No v1 extractor routes
work through ``chipsec_util``; the wrapper exists so R4.4's "probe
each optional Tool_Wrapper for availability" contract holds and
the ``tools_available`` map in ``ExtractionResult`` reflects
reality. ``chipsec``-specific extraction work (SPI flash decoding,
config-space carving) is a future spec.

The status the probe returns matches :class:`UefitoolWrapper`:
``MISSING`` / ``DEGRADED`` / ``AVAILABLE``.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import ClassVar

from loki.extraction.tools.base import (
    STDERR_EXCERPT_LIMIT,
    SubprocessToolWrapper,
    ToolStatus,
)

__all__ = ["ChipsecWrapper"]

_BINARY_NAME: str = "chipsec_util"
_VERSION_PROBE_TIMEOUT: float = 5.0


class ChipsecWrapper(SubprocessToolWrapper):
    """Resolve the ``chipsec_util`` CLI and capture its version when present."""

    name: ClassVar[str] = "chipsec"
    required: ClassVar[bool] = False

    def __init__(self) -> None:
        self._executable: str | None = None
        self._version: str | None = None

    @property
    def executable(self) -> str | None:
        return self._executable

    @property
    def version(self) -> str | None:
        return self._version

    def probe(self) -> ToolStatus:
        """Return :attr:`ToolStatus.AVAILABLE` / ``MISSING`` / ``DEGRADED``."""

        path = shutil.which(_BINARY_NAME)
        if path is None:
            return ToolStatus.MISSING
        self._executable = path

        try:
            proc = subprocess.run(
                [path, "--version"],
                capture_output=True,
                timeout=_VERSION_PROBE_TIMEOUT,
                shell=False,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return ToolStatus.DEGRADED

        stream = proc.stdout if proc.stdout else proc.stderr
        first_line = stream.splitlines()[0] if stream else b""
        text = first_line[:STDERR_EXCERPT_LIMIT].decode("utf-8", errors="replace").strip()
        self._version = text or None
        return ToolStatus.AVAILABLE

    def shutdown(self) -> None:
        """No-op."""
