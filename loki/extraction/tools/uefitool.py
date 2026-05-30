"""Optional wrapper around the UEFITool CLI (``UEFIExtract``).

R4.3 / R4.5: optional. When ``UEFIExtract`` is not on ``$PATH`` the
pipeline emits one informational ``ExtractionError`` per missing
optional tool and falls back to the required pure-Python parser.

**v1 scope.** The wrapper currently does probe + version capture
only. No extractor in the v1 pipeline routes work through
``UEFIExtract``; the required pure-Python ``uefi_firmware`` parser
covers every format the v1 spec cares about. The wrapper exists
today so R4.4's "probe each optional Tool_Wrapper for availability"
contract holds and the ``tools_available`` map in
``ExtractionResult`` reflects reality. Future extractors that need
``UEFIExtract``'s deeper section unrolling will route through this
wrapper via :meth:`SubprocessToolWrapper.run_subprocess`.

The status the probe returns:

- ``MISSING`` — ``UEFIExtract`` is not on ``$PATH``.
- ``DEGRADED`` — the binary is on ``$PATH`` but ``UEFIExtract --help``
  failed (timeout or OSError). Future extractors that need this
  wrapper should treat ``DEGRADED`` like ``MISSING`` and fall back.
- ``AVAILABLE`` — the binary is present and the help-banner probe
  succeeded; ``self.version`` is populated with the first line.
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

__all__ = ["UefitoolWrapper"]

_BINARY_NAME: str = "UEFIExtract"
_VERSION_PROBE_TIMEOUT: float = 5.0


class UefitoolWrapper(SubprocessToolWrapper):
    """Resolve the ``UEFIExtract`` CLI and capture its version when present."""

    name: ClassVar[str] = "uefitool"
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
        """Return :attr:`ToolStatus.AVAILABLE` / ``MISSING`` / ``DEGRADED``.

        - ``shutil.which("UEFIExtract")`` decides between AVAILABLE and
          MISSING.
        - When the binary is found, ``UEFIExtract --help`` is invoked
          (UEFITool does not expose ``--version`` directly; the help
          banner carries the version string). On failure of that
          probe, the wrapper degrades to ``DEGRADED`` so callers can
          still attempt extraction but flag the install as suspect.
        """

        path = shutil.which(_BINARY_NAME)
        if path is None:
            return ToolStatus.MISSING
        self._executable = path

        try:
            proc = subprocess.run(
                [path, "--help"],
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
        """No-op: UEFITool owns no resources we need to release."""
