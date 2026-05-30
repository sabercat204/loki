"""Required wrapper around the ``uefi_firmware`` Python package.

This wrapper is the *only* place in :mod:`loki.extraction` that imports
``uefi_firmware`` directly. Required-tool absence is not a recoverable
condition: if the import fails, the pipeline cannot run at all (R4.5
talks about *optional* tools only).

The wrapper exposes two roles:

- **Probe / version capture.** The pipeline runs this once at startup
  and surfaces the result via ``ExtractionResult.tools_available``.
- **Decompression.** Compressed UEFI sections (Tiano and LZMA) are
  decompressed via :meth:`decompress_tiano` and :meth:`decompress_lzma`,
  which translate library-level exceptions into ``None`` returns so
  callers can record an :class:`ExtractionError` per R5.8 instead of
  letting a bad blob crash the whole extraction.

The wrapper stays the only place ``uefi_firmware`` is imported; the
rest of :mod:`loki.extraction` parses UEFI structures by hand to
keep absolute byte offsets sound for the determinism contract.
"""

from __future__ import annotations

import logging
from typing import ClassVar

from loki.extraction.errors import ExtractionPipelineError
from loki.extraction.tools.base import ToolStatus, ToolWrapper

__all__ = ["UefiFirmwareWrapper"]


_LOGGER = logging.getLogger("loki.extraction.tools.uefi_firmware")


class UefiFirmwareWrapper(ToolWrapper):
    """Resolve and expose the ``uefi_firmware`` Python package.

    Attributes:
        name: Always ``"uefi_firmware"``.
        required: Always ``True``.
    """

    name: ClassVar[str] = "uefi_firmware"
    required: ClassVar[bool] = True

    def __init__(self) -> None:
        self._version: str | None = None
        self._status: ToolStatus | None = None

    @property
    def version(self) -> str | None:
        """Resolved package version, populated by :meth:`probe`.

        Returns ``None`` until ``probe()`` has run successfully.
        """
        return self._version

    def probe(self) -> ToolStatus:
        """Import ``uefi_firmware`` and capture its version.

        Returns:
            :attr:`ToolStatus.AVAILABLE` on success.

        Raises:
            ExtractionPipelineError: ``uefi_firmware`` cannot be
                imported. The pipeline cannot proceed without this
                package.
        """

        try:
            import uefi_firmware  # noqa: F401  # tested via getattr below
        except ImportError as exc:  # pragma: no cover - exercised in tests via patch
            raise ExtractionPipelineError(
                "the uefi_firmware Python package is required by loki.extraction "
                "but could not be imported; install it via `pip install uefi_firmware`"
            ) from exc

        # Re-import inside the local scope so the version probe is
        # immune to test-time module reloading. ``getattr`` keeps the
        # wrapper tolerant of older releases that don't expose
        # ``__version__``.
        import uefi_firmware as _module  # intentional local import

        version = getattr(_module, "__version__", None)
        self._version = str(version) if version is not None else None
        self._status = ToolStatus.AVAILABLE
        return self._status

    def shutdown(self) -> None:
        """No-op: the ``uefi_firmware`` package owns no external resources."""

    def decompress_tiano(self, blob: bytes) -> bytes | None:
        """Try to decompress ``blob`` as a UEFI Tiano-compressed payload.

        Used by the UEFI volume extractor to materialize the inner
        contents of ``EFI_SECTION_COMPRESSION`` sections (R3.1, R5.8).
        Returns the decompressed bytes on success or ``None`` on
        failure; the caller's job is to record an :class:`ExtractionError`
        and keep the outer compressed-section component (R5.8).

        ``probe()`` must have run successfully first.
        """

        if self._status is not ToolStatus.AVAILABLE:
            raise RuntimeError("decompress_tiano called before probe(); pipeline ordering bug")
        # Local import: keeps the wrapper the only module importing
        # ``uefi_firmware`` while still working under test patches.
        import uefi_firmware.efi_compressor as _ec

        try:
            return bytes(_ec.TianoDecompress(blob, len(blob)))
        except Exception as exc:
            _LOGGER.warning(
                "TianoDecompress failed on %d-byte blob: %s",
                len(blob),
                exc,
            )
            return None

    def decompress_lzma(self, blob: bytes) -> bytes | None:
        """Try to decompress ``blob`` as a UEFI LZMA-compressed payload.

        Used by the UEFI volume extractor for ``EFI_SECTION_GUID_DEFINED``
        sections whose section GUID is the standard LZMA-Custom
        decompression GUID. Same return-shape contract as
        :meth:`decompress_tiano` — ``None`` on failure, decompressed
        bytes on success.
        """

        if self._status is not ToolStatus.AVAILABLE:
            raise RuntimeError("decompress_lzma called before probe(); pipeline ordering bug")
        import uefi_firmware.efi_compressor as _ec

        try:
            return bytes(_ec.LzmaDecompress(blob, len(blob)))
        except Exception as exc:
            _LOGGER.warning(
                "LzmaDecompress failed on %d-byte blob: %s",
                len(blob),
                exc,
            )
            return None
