"""Raw FFS blob extractor.

Handles bare FFS blobs without an enclosing PI volume header. Used
when a vendor ships a partial firmware update that strips the FV
shell. Reuses the FFS-file walker from
:mod:`loki.extraction.extractors.uefi_volume` so the two extractors
stay in lock-step.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import ClassVar

from loki.extraction.detection import FormatKind
from loki.extraction.extractors.base import (
    CarvedComponent,
    ExtractorContext,
)
from loki.extraction.extractors.uefi_volume import walk_ffs_files

__all__ = ["RawFfsExtractor", "register"]


class RawFfsExtractor:
    """Yield one :class:`CarvedComponent` per FFS file in a raw FFS blob."""

    name: ClassVar[str] = "raw_ffs"

    def supports(self, kind: FormatKind) -> bool:
        # v1 detection doesn't have a separate ``RAW_FFS`` kind; the
        # detector reports raw FFS as ``UEFI_PI_VOLUME`` if a leading
        # FV header is present, else as ``UNKNOWN``. Future detection
        # work will add a dedicated kind; until then this extractor is
        # registered manually by the pipeline when needed.
        return False

    def extract(
        self,
        context: ExtractorContext,
        offset: int,
        length: int | None,
    ) -> Iterator[CarvedComponent]:
        binary = context.binary_path.read_bytes()
        end = len(binary) if length is None else offset + length
        yield from walk_ffs_files(binary, offset, end, context)


def register() -> None:
    """Register the raw FFS extractor with the dispatcher.

    No-op in v1: detection doesn't surface a dedicated raw-FFS kind
    yet, so there's no FormatKind for the registry to map against.
    Provided for symmetry with the other extractor modules; future
    detection work will plug it in.
    """
