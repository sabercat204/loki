"""UEFI capsule extractor.

Parses ``EFI_CAPSULE_HEADER`` and yields one :class:`CarvedComponent`
for the capsule body, then recurses by re-running format detection
inside the body to surface any embedded UEFI PI volumes.

Layout (UEFI 2.10 §23.4):

  0x00 16  CapsuleGuid
  0x10 4   HeaderSize       (size of the EFI_CAPSULE_HEADER itself)
  0x14 4   Flags
  0x18 4   CapsuleImageSize (total capsule size including header)
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import ClassVar

from loki.extraction.detection import FormatKind, detect_formats
from loki.extraction.extractors.base import (
    CarvedComponent,
    ExtractorContext,
    dispatch_for,
    register_extractor,
)

__all__ = ["CapsuleExtractor", "register"]


class CapsuleExtractor:
    """Yield the capsule body plus any nested UEFI PI volumes."""

    name: ClassVar[str] = "uefi_capsule"

    def supports(self, kind: FormatKind) -> bool:
        return kind is FormatKind.UEFI_CAPSULE

    def extract(
        self,
        context: ExtractorContext,
        offset: int,
        length: int | None,
    ) -> Iterator[CarvedComponent]:
        binary = context.binary_path.read_bytes()
        end_offset = len(binary) if length is None else offset + length

        if offset + 0x1C > end_offset:
            context.manifest_builder.record_error(
                error_kind="CAPSULE_HEADER_TRUNCATED",
                message=(f"[CAPSULE_HEADER_TRUNCATED] capsule header at 0x{offset:x} is truncated"),
                offset=offset,
            )
            return

        header_size = struct.unpack_from("<I", binary, offset + 0x10)[0]
        capsule_image_size = struct.unpack_from("<I", binary, offset + 0x18)[0]

        if header_size <= 0 or offset + header_size > end_offset:
            context.manifest_builder.record_error(
                error_kind="CAPSULE_INVALID_HEADER_SIZE",
                message=(
                    f"[CAPSULE_INVALID_HEADER_SIZE] capsule at 0x{offset:x} "
                    f"reports HeaderSize={header_size}"
                ),
                offset=offset,
            )
            return

        body_offset = offset + header_size
        if capsule_image_size <= header_size:
            body_size = end_offset - body_offset
        else:
            body_size = capsule_image_size - header_size
        if body_offset + body_size > end_offset:
            context.manifest_builder.record_error(
                error_kind="CAPSULE_BODY_OVERRUN",
                message=(
                    f"[CAPSULE_BODY_OVERRUN] capsule body at 0x{body_offset:x} "
                    f"size={body_size} extends past file end"
                ),
                offset=body_offset,
            )
            return

        if body_size <= 0:
            # Header-only capsule (legal: signals a flag-only request).
            return

        yield CarvedComponent(
            offset=body_offset,
            size=body_size,
            component_type_hint="UEFI_CAPSULE_BODY",
            name="capsule body",
        )

        # Recurse inside the body for embedded UEFI PI volumes.
        body_bytes = binary[body_offset : body_offset + body_size]
        inner = detect_formats(body_bytes, file_size=body_size)
        for detected in inner:
            if detected.kind is FormatKind.UNKNOWN:
                continue
            inner_extractor = dispatch_for(detected.kind)
            if inner_extractor is None:
                continue
            absolute_offset = body_offset + detected.offset
            yield from inner_extractor.extract(
                context,
                offset=absolute_offset,
                length=detected.length,
            )


def register() -> None:
    """Register the capsule extractor with the dispatcher."""

    register_extractor(FormatKind.UEFI_CAPSULE, CapsuleExtractor())
