"""Intel CPU microcode update extractor.

Walks concatenated microcode update blobs and yields one
:class:`CarvedComponent` per blob. Pure Python — does not call into
``uefi_firmware`` or any subprocess tool.

Header layout (Intel SDM Vol. 3A §9.11.1):

  0x00 uint32  header_version    (always 1)
  0x04 uint32  update_revision
  0x08 uint32  date
  0x0C uint32  processor_signature (CPUID)
  0x10 uint32  checksum
  0x14 uint32  loader_revision   (always 1)
  0x18 uint32  processor_flags
  0x1C uint32  data_size
  0x20 uint32  total_size
  0x24 uint32  reserved (3 entries)

A ``total_size`` of 0 is a legal shorthand for the default 2048-byte
payload + 48-byte header.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import ClassVar

from loki.extraction.detection import FormatKind
from loki.extraction.extractors.base import (
    CarvedComponent,
    ExtractorContext,
    register_extractor,
)

__all__ = ["MicrocodeExtractor", "register"]

_HEADER_LEN: int = 48
_HEADER_VERSION: int = 0x00000001
_LOADER_REVISION: int = 0x00000001
_DEFAULT_TOTAL_SIZE: int = 2048 + _HEADER_LEN
_MAX_TOTAL_SIZE: int = 1 << 20  # 1 MiB


class MicrocodeExtractor:
    """Yield one :class:`CarvedComponent` per microcode blob."""

    name: ClassVar[str] = "intel_microcode"

    def supports(self, kind: FormatKind) -> bool:
        return kind is FormatKind.INTEL_MICROCODE

    def extract(
        self,
        context: ExtractorContext,
        offset: int,
        length: int | None,
    ) -> Iterator[CarvedComponent]:
        binary = context.binary_path.read_bytes()
        # Multi-blob microcode: ``length`` from the detector reflects
        # only the *first* blob's ``total_size``, but the binary may
        # carry concatenated blobs. Walk all the way to file end (or
        # ``offset + length`` only when the caller explicitly bounded
        # it to a *larger* range).
        end_offset = (
            len(binary)
            if length is None or offset + length <= offset
            else max(offset + length, len(binary))
        )
        # Cap to file size so we don't read past EOF.
        end_offset = min(end_offset, len(binary))
        cursor = offset

        while cursor + _HEADER_LEN <= end_offset:
            header_version = struct.unpack_from("<I", binary, cursor)[0]
            loader_revision = struct.unpack_from("<I", binary, cursor + 0x14)[0]
            if header_version != _HEADER_VERSION or loader_revision != _LOADER_REVISION:
                # No (more) microcode blob here. Stop walking — we don't
                # try to scan past noise; that's a downstream concern.
                return

            cpuid = struct.unpack_from("<I", binary, cursor + 0x0C)[0]
            update_revision = struct.unpack_from("<I", binary, cursor + 0x04)[0]
            data_size = struct.unpack_from("<I", binary, cursor + 0x1C)[0]
            total_size_field = struct.unpack_from("<I", binary, cursor + 0x20)[0]

            effective_total = total_size_field if total_size_field != 0 else _DEFAULT_TOTAL_SIZE

            # Sanity bounds.
            if effective_total < _HEADER_LEN or effective_total > _MAX_TOTAL_SIZE:
                context.manifest_builder.record_error(
                    error_kind="MICROCODE_INVALID_SIZE",
                    message=(
                        f"[MICROCODE_INVALID_SIZE] microcode blob at 0x{cursor:x} "
                        f"has invalid total_size={effective_total}; stopping walk"
                    ),
                    offset=cursor,
                )
                return

            if cursor + effective_total > end_offset:
                context.manifest_builder.record_error(
                    error_kind="MICROCODE_OVERRUN",
                    message=(
                        f"[MICROCODE_OVERRUN] microcode blob at 0x{cursor:x} "
                        f"claims total_size={effective_total} but only "
                        f"{end_offset - cursor} bytes remain; dropping"
                    ),
                    offset=cursor,
                )
                return

            if total_size_field != 0 and data_size + _HEADER_LEN > total_size_field:
                context.manifest_builder.record_error(
                    error_kind="MICROCODE_INCONSISTENT_SIZE",
                    message=(
                        f"[MICROCODE_INCONSISTENT_SIZE] microcode blob at "
                        f"0x{cursor:x} has data_size {data_size} that overruns "
                        f"total_size {total_size_field}"
                    ),
                    offset=cursor,
                )
                return

            yield CarvedComponent(
                offset=cursor,
                size=effective_total,
                component_type_hint="INTEL_MICROCODE",
                name=f"CPUID={cpuid:08x} REV={update_revision:08x}",
            )

            cursor += effective_total


def register() -> None:
    """Register the microcode extractor with the dispatcher.

    Idempotent. Tests call :func:`clear_registry` then ``register()``
    to reset the registry between runs.
    """

    register_extractor(FormatKind.INTEL_MICROCODE, MicrocodeExtractor())
