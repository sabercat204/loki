"""Intel Flash Descriptor (full-flash) extractor.

Parses the Intel SPI Flash Descriptor at the start of a full-flash
image and yields one :class:`CarvedComponent` per IFD region (BIOS,
ME, GbE, Platform Data, EC, …). For the BIOS region, recurses by
re-running format detection inside the region's bytes and dispatching
to the corresponding extractor — so BIOS-region UEFI volumes are
emitted alongside the BIOS-region wrapper.

Layout (Intel SPI Programming Guide):

  0x10  4   FLVALSIG (``5A A5 F0 0F``)
  0x14  4   FLMAP0 — encodes NR (region count) and FRBA (region base)
  0x40+     FLREGn (one uint32 per region):
            bits[ 0:14] base in 4 KiB units
            bits[16:30] limit in 4 KiB units (inclusive)

Region indices in v1:
  0 — Flash Descriptor itself
  1 — BIOS
  2 — Intel ME
  3 — GbE
  4 — Platform Data
  5 — Embedded Controller
  6 — 10GbE Region 0
  7 — 10GbE Region 1
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

__all__ = ["IfdExtractor", "register"]

_FLVALSIG: bytes = bytes((0x5A, 0xA5, 0xF0, 0x0F))
_FLVALSIG_OFFSET: int = 0x10
_FLMAP0_OFFSET: int = 0x14

_REGION_NAMES: tuple[str, ...] = (
    "FLASH_DESCRIPTOR",
    "BIOS",
    "INTEL_ME",
    "GBE",
    "PLATFORM_DATA",
    "EMBEDDED_CONTROLLER",
    "REGION_6",
    "REGION_7",
)
_BIOS_REGION_INDEX: int = 1
_REGION_UNIT: int = 0x1000  # 4 KiB


class IfdExtractor:
    """Carve a full-flash image into IFD regions and recurse into BIOS."""

    name: ClassVar[str] = "intel_ifd"

    def supports(self, kind: FormatKind) -> bool:
        return kind is FormatKind.INTEL_IFD

    def extract(
        self,
        context: ExtractorContext,
        offset: int,
        length: int | None,
    ) -> Iterator[CarvedComponent]:
        binary = context.binary_path.read_bytes()
        end_offset = len(binary) if length is None else offset + length

        # Confirm the FLVALSIG is at the expected offset within the
        # descriptor; the detector already validated it but we re-check
        # so the extractor is callable independently.
        sig_offset = offset + _FLVALSIG_OFFSET
        if (
            sig_offset + len(_FLVALSIG) > end_offset
            or binary[sig_offset : sig_offset + len(_FLVALSIG)] != _FLVALSIG
        ):
            context.manifest_builder.record_error(
                error_kind="IFD_MISSING_SIGNATURE",
                message=(
                    f"[IFD_MISSING_SIGNATURE] IFD at 0x{offset:x} is missing the FLVALSIG at +0x10"
                ),
                offset=offset,
            )
            return

        flmap0 = struct.unpack_from("<I", binary, offset + _FLMAP0_OFFSET)[0]
        # Number of regions: bits [24:26] (count - 1) per the SPI
        # Programming Guide; v1 hardware uses up to 8 regions.
        nr = ((flmap0 >> 24) & 0x7) + 1
        # Flash Region Base Address: bits [16:23], in 16-byte units.
        frba_units = (flmap0 >> 16) & 0xFF
        frba = offset + (frba_units * 0x10)

        if frba >= end_offset:
            context.manifest_builder.record_error(
                error_kind="IFD_FRBA_OUT_OF_RANGE",
                message=(f"[IFD_FRBA_OUT_OF_RANGE] FRBA at 0x{frba:x} is past file end"),
                offset=offset,
            )
            return

        for region_index in range(nr):
            entry_offset = frba + region_index * 4
            if entry_offset + 4 > end_offset:
                context.manifest_builder.record_error(
                    error_kind="IFD_REGION_TABLE_TRUNCATED",
                    message=(
                        f"[IFD_REGION_TABLE_TRUNCATED] region table at "
                        f"0x{frba:x} is truncated by file end"
                    ),
                    offset=offset,
                )
                return
            flreg = struct.unpack_from("<I", binary, entry_offset)[0]
            base_units = flreg & 0x7FFF
            limit_units = (flreg >> 16) & 0x7FFF
            # An "empty" region is encoded as base > limit per the SPI
            # Programming Guide. Skip those silently.
            if base_units > limit_units:
                continue
            base_byte = offset + base_units * _REGION_UNIT
            # The limit is *inclusive*, so size spans [base, limit + unit).
            size = (limit_units - base_units + 1) * _REGION_UNIT
            if base_byte + size > end_offset:
                context.manifest_builder.record_error(
                    error_kind="IFD_REGION_OUT_OF_RANGE",
                    message=(
                        f"[IFD_REGION_OUT_OF_RANGE] region "
                        f"{_region_name(region_index)} at 0x{base_byte:x} "
                        f"size={size} extends past file end"
                    ),
                    offset=base_byte,
                )
                continue

            yield CarvedComponent(
                offset=base_byte,
                size=size,
                component_type_hint=f"IFD_REGION_{_region_name(region_index)}",
                name=_region_name(region_index),
            )

            # Recurse only into the BIOS region (R3.2 only mandates
            # BIOS-region recursion; ME / GbE / EC are reported as
            # opaque blobs in v1).
            if region_index == _BIOS_REGION_INDEX:
                yield from _recurse_bios(binary, base_byte, size, context)


def _region_name(index: int) -> str:
    if 0 <= index < len(_REGION_NAMES):
        return _REGION_NAMES[index]
    return f"REGION_{index}"


def _recurse_bios(
    binary: bytes,
    base: int,
    size: int,
    context: ExtractorContext,
) -> Iterator[CarvedComponent]:
    """Re-run format detection inside the BIOS region and recurse."""

    region_bytes = binary[base : base + size]
    inner = detect_formats(region_bytes, file_size=size)
    for detected in inner:
        if detected.kind is FormatKind.UNKNOWN:
            continue
        extractor = dispatch_for(detected.kind)
        if extractor is None:
            continue
        # Translate detected.offset (relative to region) into an
        # absolute offset within the source binary.
        absolute_offset = base + detected.offset
        yield from extractor.extract(
            context,
            offset=absolute_offset,
            length=detected.length,
        )


def register() -> None:
    """Register the IFD extractor with the dispatcher."""

    register_extractor(FormatKind.INTEL_IFD, IfdExtractor())
