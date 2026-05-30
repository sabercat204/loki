"""PCI option ROM extractor.

Walks chained option-ROM images per the PCI Firmware Specification 3.3
§5.1 and yields one :class:`CarvedComponent` per code image. Pure
Python — does not call into ``uefi_firmware`` or any subprocess.

Image header layout:

  0x00 byte[2]  signature (``0x55 0xAA``)
  0x02 byte     init_size in 512-byte units (legacy)
  0x18 uint16   pointer_to_pci_data_structure (relative to image start)

PCI Data Structure:

  0x00 byte[4]  signature ``"PCIR"``
  0x04 uint16   vendor_id
  0x06 uint16   device_id
  0x10 uint16   image_length (in 512-byte units)
  0x14 byte     code_type      (0x00 legacy x86, 0x03 EFI, …)
  0x15 byte     last_image_indicator (bit 7 = last image in chain)
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

__all__ = ["OptionRomExtractor", "register"]

_OPTION_ROM_SIG: bytes = bytes((0x55, 0xAA))
_PCIR_SIG: bytes = b"PCIR"
_PCIR_PTR_OFFSET: int = 0x18
_PCIR_MIN_LEN: int = 0x18

_CODE_TYPE_HINTS: dict[int, str] = {
    0x00: "PCI_LEGACY_X86",
    0x01: "PCI_OPENFIRMWARE",
    0x02: "PCI_HP_PA_RISC",
    0x03: "PCI_EFI",
}


class OptionRomExtractor:
    """Yield one :class:`CarvedComponent` per PCI option-ROM image."""

    name: ClassVar[str] = "pci_option_rom"

    def supports(self, kind: FormatKind) -> bool:
        return kind is FormatKind.PCI_OPTION_ROM

    def extract(
        self,
        context: ExtractorContext,
        offset: int,
        length: int | None,
    ) -> Iterator[CarvedComponent]:
        binary = context.binary_path.read_bytes()
        end_offset = len(binary) if length is None else offset + length
        cursor = offset
        # Cap iterations as a belt-and-braces guard against pathological
        # chains pointing back to themselves.
        max_images = 32

        for _ in range(max_images):
            if cursor + _PCIR_PTR_OFFSET + 2 > end_offset:
                return
            if binary[cursor : cursor + 2] != _OPTION_ROM_SIG:
                return

            pcir_ptr = struct.unpack_from("<H", binary, cursor + _PCIR_PTR_OFFSET)[0]
            pcir_offset = cursor + pcir_ptr
            if pcir_offset + _PCIR_MIN_LEN > end_offset:
                context.manifest_builder.record_error(
                    error_kind="OPTION_ROM_TRUNCATED",
                    message=(
                        f"[OPTION_ROM_TRUNCATED] image at 0x{cursor:x} "
                        f"points to PCI Data Structure beyond file end"
                    ),
                    offset=cursor,
                )
                return
            if binary[pcir_offset : pcir_offset + 4] != _PCIR_SIG:
                context.manifest_builder.record_error(
                    error_kind="OPTION_ROM_BAD_PCIR",
                    message=(
                        f"[OPTION_ROM_BAD_PCIR] image at 0x{cursor:x} "
                        f"has no PCIR signature at +0x{pcir_ptr:x}"
                    ),
                    offset=cursor,
                )
                return

            vendor_id = struct.unpack_from("<H", binary, pcir_offset + 0x04)[0]
            device_id = struct.unpack_from("<H", binary, pcir_offset + 0x06)[0]
            image_length_units = struct.unpack_from("<H", binary, pcir_offset + 0x10)[0]
            code_type = binary[pcir_offset + 0x14]
            last_image_flag = binary[pcir_offset + 0x15]

            if image_length_units == 0:
                context.manifest_builder.record_error(
                    error_kind="OPTION_ROM_INVALID_SIZE",
                    message=(
                        f"[OPTION_ROM_INVALID_SIZE] image at 0x{cursor:x} reports zero ImageLength"
                    ),
                    offset=cursor,
                )
                return

            image_size = image_length_units * 512
            if cursor + image_size > end_offset:
                context.manifest_builder.record_error(
                    error_kind="OPTION_ROM_OVERRUN",
                    message=(
                        f"[OPTION_ROM_OVERRUN] image at 0x{cursor:x} "
                        f"claims size={image_size} but only "
                        f"{end_offset - cursor} bytes remain; dropping"
                    ),
                    offset=cursor,
                )
                return

            yield CarvedComponent(
                offset=cursor,
                size=image_size,
                component_type_hint=_CODE_TYPE_HINTS.get(
                    code_type, f"PCI_CODE_TYPE_0x{code_type:02x}"
                ),
                name=f"vendor=0x{vendor_id:04x} device=0x{device_id:04x}",
            )

            if last_image_flag & 0x80:
                return
            cursor += image_size

        context.manifest_builder.record_error(
            error_kind="OPTION_ROM_CHAIN_TOO_LONG",
            message=(
                "[OPTION_ROM_CHAIN_TOO_LONG] option ROM chain exceeded "
                f"{max_images} images; aborting"
            ),
            offset=offset,
        )


def register() -> None:
    """Register the option-ROM extractor with the dispatcher."""

    register_extractor(FormatKind.PCI_OPTION_ROM, OptionRomExtractor())
