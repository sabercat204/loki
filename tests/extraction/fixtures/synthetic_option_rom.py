"""Synthetic PCI option ROM binary builder.

Produces a two-image option ROM exercising the PCI Data Structure
``last_image`` flag chain. Layout per the PCI Firmware Spec 3.3
§5.1.

Image 0 (first):
  0x00 byte[2]  signature 0x55 0xAA
  0x02 byte     init_size in 512-byte units
  0x18 uint16   pointer_to_pci_data_structure (relative to image start)

PCI Data Structure ("PCIR"):
  0x00 byte[4]  signature "PCIR"
  0x04 uint16   vendor_id
  0x06 uint16   device_id
  0x0C uint16   pci_data_structure_length
  0x0E byte     pci_data_structure_revision
  0x0F byte[3]  class_code
  0x10 uint16   image_length (in 512-byte units)
  0x14 byte     code_type
  0x15 byte     last_image_indicator (bit 7 set on the last image)

Image 1 follows directly after image 0, with ``last_image_indicator``
bit 7 set so the extractor knows the chain ends.
"""

from __future__ import annotations

import struct
from pathlib import Path

__all__ = ["IMAGE_SIZE_UNITS", "build"]

# Each synthetic image is exactly 1 KiB (2 x 512-byte units).
IMAGE_SIZE_UNITS: int = 2
_IMAGE_BYTES: int = IMAGE_SIZE_UNITS * 512
_PCIR_OFFSET: int = 0x20  # where we place the PCI Data Structure within each image
_PCIR_LENGTH: int = 0x18

# (vendor_id, device_id, code_type)
_IMAGE_SPECS: tuple[tuple[int, int, int], ...] = (
    (0x8086, 0x1234, 0x00),  # legacy x86 image
    (0x8086, 0x1235, 0x03),  # EFI image
)


def _build_image(
    *,
    vendor_id: int,
    device_id: int,
    code_type: int,
    is_last: bool,
) -> bytes:
    image = bytearray(_IMAGE_BYTES)

    # Option ROM header: 55 AA + size in 512-byte units at +0x02.
    image[0:2] = bytes((0x55, 0xAA))
    image[0x02] = IMAGE_SIZE_UNITS
    # Pointer to the PCI Data Structure at +0x18.
    struct.pack_into("<H", image, 0x18, _PCIR_OFFSET)

    # PCI Data Structure at _PCIR_OFFSET.
    image[_PCIR_OFFSET : _PCIR_OFFSET + 4] = b"PCIR"
    struct.pack_into("<H", image, _PCIR_OFFSET + 0x04, vendor_id)
    struct.pack_into("<H", image, _PCIR_OFFSET + 0x06, device_id)
    struct.pack_into("<H", image, _PCIR_OFFSET + 0x08, 0x0000)  # vital_product_data
    struct.pack_into("<H", image, _PCIR_OFFSET + 0x0A, _PCIR_LENGTH)  # struct length
    image[_PCIR_OFFSET + 0x0C] = 0x03  # PCI DS revision
    image[_PCIR_OFFSET + 0x0D : _PCIR_OFFSET + 0x10] = b"\x00\x00\x00"  # class_code
    struct.pack_into("<H", image, _PCIR_OFFSET + 0x10, IMAGE_SIZE_UNITS)
    struct.pack_into("<H", image, _PCIR_OFFSET + 0x12, 0x0000)  # rev
    image[_PCIR_OFFSET + 0x14] = code_type
    image[_PCIR_OFFSET + 0x15] = 0x80 if is_last else 0x00
    # Reserved bytes; leave zero.

    return bytes(image)


def build(directory: Path, *, filename: str = "option_rom.bin") -> Path:
    """Write a synthetic two-image PCI option ROM."""

    directory.mkdir(parents=True, exist_ok=True)
    out = directory / filename
    images = [
        _build_image(
            vendor_id=vid,
            device_id=did,
            code_type=ct,
            is_last=(idx == len(_IMAGE_SPECS) - 1),
        )
        for idx, (vid, did, ct) in enumerate(_IMAGE_SPECS)
    ]
    out.write_bytes(b"".join(images))
    return out
