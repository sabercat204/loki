"""Tests for ``loki.extraction.detection`` (task 7).

Each test builds a small synthetic byte buffer, asserts the detector
classifies it correctly, and pins a few negative cases for each
format. R2.7 (outer-first ordering) is covered by
``test_nested_ifd_and_uefi_volume_outer_first``.
"""

from __future__ import annotations

import struct
import uuid

import pytest

from loki.extraction.detection import (
    DetectedFormat,
    FormatKind,
    _format_guid_le,
    detect_formats,
)

# ---------------------------------------------------------------------
# Builders for synthetic header buffers
# ---------------------------------------------------------------------


def _build_ifd_header(*, base: int = 0) -> bytes:
    """Return a minimal Intel IFD descriptor with the FLVALSIG signature."""
    pad = b"\x00" * base
    descriptor = bytearray(0x1000)  # 4 KiB descriptor region
    # FLVALSIG at offset 0x10: 5A A5 F0 0F.
    descriptor[0x10:0x14] = bytes((0x5A, 0xA5, 0xF0, 0x0F))
    return pad + bytes(descriptor)


def _build_fv_header(
    *,
    fv_length: int = 0x10000,
    leading_pad: int = 0,
) -> bytes:
    """Return a minimal ``EFI_FIRMWARE_VOLUME_HEADER`` followed by zero filler.

    Layout (from UEFI PI 1.8):
      0x00 ZeroVector            16 bytes
      0x10 FileSystemGuid        16 bytes
      0x20 FvLength              uint64
      0x28 Signature             "_FVH"
      0x2C Attributes            uint32
      0x30 HeaderLength          uint16
      0x32 Checksum              uint16
      0x34 ExtHeaderOffset       uint16
      0x36 Reserved              1 byte
      0x37 Revision              1 byte
      0x38 BlockMap entries      8 bytes each, terminated by all-zero
    """
    fv = bytearray(0x40)
    # ZeroVector: required to be all zeros.
    fv[0:16] = b"\x00" * 16
    # FileSystemGuid: arbitrary; using the well-known FFS3 GUID for realism.
    fv[16:32] = uuid.UUID("5473c07a-3dcb-4dca-bd6f-1e9689e7349a").bytes_le
    struct.pack_into("<Q", fv, 0x20, fv_length)
    fv[0x28:0x2C] = b"_FVH"
    struct.pack_into("<I", fv, 0x2C, 0x000FFEFF)  # Attributes
    struct.pack_into("<H", fv, 0x30, 0x40)  # HeaderLength
    struct.pack_into("<H", fv, 0x32, 0x0000)  # Checksum (not validated)
    struct.pack_into("<H", fv, 0x34, 0x0000)  # ExtHeaderOffset
    fv[0x36] = 0x00  # Reserved
    fv[0x37] = 0x02  # Revision
    # BlockMap[0] terminates with two zero u32s.
    fv[0x38:0x40] = b"\x00" * 8
    return (b"\x00" * leading_pad) + bytes(fv)


def _build_capsule(guid: str, *, image_size: int = 0x100) -> bytes:
    """Return a minimal ``EFI_CAPSULE_HEADER`` for the given canonical GUID."""
    header = bytearray(0x1C)
    header[:16] = uuid.UUID(guid).bytes_le
    struct.pack_into("<I", header, 0x10, 0x1C)  # HeaderSize
    struct.pack_into("<I", header, 0x14, image_size)  # CapsuleImageSize
    struct.pack_into("<I", header, 0x18, 0)  # Flags
    return bytes(header)


def _build_option_rom(*, image_length_units: int = 4) -> bytes:
    """Return a minimal PCI option ROM: ``55 AA`` plus a PCIR data structure."""
    header = bytearray(0x40)
    header[:2] = bytes((0x55, 0xAA))
    # Pointer-to-PCIR at +0x18.
    struct.pack_into("<H", header, 0x18, 0x20)
    # PCIR struct at +0x20.
    pcir_offset = 0x20
    header[pcir_offset : pcir_offset + 4] = b"PCIR"
    # vendor + device IDs (arbitrary).
    struct.pack_into("<H", header, pcir_offset + 4, 0x8086)  # Intel
    struct.pack_into("<H", header, pcir_offset + 6, 0x1234)
    # ImageLength in 512-byte units at +0x10 of the PCIR struct.
    struct.pack_into("<H", header, pcir_offset + 0x10, image_length_units)
    return bytes(header)


def _build_microcode(*, total_size: int = 0x800) -> bytes:
    """Return a minimal Intel microcode update header.

    Header v1: 48 bytes. Fields used by the detector are header_version
    (offset 0), loader_revision (offset 0x14), data_size (offset 0x1C),
    total_size (offset 0x20).
    """
    header = bytearray(0x30)
    struct.pack_into("<I", header, 0, 1)  # header_version
    struct.pack_into("<I", header, 4, 0xCAFEBABE)  # update_revision
    struct.pack_into("<I", header, 8, 0x202401)  # date (BCD)
    struct.pack_into("<I", header, 12, 0x000506E3)  # processor signature
    struct.pack_into("<I", header, 16, 0xDEADBEEF)  # checksum
    struct.pack_into("<I", header, 0x14, 1)  # loader_revision
    struct.pack_into("<I", header, 0x18, 0x00000003)  # processor_flags
    struct.pack_into("<I", header, 0x1C, total_size - 0x30)  # data_size
    struct.pack_into("<I", header, 0x20, total_size)  # total_size
    return bytes(header)


# ---------------------------------------------------------------------
# _format_guid_le
# ---------------------------------------------------------------------


def test_format_guid_le_round_trips() -> None:
    """The mixed-endian formatter agrees with ``UUID.bytes_le``."""
    canonical = "6dcbd5ed-e82d-4c44-bda1-7194199ad92a"
    raw = uuid.UUID(canonical).bytes_le
    assert _format_guid_le(raw) == canonical


def test_format_guid_le_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        _format_guid_le(b"\x00" * 15)


# ---------------------------------------------------------------------
# Per-format detectors
# ---------------------------------------------------------------------


def test_detect_intel_ifd_at_offset_zero() -> None:
    buf = _build_ifd_header()
    found = detect_formats(buf, file_size=len(buf))
    assert any(d.kind is FormatKind.INTEL_IFD and d.offset == 0 for d in found)


def test_detect_intel_ifd_at_4kib_aligned_offset() -> None:
    """Some flash dumps have a 4 KiB pad before the descriptor."""
    buf = _build_ifd_header(base=0x1000)
    found = detect_formats(buf, file_size=len(buf))
    matches = [d for d in found if d.kind is FormatKind.INTEL_IFD]
    assert matches and matches[0].offset == 0x1000


def test_detect_uefi_pi_volume_at_offset_zero() -> None:
    buf = _build_fv_header(fv_length=0x10000) + b"\x00" * 0x100
    found = detect_formats(buf, file_size=len(buf))
    pi = [d for d in found if d.kind is FormatKind.UEFI_PI_VOLUME]
    assert pi and pi[0].offset == 0
    assert pi[0].length == 0x10000


def test_detect_uefi_pi_volume_records_none_for_invalid_length() -> None:
    """An ``FvLength == 0`` is malformed; the detector still recognizes the FV
    but reports ``length=None`` so callers fall back to file-size bounds."""
    buf = _build_fv_header(fv_length=0)
    found = detect_formats(buf, file_size=len(buf))
    pi = [d for d in found if d.kind is FormatKind.UEFI_PI_VOLUME]
    assert pi and pi[0].length is None


def test_detect_uefi_capsule_known_guid() -> None:
    buf = _build_capsule("6dcbd5ed-e82d-4c44-bda1-7194199ad92a", image_size=0x100)
    found = detect_formats(buf, file_size=len(buf))
    capsules = [d for d in found if d.kind is FormatKind.UEFI_CAPSULE]
    assert capsules and capsules[0].offset == 0
    assert capsules[0].length == 0x100


def test_detect_uefi_capsule_rejects_unknown_guid() -> None:
    """A vendor-private capsule GUID isn't in our v1 set; falls through to UNKNOWN."""
    buf = _build_capsule("00000000-0000-0000-0000-000000000000")
    found = detect_formats(buf, file_size=len(buf))
    assert found == [DetectedFormat(FormatKind.UNKNOWN, 0, len(buf))]


def test_detect_pci_option_rom() -> None:
    buf = _build_option_rom(image_length_units=4)
    found = detect_formats(buf, file_size=len(buf))
    rom = [d for d in found if d.kind is FormatKind.PCI_OPTION_ROM]
    assert rom and rom[0].offset == 0
    # length is in bytes; image_length_units * 512.
    assert rom[0].length == 4 * 512


def test_detect_pci_option_rom_rejects_when_no_pcir_signature() -> None:
    """``55 AA`` without a valid PCIR struct is not a recognized option ROM."""
    buf = bytearray(_build_option_rom())
    # Corrupt the PCIR signature.
    buf[0x20:0x24] = b"XXXX"
    found = detect_formats(bytes(buf), file_size=len(buf))
    assert all(d.kind is not FormatKind.PCI_OPTION_ROM for d in found)


def test_detect_intel_microcode() -> None:
    buf = _build_microcode(total_size=0x800)
    found = detect_formats(buf, file_size=len(buf))
    micro = [d for d in found if d.kind is FormatKind.INTEL_MICROCODE]
    assert micro and micro[0].offset == 0
    assert micro[0].length == 0x800


def test_detect_intel_microcode_default_total_size() -> None:
    """``total_size == 0`` means the default 2048-byte payload."""
    buf = _build_microcode(total_size=0x800)
    # Override total_size to zero, signaling the default.
    mutable = bytearray(buf)
    struct.pack_into("<I", mutable, 0x20, 0)
    # data_size also needs to satisfy the consistency check; legal in default mode.
    struct.pack_into("<I", mutable, 0x1C, 2048)
    found = detect_formats(bytes(mutable), file_size=len(mutable))
    micro = [d for d in found if d.kind is FormatKind.INTEL_MICROCODE]
    assert micro and micro[0].length == 2048 + 48


def test_detect_intel_microcode_rejects_wrong_loader_revision() -> None:
    buf = _build_microcode()
    mutable = bytearray(buf)
    struct.pack_into("<I", mutable, 0x14, 0xFFFFFFFF)
    found = detect_formats(bytes(mutable), file_size=len(mutable))
    assert all(d.kind is not FormatKind.INTEL_MICROCODE for d in found)


# ---------------------------------------------------------------------
# Combinations and unknown handling (R2.7, R2.8)
# ---------------------------------------------------------------------


def test_nested_ifd_and_uefi_volume_outer_first() -> None:
    """R2.7: an Intel IFD wrapping a UEFI PI volume reports IFD first, then PI."""
    ifd = _build_ifd_header()  # 4 KiB descriptor
    fv = _build_fv_header(fv_length=0x10000)
    buf = ifd + b"\x00" * 0x1000 + fv  # IFD, padding, then a PI volume
    found = detect_formats(buf, file_size=len(buf))
    kinds = [d.kind for d in found]
    assert kinds == [FormatKind.INTEL_IFD, FormatKind.UEFI_PI_VOLUME]
    # The PI volume offset is well past the 4 KiB descriptor.
    pi = next(d for d in found if d.kind is FormatKind.UEFI_PI_VOLUME)
    assert pi.offset == len(ifd) + 0x1000


def test_unknown_format_returns_single_unknown_entry() -> None:
    buf = b"definitely not firmware" + b"\x00" * 1024
    found = detect_formats(buf, file_size=len(buf))
    assert found == [DetectedFormat(FormatKind.UNKNOWN, 0, len(buf))]


def test_empty_buffer_returns_unknown() -> None:
    found = detect_formats(b"", file_size=0)
    assert found == [DetectedFormat(FormatKind.UNKNOWN, 0, 0)]


def test_short_buffer_below_64kib_still_works() -> None:
    """The detector tolerates buffers smaller than the canonical 64 KiB peek window."""
    buf = _build_microcode(total_size=0x100)  # well under 64 KiB
    found = detect_formats(buf, file_size=len(buf))
    micro = [d for d in found if d.kind is FormatKind.INTEL_MICROCODE]
    assert micro and micro[0].length == 0x100
