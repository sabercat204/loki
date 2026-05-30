"""Format detection: identifies which firmware container formats a binary uses.

Inspects the first 64 KiB of a binary (R2.1) and returns an ordered
list of every recognized container format. When a known wrapper nests
another supported format (e.g. an Intel IFD whose BIOS region holds
UEFI PI volumes), both kinds appear in the list, outermost first
(R2.7).

The detector is intentionally conservative: each per-format check
verifies *every* invariant the v1 contract requires (signatures,
magic bytes, size fields, alignment) and rejects anything ambiguous.
That's because a false positive at this stage routes the binary into
the wrong extractor, which can produce nonsense components.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "DetectedFormat",
    "FormatKind",
    "detect_formats",
]


class FormatKind(StrEnum):
    """v1 supported container formats (R2.9) plus an UNKNOWN sentinel.

    The order of the enum values is *not* significant; ordering of
    detected formats inside :func:`detect_formats` is computed at
    runtime per R2.7.
    """

    INTEL_IFD = "INTEL_IFD"
    UEFI_PI_VOLUME = "UEFI_PI_VOLUME"
    UEFI_CAPSULE = "UEFI_CAPSULE"
    PCI_OPTION_ROM = "PCI_OPTION_ROM"
    INTEL_MICROCODE = "INTEL_MICROCODE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class DetectedFormat:
    """One recognized container format and where it was found."""

    kind: FormatKind
    offset: int
    """Absolute byte offset into the firmware binary."""

    length: int | None
    """Byte length when known from the header; ``None`` otherwise."""


# ---------------------------------------------------------------------
# Per-format magic / signature constants
# ---------------------------------------------------------------------

#: Intel Flash Descriptor "flash valid" signature (FLVALSIG).
#: 4 bytes, little-endian: ``0x0FF0A55A``.
_IFD_FLVALSIG: bytes = bytes((0x5A, 0xA5, 0xF0, 0x0F))
_IFD_FLVALSIG_OFFSET: int = 0x10
_IFD_DESCRIPTOR_ALIGNMENT: int = 0x1000  # 4 KiB per the SPI Programming Guide

#: ``_FVH`` marker sitting in ``EFI_FIRMWARE_VOLUME_HEADER.Signature``.
#: Per UEFI PI 1.8 spec, the field lives at offset ``0x28`` within the
#: ``EFI_FIRMWARE_VOLUME_HEADER`` struct; the FV header itself starts
#: at the FV's base address. ``ZeroVector`` (16 bytes) and
#: ``FileSystemGuid`` (16 bytes) precede the signature, so:
_FV_SIG_OFFSET_IN_HEADER: int = 0x28
_FV_SIG: bytes = b"_FVH"
#: Minimum FV header length we'll accept (zero vector + GUID +
#: FvLength + Signature + Attributes + HeaderLength + Checksum +
#: ExtHeaderOffset + Reserved + Revision + BlockMap[0]).
_FV_HEADER_MIN_LEN: int = 0x40

#: Known UEFI capsule GUIDs we recognize. Lowercase canonical
#: 8-4-4-4-12. See design doc §"Format detection" for the rationale
#: and Open question §1 for the deferral on private vendor GUIDs.
_KNOWN_CAPSULE_GUIDS: frozenset[str] = frozenset(
    {
        # UEFI 2.10: EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID.
        "6dcbd5ed-e82d-4c44-bda1-7194199ad92a",
        # UEFI 2.10: EFI_FMP_CAPSULE_ID_GUID.
        "3b8c8162-188c-46a4-aec9-be43f1d65697",
        # Legacy EFI_CAPSULE_GUID.
        "3b6686bd-0d76-4030-b70e-b5519e2fc5a0",
    }
)

#: PCI option ROM signature: ``55 AA`` at the start of an image.
_OPTION_ROM_SIG: bytes = bytes((0x55, 0xAA))
#: Pointer to PCI Data Structure lives at ``+0x18`` of the option-ROM
#: header (PCI Firmware Spec 3.3 §5.1).
_OPTION_ROM_PCIR_PTR_OFFSET: int = 0x18
_OPTION_ROM_PCIR_SIG: bytes = b"PCIR"
_OPTION_ROM_PCIR_MIN_LEN: int = 0x18  # struct PCI_Data_Structure

#: Intel CPU microcode update header constants. Header version and
#: loader revision are both ``0x00000001`` in the v1 microcode
#: format (Intel SDM Vol. 3A §9.11).
_MICROCODE_HEADER_LEN: int = 48
_MICROCODE_HEADER_VERSION: int = 0x00000001
_MICROCODE_LOADER_REVISION: int = 0x00000001
#: ``total_size = 0`` in the header is a legal shorthand for "default
#: 2048-byte payload + 48-byte header"; treat that as 2048 + 48.
_MICROCODE_DEFAULT_TOTAL_SIZE: int = 2048 + _MICROCODE_HEADER_LEN
#: Reasonable upper bound on a single microcode update blob; anything
#: bigger is almost certainly not a microcode update.
_MICROCODE_MAX_TOTAL_SIZE: int = 1 << 20  # 1 MiB


# ---------------------------------------------------------------------
# Per-format detectors
# ---------------------------------------------------------------------


def _format_guid_le(buf: bytes) -> str:
    """Render a 16-byte buffer as a canonical lowercase 8-4-4-4-12 UUID.

    Microsoft / UEFI GUIDs use mixed-endian on disk: the first three
    components are little-endian, the last two are big-endian.
    """

    if len(buf) != 16:
        raise ValueError("GUID must be exactly 16 bytes")
    d1 = int.from_bytes(buf[0:4], "little")
    d2 = int.from_bytes(buf[4:6], "little")
    d3 = int.from_bytes(buf[6:8], "little")
    d4 = buf[8:10].hex()
    d5 = buf[10:16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}"


def _detect_intel_ifd(buf: bytes) -> DetectedFormat | None:
    """Return ``DetectedFormat(INTEL_IFD, ...)`` if the IFD signature is present.

    R2.2: signature ``0x5A A5 F0 0F`` at offset ``0x10`` of a 4 KiB-
    aligned descriptor region. Most real flash images have the
    descriptor at offset 0; a small number of dumps have a leading
    pad to align the descriptor. The detector scans every 4 KiB
    boundary inside the inspected window.
    """

    for base in range(0, len(buf), _IFD_DESCRIPTOR_ALIGNMENT):
        sig_offset = base + _IFD_FLVALSIG_OFFSET
        if sig_offset + len(_IFD_FLVALSIG) > len(buf):
            return None
        if buf[sig_offset : sig_offset + len(_IFD_FLVALSIG)] == _IFD_FLVALSIG:
            return DetectedFormat(FormatKind.INTEL_IFD, base, length=None)
    return None


def _detect_uefi_pi_volume(buf: bytes) -> DetectedFormat | None:
    """Return ``DetectedFormat(UEFI_PI_VOLUME, ...)`` for the first FV header found.

    R2.3: ``_FVH`` signature inside ``EFI_FIRMWARE_VOLUME_HEADER``.
    The FV header may sit at offset 0 or be embedded later in the
    binary (e.g. an Intel IFD's BIOS region starts mid-image). Scan
    aligned 8-byte boundaries for the signature and validate the
    header is large enough to contain a ``FvLength`` field.
    """

    for candidate_sig_offset in range(0, len(buf) - len(_FV_SIG), 8):
        if buf[candidate_sig_offset : candidate_sig_offset + len(_FV_SIG)] != _FV_SIG:
            continue
        fv_base = candidate_sig_offset - _FV_SIG_OFFSET_IN_HEADER
        if fv_base < 0 or fv_base + _FV_HEADER_MIN_LEN > len(buf):
            continue
        # FvLength is a uint64 at offset 0x20 within EFI_FIRMWARE_VOLUME_HEADER.
        fv_length = struct.unpack_from("<Q", buf, fv_base + 0x20)[0]
        # Sanity bound: a FvLength of 0 or > 4 GiB is malformed.
        if fv_length == 0 or fv_length > (1 << 32):
            length: int | None = None
        else:
            length = int(fv_length)
        return DetectedFormat(FormatKind.UEFI_PI_VOLUME, fv_base, length)
    return None


def _detect_uefi_capsule(buf: bytes) -> DetectedFormat | None:
    """Return ``DetectedFormat(UEFI_CAPSULE, ...)`` for a recognized capsule GUID.

    R2.4: the capsule's ``CapsuleGuid`` (the first 16 bytes of an
    ``EFI_CAPSULE_HEADER``) must match one of the GUIDs in
    :data:`_KNOWN_CAPSULE_GUIDS`. The detector only looks at offset 0
    (capsules are always wrapped at the start of their carrier).
    ``CapsuleImageSize`` lives at offset 0x14 (``UINT32``).
    """

    if len(buf) < 24:
        return None
    guid = _format_guid_le(buf[:16])
    if guid not in _KNOWN_CAPSULE_GUIDS:
        return None
    image_size = struct.unpack_from("<I", buf, 0x14)[0]
    length = int(image_size) if image_size > 0 else None
    return DetectedFormat(FormatKind.UEFI_CAPSULE, 0, length)


def _detect_pci_option_rom(buf: bytes) -> DetectedFormat | None:
    """Return ``DetectedFormat(PCI_OPTION_ROM, ...)`` for an option-ROM image.

    R2.5: ``55 AA`` at offset 0 plus a self-consistent PCI Data
    Structure pointer at offset 0x18 whose target carries a ``PCIR``
    signature.
    """

    if len(buf) < _OPTION_ROM_PCIR_PTR_OFFSET + 2:
        return None
    if buf[:2] != _OPTION_ROM_SIG:
        return None
    pcir_ptr = struct.unpack_from("<H", buf, _OPTION_ROM_PCIR_PTR_OFFSET)[0]
    if pcir_ptr == 0 or pcir_ptr + _OPTION_ROM_PCIR_MIN_LEN > len(buf):
        return None
    if buf[pcir_ptr : pcir_ptr + 4] != _OPTION_ROM_PCIR_SIG:
        return None
    # ImageLength field in the PCI Data Structure is in 512-byte units.
    image_length_units = struct.unpack_from("<H", buf, pcir_ptr + 0x10)[0]
    length = int(image_length_units) * 512 if image_length_units > 0 else None
    return DetectedFormat(FormatKind.PCI_OPTION_ROM, 0, length)


def _detect_intel_microcode(buf: bytes) -> DetectedFormat | None:
    """Return ``DetectedFormat(INTEL_MICROCODE, ...)`` for an Intel microcode update.

    R2.6: header version ``0x1``, loader revision ``0x1``, valid
    ``total_size`` (or the legal default).
    """

    if len(buf) < _MICROCODE_HEADER_LEN:
        return None
    header_version = struct.unpack_from("<I", buf, 0)[0]
    if header_version != _MICROCODE_HEADER_VERSION:
        return None
    loader_revision = struct.unpack_from("<I", buf, 0x14)[0]
    if loader_revision != _MICROCODE_LOADER_REVISION:
        return None
    data_size = struct.unpack_from("<I", buf, 0x1C)[0]
    total_size = struct.unpack_from("<I", buf, 0x20)[0]
    # Per the Intel SDM, total_size = 0 implies the default 2048-byte
    # payload plus the 48-byte header.
    effective_total = total_size if total_size != 0 else _MICROCODE_DEFAULT_TOTAL_SIZE
    if effective_total < _MICROCODE_HEADER_LEN:
        return None
    if effective_total > _MICROCODE_MAX_TOTAL_SIZE:
        return None
    # data_size + header should equal total_size; tolerate the legal
    # default-shorthand case.
    if total_size != 0 and data_size + _MICROCODE_HEADER_LEN > total_size:
        return None
    return DetectedFormat(FormatKind.INTEL_MICROCODE, 0, effective_total)


# ---------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------


def detect_formats(buf: bytes, file_size: int) -> list[DetectedFormat]:
    """Identify every supported container format inside ``buf``.

    The dispatcher runs each per-format detector in turn and assembles
    the ordered output. Outermost wrappers (Intel IFD, UEFI capsule)
    sort first, then nested formats (UEFI PI volumes), then the
    self-contained payload formats (PCI option ROM, Intel microcode).
    The order is what callers rely on for R2.7.

    Args:
        buf: Leading bytes of the firmware binary, as returned by
            :func:`loki.extraction.streaming.StreamingHasher.hash_file`.
            Should be at most :data:`PEEK_SIZE` (64 KiB) — the
            detector deliberately limits itself to that window so it
            doesn't second-guess the streaming-read invariants.
        file_size: Total size of the firmware binary on disk. Used to
            populate the trailing ``UNKNOWN`` entry's ``length`` so
            callers can carve the whole file as one out-of-scope
            error region (R2.8).

    Returns:
        A possibly empty list (``[DetectedFormat(UNKNOWN, 0, file_size)]``
        when nothing is recognized; never just ``[]``). Each
        ``DetectedFormat.offset`` is the byte offset relative to the
        start of the firmware binary.
    """

    if not buf:
        return [DetectedFormat(FormatKind.UNKNOWN, 0, file_size)]

    found: list[DetectedFormat] = []

    # Outer wrappers first.
    ifd = _detect_intel_ifd(buf)
    if ifd is not None:
        found.append(ifd)
    capsule = _detect_uefi_capsule(buf)
    if capsule is not None:
        found.append(capsule)

    # Nested PI volumes.
    fv = _detect_uefi_pi_volume(buf)
    if fv is not None:
        found.append(fv)

    # Self-contained payload formats. Skip these when an outer wrapper
    # was recognized — they share leading-byte ranges with capsules and
    # would produce false positives. For example, a PE32 binary's
    # ``MZ`` is benign here, but real-world capsule payloads can begin
    # with ``55 AA``.
    if ifd is None and capsule is None and fv is None:
        opt_rom = _detect_pci_option_rom(buf)
        if opt_rom is not None:
            found.append(opt_rom)
        microcode = _detect_intel_microcode(buf)
        if microcode is not None:
            found.append(microcode)

    if not found:
        return [DetectedFormat(FormatKind.UNKNOWN, 0, file_size)]
    return found
