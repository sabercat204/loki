"""Synthetic UEFI Platform Initialization (PI) firmware volume builder.

Produces a tiny but format-valid PI volume containing a single FFS
file with a single raw section. Sized at 16 KiB so each block-map
entry covers a clean 4 KiB block.

Layout (UEFI PI 1.8 §3):

  EFI_FIRMWARE_VOLUME_HEADER (zero vector + GUID + length + signature
    + attributes + header length + checksum + ext header offset
    + reserved + revision + block map terminator), then one FFS file:

  EFI_FFS_FILE_HEADER (file GUID + integrity check + type + attrs
    + size[3] + state), then one EFI_COMMON_SECTION_HEADER (size[3]
    + type) followed by section payload.

Field formulas mirror the UEFI PI spec:

* FV header checksum: 16-bit ones'-complement so the whole header
  sums to zero.
* FFS file header checksum: header bytes XORed (excluding the
  IntegrityCheck field itself), then complemented; data field is
  ``0xAA`` when no file checksum is required.
* FFS file state: ``0xF8`` (header valid, data valid, marked-for-use).

Only the fields the v1 extractor actually consumes are populated;
the rest are set to spec-defined defaults (zeros for reserved,
``0xFF`` for erased).
"""

from __future__ import annotations

import struct
import uuid
from pathlib import Path

__all__ = [
    "FFS_CORRUPT_FILE_GUID",
    "FFS_CORRUPT_FILE_NAME",
    "FFS_FILE_GUID",
    "FFS_FILE_NAME",
    "FFS_LZMA_FILE_GUID",
    "FFS_LZMA_FILE_NAME",
    "FFS_TIANO_FILE_GUID",
    "FFS_TIANO_FILE_NAME",
    "FV_GUID",
    "FV_LENGTH",
    "LZMA_INNER_UI_NAME",
    "LZMA_PAYLOAD",
    "TIANO_INNER_UI_NAME",
    "TIANO_PAYLOAD",
    "build",
]


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

#: 16 KiB. Big enough for one block-map entry, small enough for VCS.
FV_LENGTH: int = 0x4000

#: EFI Firmware File System 2 GUID (UEFI PI 1.8 spec).
FV_GUID: uuid.UUID = uuid.UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3")

#: GUID for the synthetic FFS file. Stable across runs.
FFS_FILE_GUID: uuid.UUID = uuid.UUID("11111111-2222-3333-4444-555566667777")

#: UI section name embedded in the FFS file. Surfaces in
#: ``ExtractedComponent.name`` once the real extractor lands.
FFS_FILE_NAME: str = "DemoModule"

#: GUID for the optional FFS file containing a Tiano-compressed section.
FFS_TIANO_FILE_GUID: uuid.UUID = uuid.UUID("22222222-3333-4444-5555-666677778888")
FFS_TIANO_FILE_NAME: str = "TianoCompressedModule"

#: GUID for the optional FFS file containing an LZMA-compressed section.
FFS_LZMA_FILE_GUID: uuid.UUID = uuid.UUID("33333333-4444-5555-6666-777788889999")
FFS_LZMA_FILE_NAME: str = "LzmaCompressedModule"

#: GUID for the optional FFS file containing a corrupt compressed
#: section (Tiano header pointing at junk bytes). Used to exercise
#: the R5.8 decompression-failure path.
FFS_CORRUPT_FILE_GUID: uuid.UUID = uuid.UUID("44444444-5555-6666-7777-8888aaaabbbb")
FFS_CORRUPT_FILE_NAME: str = "CorruptCompressedModule"

#: Inner-section-formatted payload used as the Tiano-compressed body.
#: A UI section ("InnerTianoModule") followed by a 256-byte RAW
#: section, both 4-byte aligned. The inner-section walker should
#: yield exactly two :class:`InnerCarve` entries when this payload
#: is decompressed.
TIANO_PAYLOAD: bytes = (
    # UI section: 4-byte header + UTF-16 NUL-terminated name (32 bytes
    # for "InnerTianoModule" + NUL = 17 chars * 2 = 34 bytes), padded
    # to a 4-byte boundary.
    b"\x26\x00\x00\x15"  # size=0x26 (38), type=0x15 (UI)
    b"I\x00n\x00n\x00e\x00r\x00T\x00i\x00a\x00n\x00o\x00"
    b"M\x00o\x00d\x00u\x00l\x00e\x00\x00\x00"
    b"\x00\x00"  # padding to 4-byte boundary (40 bytes total)
    # RAW section: 4-byte header + 256 bytes of 0x5A.
    + b"\x04\x01\x00\x19"  # size=0x104 (260), type=0x19 (RAW)
    + (b"\x5a" * 256)
)

#: Inner-section-formatted payload used as the LZMA-compressed body.
#: Same shape as :data:`TIANO_PAYLOAD` but a different name and
#: different RAW filler so the two payloads have distinct hashes.
LZMA_PAYLOAD: bytes = (
    # UI section: "InnerLzmaModule" + NUL = 16 chars * 2 = 32 bytes,
    # plus 4-byte header = 36 bytes. Already 4-byte aligned.
    b"\x24\x00\x00\x15"  # size=0x24 (36), type=0x15 (UI)
    b"I\x00n\x00n\x00e\x00r\x00L\x00z\x00m\x00a\x00"
    b"M\x00o\x00d\x00u\x00l\x00e\x00\x00\x00"
    # RAW section: 4-byte header + 256 bytes of 0xA5.
    + b"\x04\x01\x00\x19"  # size=0x104 (260), type=0x19 (RAW)
    + (b"\xa5" * 256)
)

#: UI name embedded in :data:`TIANO_PAYLOAD`'s inner UI section.
TIANO_INNER_UI_NAME: str = "InnerTianoModule"

#: UI name embedded in :data:`LZMA_PAYLOAD`'s inner UI section.
LZMA_INNER_UI_NAME: str = "InnerLzmaModule"

# Block size = 4096; block count = FV_LENGTH / block_size = 4.
_BLOCK_SIZE: int = 0x1000
_BLOCK_COUNT: int = FV_LENGTH // _BLOCK_SIZE

# FV header layout (little-endian):
#   0x00 16  ZeroVector
#   0x10 16  FileSystemGuid
#   0x20 8   FvLength
#   0x28 4   Signature ("_FVH")
#   0x2C 4   Attributes
#   0x30 2   HeaderLength
#   0x32 2   Checksum
#   0x34 2   ExtHeaderOffset
#   0x36 1   Reserved
#   0x37 1   Revision
#   0x38 +   BlockMap entries (8 bytes each), terminated by zeros
_FV_HEADER_LEN: int = 0x48  # 0x40 fixed + one 8-byte entry + 8-byte terminator

# FFS file header layout:
#   0x00 16  FileName (GUID)
#   0x10 2   IntegrityCheck (Header / File checksums)
#   0x12 1   Type
#   0x13 1   Attributes
#   0x14 3   Size (24-bit little-endian)
#   0x17 1   State
_FFS_HEADER_LEN: int = 0x18

#: Files inside an FV body are 8-byte aligned (UEFI PI 1.8 §3.2).
_FFS_FILE_ALIGNMENT: int = 8

# Section header layout (24-bit size + 8-bit type).
_SECTION_HEADER_LEN: int = 0x04

# UEFI PI common section types we use.
_SECTION_TYPE_USER_INTERFACE: int = 0x15
_SECTION_TYPE_RAW: int = 0x19
_SECTION_TYPE_COMPRESSION: int = 0x01
_SECTION_TYPE_GUID_DEFINED: int = 0x02

# Compression-section header layout (UEFI PI 1.8 §3.4):
#   3 bytes   Size (24-bit little-endian)
#   1 byte    Type (0x01)
#   4 bytes   UncompressedLength
#   1 byte    CompressionType (0x00 = none, 0x01 = standard Tiano)
#   payload
_COMPRESSION_HEADER_LEN: int = 0x09
_COMPRESSION_TYPE_STANDARD: int = 0x01

# GUID-defined-section header layout (UEFI PI 1.8 §3.5):
#   3 bytes   Size (24-bit little-endian)
#   1 byte    Type (0x02)
#  16 bytes   SectionDefinitionGuid
#   2 bytes   DataOffset
#   2 bytes   Attributes
#   payload at DataOffset
_GUID_DEFINED_FIXED_HEADER_LEN: int = 0x18

#: LZMA Custom decompress GUID — EE4E5898-3914-4259-9D6E-DC7BD79403CF.
#: Mixed-endian byte order matches how UEFI stores GUIDs on disk.
_LZMA_CUSTOM_GUID_LE: bytes = bytes.fromhex("98584eee143959429d6edc7bd79403cf")

# FFS file types.
_FFS_FILE_TYPE_DRIVER: int = 0x07  # EFI_FV_FILETYPE_DRIVER

# State bits: erase polarity = 1 → 0xF8 means
# (HEADER_VALID | DATA_VALID | NOT_MARKED_FOR_DELETE) inverted to
# header-valid, data-valid, not deleted.
_FFS_FILE_STATE: int = 0xF8


# ---------------------------------------------------------------------
# Checksum helpers
# ---------------------------------------------------------------------


def _u16_zero_sum_checksum(buf: bytes, *, checksum_offset: int) -> int:
    """Return the 16-bit checksum that makes the entire buffer sum to zero.

    UEFI FV checksums are ones'-complement 16-bit additions over the
    header bytes, with the checksum field itself counted as zero.
    """

    if len(buf) % 2 != 0:
        raise ValueError("buffer must be 16-bit aligned for checksum")
    total = 0
    for offset in range(0, len(buf), 2):
        if offset == checksum_offset:
            continue
        total = (total + struct.unpack_from("<H", buf, offset)[0]) & 0xFFFF
    return (-total) & 0xFFFF


def _ffs_header_checksum(buf: bytes) -> int:
    """Return the 8-bit XOR checksum the FFS header contract requires.

    Per UEFI PI 1.8: sum (with overflow) all bytes of the header
    *except* the IntegrityCheck field itself and the State field, then
    take the two's complement.
    """

    accumulator = 0
    for offset, byte in enumerate(buf):
        if offset in (0x10, 0x11, 0x17):  # IntegrityCheck (2 bytes), State
            continue
        accumulator = (accumulator + byte) & 0xFF
    return (-accumulator) & 0xFF


# ---------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------


def _build_ui_section(name: str) -> bytes:
    """Return a UI section ``(name as NUL-terminated UTF-16)``, 4-byte aligned."""
    name_utf16 = (name + "\x00").encode("utf-16-le")
    section_len = _SECTION_HEADER_LEN + len(name_utf16)
    section = bytearray(section_len)
    section[0:3] = section_len.to_bytes(3, "little")
    section[3] = _SECTION_TYPE_USER_INTERFACE
    section[_SECTION_HEADER_LEN:] = name_utf16
    padded_len = (section_len + 3) & ~0x3
    section.extend(b"\x00" * (padded_len - section_len))
    return bytes(section)


def _build_raw_section(payload: bytes) -> bytes:
    """Return a RAW section wrapping ``payload``, 4-byte aligned."""
    section_len = _SECTION_HEADER_LEN + len(payload)
    section = bytearray(section_len)
    section[0:3] = section_len.to_bytes(3, "little")
    section[3] = _SECTION_TYPE_RAW
    section[_SECTION_HEADER_LEN:] = payload
    padded_len = (section_len + 3) & ~0x3
    section.extend(b"\x00" * (padded_len - section_len))
    return bytes(section)


def _build_compression_section(
    *,
    compressed_payload: bytes,
    uncompressed_length: int,
) -> bytes:
    """Return an ``EFI_SECTION_COMPRESSION`` (Tiano standard) section.

    The 9-byte header is followed by the compressed payload bytes;
    the section is padded to a 4-byte boundary.
    """
    body_len = _COMPRESSION_HEADER_LEN + len(compressed_payload)
    section = bytearray(body_len)
    section[0:3] = body_len.to_bytes(3, "little")
    section[3] = _SECTION_TYPE_COMPRESSION
    struct.pack_into("<I", section, 0x04, uncompressed_length)
    section[0x08] = _COMPRESSION_TYPE_STANDARD
    section[_COMPRESSION_HEADER_LEN:] = compressed_payload
    padded_len = (body_len + 3) & ~0x3
    section.extend(b"\x00" * (padded_len - body_len))
    return bytes(section)


def _build_lzma_guided_section(*, compressed_payload: bytes) -> bytes:
    """Return an ``EFI_SECTION_GUID_DEFINED`` LZMA section.

    The 24-byte fixed header (3 size + 1 type + 16 GUID + 2 DataOffset
    + 2 Attributes) is followed by the compressed payload; the section
    is padded to a 4-byte boundary.
    """
    body_len = _GUID_DEFINED_FIXED_HEADER_LEN + len(compressed_payload)
    section = bytearray(body_len)
    section[0:3] = body_len.to_bytes(3, "little")
    section[3] = _SECTION_TYPE_GUID_DEFINED
    section[0x04:0x14] = _LZMA_CUSTOM_GUID_LE
    struct.pack_into("<H", section, 0x14, _GUID_DEFINED_FIXED_HEADER_LEN)  # DataOffset
    struct.pack_into("<H", section, 0x16, 0x0001)  # Attributes: PROCESSING_REQUIRED
    section[_GUID_DEFINED_FIXED_HEADER_LEN:] = compressed_payload
    padded_len = (body_len + 3) & ~0x3
    section.extend(b"\x00" * (padded_len - body_len))
    return bytes(section)


# ---------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------


def _build_ffs_file_from_sections(
    *,
    file_guid: uuid.UUID,
    section_bytes: bytes,
) -> bytes:
    """Wrap pre-built section bytes in an FFS file header + checksums."""

    file_size = _FFS_HEADER_LEN + len(section_bytes)
    header = bytearray(_FFS_HEADER_LEN)
    header[0:16] = file_guid.bytes_le
    # IntegrityCheck.Checksum.File defaults to 0xAA when no checksum.
    header[0x11] = 0xAA
    header[0x12] = _FFS_FILE_TYPE_DRIVER
    header[0x13] = 0x00  # attributes
    header[0x14:0x17] = file_size.to_bytes(3, "little")
    header[0x17] = _FFS_FILE_STATE
    header[0x10] = _ffs_header_checksum(bytes(header))
    return bytes(header) + section_bytes


def _build_ffs_file() -> bytes:
    """Return the canonical FFS file: UI section + raw section."""
    sections = _build_ui_section(FFS_FILE_NAME) + _build_raw_section(b"\xa5" * 256)
    return _build_ffs_file_from_sections(
        file_guid=FFS_FILE_GUID,
        section_bytes=sections,
    )


def _build_tiano_compressed_ffs_file() -> bytes:
    """Return an FFS file containing one Tiano-compressed section.

    The compressed payload round-trips with the
    :class:`UefiFirmwareWrapper` decoder; tests verify the
    extractor's ``decompressed_payload`` matches :data:`TIANO_PAYLOAD`.
    """
    import uefi_firmware.efi_compressor as _ec

    compressed = bytes(_ec.TianoCompress(TIANO_PAYLOAD, len(TIANO_PAYLOAD)))
    sections = _build_ui_section(FFS_TIANO_FILE_NAME) + _build_compression_section(
        compressed_payload=compressed,
        uncompressed_length=len(TIANO_PAYLOAD),
    )
    return _build_ffs_file_from_sections(
        file_guid=FFS_TIANO_FILE_GUID,
        section_bytes=sections,
    )


def _build_lzma_compressed_ffs_file() -> bytes:
    """Return an FFS file containing one LZMA GUID-defined section."""
    import uefi_firmware.efi_compressor as _ec

    compressed = bytes(_ec.LzmaCompress(LZMA_PAYLOAD, len(LZMA_PAYLOAD)))
    sections = _build_ui_section(FFS_LZMA_FILE_NAME) + _build_lzma_guided_section(
        compressed_payload=compressed,
    )
    return _build_ffs_file_from_sections(
        file_guid=FFS_LZMA_FILE_GUID,
        section_bytes=sections,
    )


def _build_corrupt_compressed_ffs_file() -> bytes:
    """Return an FFS file whose Tiano-marked section contains junk bytes.

    Used to exercise the R5.8 failure path: the section header is
    well-formed, the compression type is set to standard Tiano, but
    the payload is unparseable. The extractor must record an
    ``ExtractionError`` and still emit the outer FFS component.
    """
    junk = b"NOT REAL TIANO COMPRESSED DATA, JUST A LOKI TEST CANARY" * 8
    sections = _build_ui_section(FFS_CORRUPT_FILE_NAME) + _build_compression_section(
        compressed_payload=junk,
        uncompressed_length=4096,  # nonsense; the decoder rejects regardless
    )
    return _build_ffs_file_from_sections(
        file_guid=FFS_CORRUPT_FILE_GUID,
        section_bytes=sections,
    )


def _build_fv_header(payload_len: int) -> bytes:
    """Return the 16-byte-aligned FV header for a volume of FV_LENGTH bytes."""

    header = bytearray(_FV_HEADER_LEN)
    # ZeroVector left as 16 zero bytes.
    header[0x10:0x20] = FV_GUID.bytes_le
    struct.pack_into("<Q", header, 0x20, FV_LENGTH)
    header[0x28:0x2C] = b"_FVH"
    # Attributes: any non-zero value with the EFI_FVB2_READ_ENABLED_CAP bit
    # set. 0x000FFEFF is what real-world Intel images typically use.
    struct.pack_into("<I", header, 0x2C, 0x000FFEFF)
    struct.pack_into("<H", header, 0x30, _FV_HEADER_LEN)
    struct.pack_into("<H", header, 0x32, 0x0000)  # placeholder for checksum
    struct.pack_into("<H", header, 0x34, 0x0000)  # ExtHeaderOffset
    header[0x36] = 0x00  # Reserved
    header[0x37] = 0x02  # Revision (PI 1.8: revision 2)
    # BlockMap[0]: 4 blocks of _BLOCK_SIZE bytes each.
    struct.pack_into("<I", header, 0x38, _BLOCK_COUNT)
    struct.pack_into("<I", header, 0x3C, _BLOCK_SIZE)
    # BlockMap terminator: 8 zero bytes at 0x40.
    struct.pack_into("<I", header, 0x40, 0)
    struct.pack_into("<I", header, 0x44, 0)

    # Compute and patch the header checksum.
    checksum = _u16_zero_sum_checksum(bytes(header), checksum_offset=0x32)
    struct.pack_into("<H", header, 0x32, checksum)
    return bytes(header)


def build(
    directory: Path,
    *,
    filename: str = "uefi_volume.bin",
    with_tiano_section: bool = False,
    with_lzma_section: bool = False,
    with_corrupt_compressed_section: bool = False,
) -> Path:
    """Write a synthetic 16 KiB UEFI PI volume.

    The default volume contains the canonical FFS file used by the
    rest of the extraction test suite. Optional kwargs append extra
    FFS files to exercise the decompression path:

    Args:
        directory: Where to write the binary.
        filename: Output filename. Defaults to ``uefi_volume.bin``.
        with_tiano_section: When ``True``, append an FFS file whose
            body is one Tiano-compressed section. The compressed
            payload round-trips with :func:`TianoDecompress` so the
            extractor's ``decompressed_payload`` should match
            :data:`TIANO_PAYLOAD`.
        with_lzma_section: When ``True``, append an FFS file whose
            body is one LZMA GUID-defined section. The decompressed
            payload should match :data:`LZMA_PAYLOAD`.
        with_corrupt_compressed_section: When ``True``, append an
            FFS file whose body is a Tiano-compressed section whose
            payload is junk bytes. The extractor must record a
            ``DECOMPRESSION_FAILED`` :class:`ExtractionError` per
            R5.8 and still emit the outer FFS component.

    Multiple optional kwargs may be combined; the order of files in
    the volume mirrors the order of the parameters above.
    """

    directory.mkdir(parents=True, exist_ok=True)
    out = directory / filename

    # Assemble the FFS file payloads in order. Each file is padded to
    # an 8-byte boundary within the FV body (UEFI PI alignment).
    ffs_files: list[bytes] = [_build_ffs_file()]
    if with_tiano_section:
        ffs_files.append(_build_tiano_compressed_ffs_file())
    if with_lzma_section:
        ffs_files.append(_build_lzma_compressed_ffs_file())
    if with_corrupt_compressed_section:
        ffs_files.append(_build_corrupt_compressed_ffs_file())

    fv_header = _build_fv_header(payload_len=sum(len(f) for f in ffs_files))

    body = bytearray(FV_LENGTH)
    body[: len(fv_header)] = fv_header
    cursor = len(fv_header)
    for ffs in ffs_files:
        # Align the file's start within the FV body to 8 bytes
        # (UEFI PI 1.8 §3.2 "Files are 8-byte aligned within the FV body").
        aligned = (cursor + _FFS_FILE_ALIGNMENT - 1) & ~(_FFS_FILE_ALIGNMENT - 1)
        # Fill alignment gap with 0xFF (erased state).
        for i in range(cursor, aligned):
            body[i] = 0xFF
        cursor = aligned
        body[cursor : cursor + len(ffs)] = ffs
        cursor += len(ffs)

    # Mark erased remainder explicitly with 0xFF so a reader who keys
    # off erased state recognizes it.
    for i in range(cursor, FV_LENGTH):
        body[i] = 0xFF

    out.write_bytes(bytes(body))
    return out
