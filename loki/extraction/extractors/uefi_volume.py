"""UEFI Platform Initialization (PI) firmware volume extractor.

Walks an :class:`EFI_FIRMWARE_VOLUME_HEADER` and yields one
:class:`CarvedComponent` per FFS file inside the volume. All offsets
are absolute byte offsets into the source firmware binary so the
manifest builder's deterministic ``component_id`` derivation stays
sound.

When an FFS file contains a compressed section
(:data:`_SECTION_TYPE_COMPRESSION` or
:data:`_SECTION_TYPE_GUID_DEFINED` with the LZMA-Custom GUID), the
extractor attempts to decompress it via the registered
:class:`~loki.extraction.tools.uefi_firmware.UefiFirmwareWrapper`.
On success, the decompressed bytes land on the FFS file's
``CarvedComponent.decompressed_payload`` field for downstream
classification (R3.1). On failure, an :class:`ExtractionError` is
recorded with offset = the section's absolute position in the
source binary and the outer FFS file's ``CarvedComponent`` is still
emitted with ``raw_hash`` covering the on-disk compressed bytes
(R5.8).

Why hand-rolled? The :mod:`uefi_firmware` library doesn't expose
absolute byte offsets for FFS files (it normalizes everything into a
parsed-object tree), and we need those offsets to satisfy R3.6 plus
the determinism contract from R7.2. The library is still loaded —
it's the only way we get Tiano / LZMA decompression in v1 — but the
walk itself runs in pure Python.

FFS file layout (UEFI PI 1.8 §3.2):

  0x00 16  FileName (GUID, mixed-endian)
  0x10 2   IntegrityCheck (Header / File checksums)
  0x12 1   Type
  0x13 1   Attributes
  0x14 3   Size (24-bit little-endian)
  0x17 1   State
  0x18 +   Sections

Files are 8-byte aligned within the FV body. The walk stops when:

* fewer than 24 bytes remain (no room for another header), or
* the next byte is ``0xFF`` (erased — no more files), or
* the parsed FFS Size overruns the remaining FV bytes.
"""

from __future__ import annotations

import struct
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import ClassVar

from loki.extraction.detection import FormatKind
from loki.extraction.extractors.base import (
    CarvedComponent,
    ExtractorContext,
    register_extractor,
)

__all__ = ["UefiVolumeExtractor", "register", "walk_ffs_files"]


# FV header byte offsets we need.
_FV_HEADER_LEN_OFFSET: int = 0x30
_FV_BLOCK_MAP_OFFSET: int = 0x38

_FFS_HEADER_LEN: int = 0x18
_FFS_FILE_ALIGNMENT: int = 8

# Section header offsets within an EFI_COMMON_SECTION_HEADER.
_SECTION_HEADER_LEN: int = 0x04
_SECTION_TYPE_USER_INTERFACE: int = 0x15
_SECTION_TYPE_COMPRESSION: int = 0x01
_SECTION_TYPE_GUID_DEFINED: int = 0x02

# Compression-section header layout (UEFI PI 1.8 §3.4):
#   0x00 3   Size (24-bit little-endian)
#   0x03 1   Type (0x01)
#   0x04 4   UncompressedLength
#   0x08 1   CompressionType (0x00 = none, 0x01 = standard Tiano)
#   0x09 +   Compressed payload
_COMPRESSION_HEADER_LEN: int = 0x09
_COMPRESSION_TYPE_NONE: int = 0x00
_COMPRESSION_TYPE_STANDARD: int = 0x01

# GUID-defined-section header layout (UEFI PI 1.8 §3.5):
#   0x00 3   Size (24-bit little-endian)
#   0x03 1   Type (0x02)
#   0x04 16  SectionDefinitionGuid
#   0x14 2   DataOffset (offset of compressed payload from start of section)
#   0x16 2   Attributes
#   ...      Compressed payload at DataOffset
_GUID_DEFINED_FIXED_HEADER_LEN: int = 0x18  # through Attributes; payload starts at DataOffset

# LZMA Custom decompress GUID — EE4E5898-3914-4259-9D6E-DC7BD79403CF.
# Mixed-endian byte ordering matches how UEFI stores the GUID on
# disk (D1/D2/D3 little-endian, D4/D5 big-endian).
_LZMA_CUSTOM_GUID_LE: bytes = bytes.fromhex("98584eee143959429d6edc7bd79403cf")

# An erased FFS slot is filled with 0xFF; recognizing this lets us
# stop walking at the end of the populated portion of the FV.
_FFS_ERASED_GUID: bytes = b"\xff" * 16


@dataclass(frozen=True)
class _CompressedSection:
    """Bookkeeping for a compressed section discovered inside an FFS file.

    ``algorithm`` is the human-readable name used in error messages
    and the ``component_type_hint`` of any future inner-component
    work; v1 only uses it for diagnostics.
    """

    absolute_offset: int
    """Absolute byte offset of the section header in the source binary."""

    compressed_blob: bytes
    """The compressed payload bytes (post-header) ready to feed to a decoder."""

    algorithm: str
    """``"tiano"`` or ``"lzma"``; identifies the decoder to invoke."""


def _format_guid_le(buf: bytes) -> str:
    """Render a 16-byte mixed-endian GUID as canonical lowercase 8-4-4-4-12."""

    if len(buf) != 16:
        raise ValueError("GUID must be exactly 16 bytes")
    d1 = int.from_bytes(buf[0:4], "little")
    d2 = int.from_bytes(buf[4:6], "little")
    d3 = int.from_bytes(buf[6:8], "little")
    d4 = buf[8:10].hex()
    d5 = buf[10:16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}"


def _read_ffs_size(buf: bytes, offset: int) -> int:
    """Return the 24-bit little-endian Size field at ``offset + 0x14``."""

    raw = buf[offset + 0x14 : offset + 0x17]
    return int.from_bytes(raw, "little")


def _read_ui_section_name(file_bytes: bytes) -> str | None:
    """Walk sections to find the UI section's NUL-terminated UTF-16 name.

    Returns ``None`` if no UI section is present or the name is empty.
    Sections start at offset ``_FFS_HEADER_LEN`` within a file, are
    4-byte aligned, and use a 24-bit little-endian size field.
    """

    cursor = _FFS_HEADER_LEN
    end = len(file_bytes)
    while cursor + _SECTION_HEADER_LEN <= end:
        section_size = int.from_bytes(file_bytes[cursor : cursor + 3], "little")
        section_type = file_bytes[cursor + 3]
        if section_size < _SECTION_HEADER_LEN or cursor + section_size > end:
            return None
        if section_type == _SECTION_TYPE_USER_INTERFACE:
            payload = file_bytes[cursor + _SECTION_HEADER_LEN : cursor + section_size]
            text = payload.decode("utf-16-le", errors="replace")
            # NUL-terminator strip per R3.11.
            text = text.split("\x00", 1)[0]
            return text or None
        # Advance to the next section, aligned to 4 bytes.
        next_cursor = cursor + section_size
        cursor = (next_cursor + 3) & ~0x3
    return None


def _find_compressed_sections(
    file_bytes: bytes,
    file_absolute_offset: int,
) -> list[_CompressedSection]:
    """Walk one FFS file's sections and return its compressed-section bodies.

    Each entry in the returned list captures the absolute offset of
    the section header in the source binary (so error messages can
    name a real position) and the raw compressed bytes ready for the
    Tiano or LZMA decoder.

    Two section types qualify as "compressed" for v1:

    - ``EFI_SECTION_COMPRESSION`` (type 0x01) with compression type
      ``0x01`` (standard Tiano). Compression type ``0x00`` ("none")
      is *not* compressed and is skipped silently.
    - ``EFI_SECTION_GUID_DEFINED`` (type 0x02) whose
      ``SectionDefinitionGuid`` matches the LZMA-Custom decompression
      GUID. Other GUID-defined sections (signatures, GUIDed-attributes,
      vendor-specific) are not in scope for v1 decompression.

    This helper is read-only — it never raises and never mutates the
    input. Malformed sections short-circuit the walk by returning
    whatever was found before the malformed entry.

    Args:
        file_bytes: The full FFS file (header + sections) as a byte
            buffer, sliced from the source binary.
        file_absolute_offset: Where ``file_bytes`` lives in the
            source binary, used to translate section-relative
            offsets into absolute ones.

    Returns:
        A list of :class:`_CompressedSection` entries in the order
        they appear in the file. Empty when no compressed sections
        are present.
    """

    found: list[_CompressedSection] = []
    cursor = _FFS_HEADER_LEN
    end = len(file_bytes)
    while cursor + _SECTION_HEADER_LEN <= end:
        section_size = int.from_bytes(file_bytes[cursor : cursor + 3], "little")
        section_type = file_bytes[cursor + 3]
        if section_size < _SECTION_HEADER_LEN or cursor + section_size > end:
            # Malformed section — abandon further section-level
            # parsing for this file. The outer FFS file is still
            # carved as a component by ``walk_ffs_files``; only the
            # decompression pass is short-circuited.
            return found

        section_absolute_offset = file_absolute_offset + cursor

        if section_type == _SECTION_TYPE_COMPRESSION:
            # Compression-section header is 9 bytes. The 4-byte
            # UncompressedLength field is informational; we ignore
            # it (the decoder verifies the actual output size).
            if section_size < _COMPRESSION_HEADER_LEN:
                # Truncated; treat like a malformed section.
                return found
            compression_type = file_bytes[cursor + 0x08]
            payload = bytes(file_bytes[cursor + _COMPRESSION_HEADER_LEN : cursor + section_size])
            if compression_type == _COMPRESSION_TYPE_STANDARD:
                found.append(
                    _CompressedSection(
                        absolute_offset=section_absolute_offset,
                        compressed_blob=payload,
                        algorithm="tiano",
                    )
                )
            # compression_type == 0x00 ("none") is not compressed —
            # the section payload is already plain. Other compression
            # types are out of scope for v1.

        elif section_type == _SECTION_TYPE_GUID_DEFINED:
            # GUID-defined section header is at least 0x18 bytes
            # (through Attributes); the compressed payload starts at
            # DataOffset.
            if section_size < _GUID_DEFINED_FIXED_HEADER_LEN:
                return found
            section_guid_bytes = bytes(file_bytes[cursor + 0x04 : cursor + 0x14])
            data_offset = int.from_bytes(file_bytes[cursor + 0x14 : cursor + 0x16], "little")
            if data_offset < _GUID_DEFINED_FIXED_HEADER_LEN or data_offset > section_size:
                return found
            if section_guid_bytes == _LZMA_CUSTOM_GUID_LE:
                payload = bytes(file_bytes[cursor + data_offset : cursor + section_size])
                found.append(
                    _CompressedSection(
                        absolute_offset=section_absolute_offset,
                        compressed_blob=payload,
                        algorithm="lzma",
                    )
                )
            # Any other GUID is out of scope.

        # Advance to the next section, aligned to 4 bytes.
        next_cursor = cursor + section_size
        cursor = (next_cursor + 3) & ~0x3
    return found


def _try_decompress(
    section: _CompressedSection,
    context: ExtractorContext,
) -> bytes | None:
    """Decompress ``section`` via the registered ``UefiFirmwareWrapper``.

    Returns the decompressed bytes on success or ``None`` on failure.
    Failure paths:

    - ``context.uefi_firmware`` is ``None`` (test setup with no
      wrapper). Treats as a soft miss.
    - The wrapper's decompress method returns ``None`` (the library
      raised ``Exception("Failed to decompress")``).

    The caller's job is to convert ``None`` into an
    :class:`ExtractionError` per R5.8.
    """

    wrapper = context.uefi_firmware
    if wrapper is None:
        return None
    if section.algorithm == "tiano":
        return wrapper.decompress_tiano(section.compressed_blob)
    if section.algorithm == "lzma":
        return wrapper.decompress_lzma(section.compressed_blob)
    return None  # pragma: no cover - guarded by caller


def _decompress_first_compressed_section(
    file_bytes: bytes,
    *,
    file_absolute_offset: int,
    context: ExtractorContext,
) -> bytes | None:
    """Decompress an FFS file's first compressed section, if any.

    Walks ``file_bytes`` for compressed sections via
    :func:`_find_compressed_sections`, attempts to decompress each
    in document order, and returns the first successfully
    decompressed payload. Sections that fail decompression record an
    :class:`ExtractionError` per R5.8 but do not abort the walk —
    the FFS file's outer ``CarvedComponent`` is always emitted by
    the caller.

    Why "first" only? The v1 ``CarvedComponent.decompressed_payload``
    field carries a single bytes value, not a list. Real FFS files
    almost always contain at most one compressed section (the
    typical pattern is ``Compression(Tiano) -> Raw -> PE32`` inside
    one file), so storing a single payload covers the realistic
    case. If a later spec broadens the contract to carry every
    decompressed section, the bookkeeping moves to the manifest
    builder; this helper would still correctly identify each
    section.

    Returns ``None`` when:

    - The FFS file has no compressed sections.
    - Every compressed section failed to decompress (each failure is
      recorded as an :class:`ExtractionError`).
    - ``context.uefi_firmware`` is ``None`` (test setup); failures
      are recorded the same way for symmetry with production.
    """

    sections = _find_compressed_sections(file_bytes, file_absolute_offset=file_absolute_offset)
    if not sections:
        return None

    first_payload: bytes | None = None
    for section in sections:
        decompressed = _try_decompress(section, context)
        if decompressed is None:
            # R5.8: record an ExtractionError for each failed
            # section. The outer FFS component is still emitted by
            # the caller; this helper just decides what (if
            # anything) lands on ``decompressed_payload``.
            context.manifest_builder.record_error(
                error_kind="DECOMPRESSION_FAILED",
                message=(
                    f"[DECOMPRESSION_FAILED] {section.algorithm} section at "
                    f"0x{section.absolute_offset:x} could not be decompressed"
                ),
                offset=section.absolute_offset,
            )
            continue
        if first_payload is None:
            first_payload = decompressed
    return first_payload


def _validate_guid_format(guid_str: str) -> None:
    """Ensure the rendered GUID parses as a real UUID."""

    uuid.UUID(guid_str)


class UefiVolumeExtractor:
    """Yield one :class:`CarvedComponent` per FFS file inside a PI volume."""

    name: ClassVar[str] = "uefi_volume"

    def supports(self, kind: FormatKind) -> bool:
        return kind is FormatKind.UEFI_PI_VOLUME

    def extract(
        self,
        context: ExtractorContext,
        offset: int,
        length: int | None,
    ) -> Iterator[CarvedComponent]:
        binary = context.binary_path.read_bytes()
        end_offset = len(binary) if length is None else offset + length

        if offset + _FV_BLOCK_MAP_OFFSET > end_offset:
            context.manifest_builder.record_error(
                error_kind="FV_HEADER_TRUNCATED",
                message=(
                    f"[FV_HEADER_TRUNCATED] FV header at 0x{offset:x} is truncated by file end"
                ),
                offset=offset,
            )
            return

        fv_header_len = struct.unpack_from("<H", binary, offset + _FV_HEADER_LEN_OFFSET)[0]
        if fv_header_len <= 0 or offset + fv_header_len > end_offset:
            context.manifest_builder.record_error(
                error_kind="FV_HEADER_INVALID_LENGTH",
                message=(
                    f"[FV_HEADER_INVALID_LENGTH] FV header at 0x{offset:x} "
                    f"reports HeaderLength={fv_header_len}"
                ),
                offset=offset,
            )
            return

        # FFS files start immediately after the FV header. Alignment
        # is relative to the FV base, so a FV that starts at a
        # non-8-aligned absolute offset (e.g. inside a capsule with a
        # 0x1C header) still parses correctly: we measure the
        # post-header gap from ``offset``, not from the absolute
        # cursor.
        post_header = fv_header_len
        post_header = (post_header + _FFS_FILE_ALIGNMENT - 1) & ~(_FFS_FILE_ALIGNMENT - 1)
        cursor = offset + post_header

        yield from walk_ffs_files(binary, cursor, end_offset, context, fv_base=offset)


def walk_ffs_files(
    binary: bytes,
    start: int,
    end: int,
    context: ExtractorContext,
    *,
    fv_base: int | None = None,
) -> Iterator[CarvedComponent]:
    """Walk a contiguous run of FFS files and yield ``CarvedComponent``\\s.

    Used by both :class:`UefiVolumeExtractor` (after skipping the FV
    header) and the raw FFS extractor (which starts at offset 0).
    Records typed errors via ``context.manifest_builder.record_error``
    on size, GUID, or alignment violations and stops the walk on any
    fatal one.

    Args:
        binary: Whole-file byte buffer.
        start: Absolute byte offset of the first FFS file.
        end: Exclusive end of the walk window.
        context: Extractor context (forwarded for error recording).
        fv_base: Optional FV start (absolute) used to compute file
            alignment. When ``None`` (raw FFS), alignment is computed
            from ``start`` directly.
    """

    cursor = start
    while cursor + _FFS_HEADER_LEN <= end:
        guid_bytes = binary[cursor : cursor + 16]
        if guid_bytes == _FFS_ERASED_GUID:
            return
        file_size = _read_ffs_size(binary, cursor)
        if file_size < _FFS_HEADER_LEN:
            context.manifest_builder.record_error(
                error_kind="FFS_FILE_INVALID_SIZE",
                message=(
                    f"[FFS_FILE_INVALID_SIZE] FFS file at 0x{cursor:x} reports size={file_size}"
                ),
                offset=cursor,
            )
            return
        if cursor + file_size > end:
            context.manifest_builder.record_error(
                error_kind="FFS_FILE_OVERRUN",
                message=(
                    f"[FFS_FILE_OVERRUN] FFS file at 0x{cursor:x} "
                    f"claims size={file_size} but only "
                    f"{end - cursor} bytes remain"
                ),
                offset=cursor,
            )
            return

        guid_str = _format_guid_le(guid_bytes)
        try:
            _validate_guid_format(guid_str)
        except ValueError:
            context.manifest_builder.record_error(
                error_kind="FFS_FILE_BAD_GUID",
                message=(f"[FFS_FILE_BAD_GUID] FFS file at 0x{cursor:x} has unparseable GUID"),
                offset=cursor,
            )
            return

        file_bytes = binary[cursor : cursor + file_size]
        file_type = file_bytes[0x12]
        ui_name = _read_ui_section_name(file_bytes)
        decompressed_payload = _decompress_first_compressed_section(
            file_bytes,
            file_absolute_offset=cursor,
            context=context,
        )

        yield CarvedComponent(
            offset=cursor,
            size=file_size,
            component_type_hint=f"FFS_FILE_TYPE_0x{file_type:02x}",
            guid=guid_str,
            name=ui_name,
            decompressed_payload=decompressed_payload,
        )

        # Files are 8-byte aligned within the FV; alignment is computed
        # relative to fv_base when supplied so an FV embedded at a
        # non-8-aligned absolute offset still parses correctly.
        next_cursor = cursor + file_size
        if fv_base is None:
            cursor = (next_cursor + _FFS_FILE_ALIGNMENT - 1) & ~(_FFS_FILE_ALIGNMENT - 1)
        else:
            relative = next_cursor - fv_base
            relative = (relative + _FFS_FILE_ALIGNMENT - 1) & ~(_FFS_FILE_ALIGNMENT - 1)
            cursor = fv_base + relative


def register() -> None:
    """Register the UEFI PI volume extractor with the dispatcher."""

    register_extractor(FormatKind.UEFI_PI_VOLUME, UefiVolumeExtractor())
