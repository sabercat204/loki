"""Section-walker for decompressed UEFI payloads.

When the UEFI volume extractor decompresses a Tiano or LZMA section,
the resulting buffer is typically a chain of further UEFI PI sections
(PE32, RAW, UI, etc.). This module walks that chain and yields one
:class:`InnerCarve` per section so the manifest builder can emit
:class:`~loki.models.ExtractedComponent` records for each inner
component.

The walker is a pure function: it takes a byte buffer in and yields
parsed positions out. It never touches the filesystem, the clock,
the network, or any RNG (Property 17 / Property 22 audit). That
makes inner-component derivation deterministic — same decompressed
bytes always produce the same inner carves.

Section header layout (UEFI PI 1.8 §3.3, identical to FFS sections):

  3 bytes  Size (24-bit little-endian)
  1 byte   Type
  payload  (Type-specific, runs from byte 4 to ``Size``)

Sections are 4-byte aligned within the buffer. The walk stops
when:

* fewer than 4 bytes remain (no room for another header), or
* the parsed Size overruns the remaining buffer, or
* the parsed Size is less than the 4-byte minimum.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

__all__ = ["InnerCarve", "walk_decompressed_sections"]

#: Section header layout (must match the FFS section header layout
#: in :mod:`loki.extraction.extractors.uefi_volume`).
_SECTION_HEADER_LEN: int = 0x04

#: Section types we surface. The full UEFI PI taxonomy has many more
#: but the v1 inner walker only needs to identify them by type byte
#: for the ``component_type_hint`` field; the rest of the section
#: contents are opaque to this walker.
_SECTION_TYPE_NAMES: dict[int, str] = {
    0x01: "COMPRESSION",
    0x02: "GUID_DEFINED",
    0x10: "PE32",
    0x11: "PIC",
    0x12: "TE",
    0x13: "DXE_DEPEX",
    0x14: "VERSION",
    0x15: "USER_INTERFACE",
    0x16: "COMPATIBILITY16",
    0x17: "FIRMWARE_VOLUME_IMAGE",
    0x18: "FREEFORM_SUBTYPE_GUID",
    0x19: "RAW",
    0x1B: "PEI_DEPEX",
    0x1C: "MM_DEPEX",
}

#: UI section type — same constant as the FFS walker uses, repeated
#: here so the inner walker can stay independent of
#: :mod:`loki.extraction.extractors.uefi_volume` and not pull in a
#: hard dependency on the FFS file format.
_SECTION_TYPE_USER_INTERFACE: int = 0x15


@dataclass(frozen=True)
class InnerCarve:
    """One section discovered inside a decompressed UEFI payload.

    Attributes:
        offset: Byte offset of the section's first byte (the start
            of the section header) within the decompressed buffer.
            Used as the inner component's ``offset`` in the
            ``ExtractedComponent.offset`` hex string.
        size: On-disk size of the section as parsed from its
            24-bit little-endian Size field. Includes the 4-byte
            section header.
        component_type_hint: Human-readable type label derived from
            the section type byte, e.g. ``"INNER_SECTION_TYPE_PE32"``.
            Falls back to ``"INNER_SECTION_TYPE_0x{:02x}"`` for
            unrecognized section types.
        name: UI section's NUL-terminated UTF-16 name, when the
            section type is ``EFI_SECTION_USER_INTERFACE``.
            ``None`` for every other section type.
    """

    offset: int
    size: int
    component_type_hint: str
    name: str | None


def _read_ui_name(buffer: bytes, section_offset: int, section_size: int) -> str | None:
    """Decode the UI section payload as NUL-terminated UTF-16.

    Empty names return ``None``; the caller does not surface them in
    ``ExtractedComponent.name``.
    """
    payload = buffer[section_offset + _SECTION_HEADER_LEN : section_offset + section_size]
    text = payload.decode("utf-16-le", errors="replace")
    text = text.split("\x00", 1)[0]
    return text or None


def walk_decompressed_sections(buffer: bytes) -> Iterator[InnerCarve]:
    """Walk a decompressed UEFI payload and yield one :class:`InnerCarve` per section.

    Parses sections starting from offset 0 of ``buffer``. Each
    section is yielded with its offset within ``buffer``, its size
    (including header), and a type hint plus optional UI name. The
    walker stops on the first malformed section without raising —
    callers get whatever was found before the malformed entry.

    Args:
        buffer: Decompressed UEFI section payload. Must be a real
            decompressed buffer (Tiano or LZMA output); this walker
            does not validate that the bytes look UEFI-shaped.

    Yields:
        :class:`InnerCarve` instances in document order.
    """

    cursor = 0
    end = len(buffer)
    while cursor + _SECTION_HEADER_LEN <= end:
        section_size = int.from_bytes(buffer[cursor : cursor + 3], "little")
        section_type = buffer[cursor + 3]
        if section_size < _SECTION_HEADER_LEN or cursor + section_size > end:
            # Malformed — abandon the walk. Caller gets whatever's
            # already been yielded.
            return

        type_label = _SECTION_TYPE_NAMES.get(section_type)
        if type_label is not None:
            hint = f"INNER_SECTION_TYPE_{type_label}"
        else:
            hint = f"INNER_SECTION_TYPE_0x{section_type:02x}"

        name: str | None = None
        if section_type == _SECTION_TYPE_USER_INTERFACE:
            name = _read_ui_name(buffer, cursor, section_size)

        yield InnerCarve(
            offset=cursor,
            size=section_size,
            component_type_hint=hint,
            name=name,
        )

        # Advance to the next section, aligned to 4 bytes.
        next_cursor = cursor + section_size
        cursor = (next_cursor + 3) & ~0x3
