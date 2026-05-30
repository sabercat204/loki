"""Tests for the inner-section walker (decompressed UEFI payloads)."""

from __future__ import annotations

import pytest

from loki.extraction.inner_carve import InnerCarve, walk_decompressed_sections
from tests.extraction.fixtures import synthetic_uefi_volume

# ---------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------


def test_walks_tiano_payload_to_two_sections() -> None:
    """The TIANO_PAYLOAD fixture decodes to UI + RAW."""
    carves = list(walk_decompressed_sections(synthetic_uefi_volume.TIANO_PAYLOAD))
    assert len(carves) == 2
    # UI section first.
    assert carves[0].component_type_hint == "INNER_SECTION_TYPE_USER_INTERFACE"
    assert carves[0].name == synthetic_uefi_volume.TIANO_INNER_UI_NAME
    assert carves[0].offset == 0
    # RAW section second, at the 4-byte-aligned offset after the UI section.
    assert carves[1].component_type_hint == "INNER_SECTION_TYPE_RAW"
    assert carves[1].name is None
    # 38-byte UI section rounded up to 40 (4-byte aligned) puts RAW at 0x28.
    assert carves[1].offset == 0x28


def test_walks_lzma_payload_to_two_sections() -> None:
    """LZMA_PAYLOAD has a slightly different shape but the same two-section count."""
    carves = list(walk_decompressed_sections(synthetic_uefi_volume.LZMA_PAYLOAD))
    assert len(carves) == 2
    assert carves[0].component_type_hint == "INNER_SECTION_TYPE_USER_INTERFACE"
    assert carves[0].name == synthetic_uefi_volume.LZMA_INNER_UI_NAME
    assert carves[1].component_type_hint == "INNER_SECTION_TYPE_RAW"


def test_walker_yields_in_document_order() -> None:
    """Sections are yielded in the order they appear in the buffer."""
    carves = list(walk_decompressed_sections(synthetic_uefi_volume.TIANO_PAYLOAD))
    offsets = [c.offset for c in carves]
    assert offsets == sorted(offsets)


def test_walker_returns_inner_carve_dataclass() -> None:
    """Every yielded value is an :class:`InnerCarve` instance."""
    carves = list(walk_decompressed_sections(synthetic_uefi_volume.TIANO_PAYLOAD))
    assert all(isinstance(c, InnerCarve) for c in carves)


def test_walker_carves_size_includes_section_header() -> None:
    """``InnerCarve.size`` matches the section's full on-disk length."""
    buf = synthetic_uefi_volume.TIANO_PAYLOAD
    carves = list(walk_decompressed_sections(buf))
    # Sum of carved sizes plus inter-section padding equals the total
    # buffer length.
    cursor = 0
    for carve in carves:
        # Sections are 4-byte aligned within the buffer.
        cursor = (cursor + 3) & ~0x3
        assert cursor == carve.offset
        cursor += carve.size


# ---------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------


def test_empty_buffer_yields_nothing() -> None:
    """Walking an empty buffer is safe and yields zero carves."""
    assert list(walk_decompressed_sections(b"")) == []


def test_buffer_smaller_than_header_yields_nothing() -> None:
    """A buffer smaller than the 4-byte section header yields nothing."""
    assert list(walk_decompressed_sections(b"\x00\x00\x00")) == []


def test_malformed_size_field_stops_walk() -> None:
    """A section whose size overruns the buffer ends the walk silently.

    The walker is read-only; it never raises. Callers get whatever
    was found before the malformed entry.
    """
    # First byte: size=0xFFFFFF (way beyond buffer length) — type=0x19.
    bad = b"\xff\xff\xff\x19" + (b"\x00" * 16)
    assert list(walk_decompressed_sections(bad)) == []


def test_zero_size_section_stops_walk() -> None:
    """A section header reporting size 0 is rejected (smaller than header)."""
    bad = b"\x00\x00\x00\x19" + (b"\x00" * 16)
    assert list(walk_decompressed_sections(bad)) == []


def test_unrecognized_section_type_falls_back_to_hex_hint() -> None:
    """An unknown type byte still surfaces as ``INNER_SECTION_TYPE_0x{xx}``."""
    # 4-byte header: size=0x10 (16), type=0xFE (made up).
    payload = b"\x10\x00\x00\xfe" + (b"\x42" * 12)
    carves = list(walk_decompressed_sections(payload))
    assert len(carves) == 1
    assert carves[0].component_type_hint == "INNER_SECTION_TYPE_0xfe"


def test_ui_section_with_empty_name_yields_none() -> None:
    """A UI section with only a NUL terminator surfaces ``name=None``."""
    # Header (size=6, type=0x15) + 2-byte NUL.
    payload = b"\x06\x00\x00\x15" + b"\x00\x00"
    carves = list(walk_decompressed_sections(payload))
    assert len(carves) == 1
    assert carves[0].name is None


# ---------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------


def test_walker_is_deterministic() -> None:
    """Two walks of the same buffer yield identical results."""
    buf = synthetic_uefi_volume.TIANO_PAYLOAD
    a = list(walk_decompressed_sections(buf))
    b = list(walk_decompressed_sections(buf))
    assert a == b


@pytest.mark.parametrize(
    "payload",
    [
        synthetic_uefi_volume.TIANO_PAYLOAD,
        synthetic_uefi_volume.LZMA_PAYLOAD,
    ],
)
def test_inner_carve_offsets_are_within_buffer(payload: bytes) -> None:
    """Every carved offset+size fits within the source buffer."""
    for carve in walk_decompressed_sections(payload):
        assert 0 <= carve.offset
        assert carve.offset + carve.size <= len(payload)
