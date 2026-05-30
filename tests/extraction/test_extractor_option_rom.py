"""Tests for the PCI option ROM extractor (task 16)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loki.extraction.detection import FormatKind
from loki.extraction.extractors.base import (
    ExtractorContext,
    clear_registry,
    dispatch_for,
)
from loki.extraction.extractors.option_rom import OptionRomExtractor, register
from loki.extraction.manifest import ManifestBuilder
from loki.extraction.streaming import StreamingHasher
from loki.models import FirmwareImage


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    clear_registry()
    register()
    yield
    clear_registry()


@pytest.fixture()
def context_for(synthetic_option_rom_path: Path) -> ExtractorContext:
    file_hash, file_size, _ = StreamingHasher(synthetic_option_rom_path).hash_file()
    image = FirmwareImage(
        file_path=str(synthetic_option_rom_path),
        file_hash=file_hash,
        file_size=file_size,
    )
    builder = ManifestBuilder(
        source_image=image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )
    return ExtractorContext(
        binary_path=synthetic_option_rom_path,
        manifest_builder=builder,
        max_component_size=10_000,
    )


def test_extractor_registered_for_option_rom_kind() -> None:
    extractor = dispatch_for(FormatKind.PCI_OPTION_ROM)
    assert extractor is not None
    assert isinstance(extractor, OptionRomExtractor)


def test_extracts_two_images_from_synthetic_fixture(
    context_for: ExtractorContext,
) -> None:
    extractor = OptionRomExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert len(carves) == 2
    # Image 0 starts at 0; image 1 follows.
    assert carves[0].offset == 0
    assert carves[1].offset == 1024  # IMAGE_SIZE_UNITS * 512


def test_extractor_records_code_type_in_hint(
    context_for: ExtractorContext,
) -> None:
    extractor = OptionRomExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    # Synthetic builder uses code_type 0x00 (legacy x86) and 0x03 (EFI).
    assert carves[0].component_type_hint == "PCI_LEGACY_X86"
    assert carves[1].component_type_hint == "PCI_EFI"


def test_extractor_includes_vendor_device_in_name(
    context_for: ExtractorContext,
) -> None:
    extractor = OptionRomExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    # Synthetic builder uses Intel vendor (0x8086) for both images.
    for carve in carves:
        assert carve.name is not None
        assert "8086" in carve.name


def test_extractor_supports_only_option_rom() -> None:
    ext = OptionRomExtractor()
    assert ext.supports(FormatKind.PCI_OPTION_ROM) is True
    assert ext.supports(FormatKind.UEFI_PI_VOLUME) is False


def test_extractor_stops_when_image_overruns_remaining(
    context_for: ExtractorContext, synthetic_option_rom_path: Path
) -> None:
    """An image whose ImageLength runs past the file is dropped, error recorded."""

    payload = bytearray(synthetic_option_rom_path.read_bytes())
    # Bump the first image's ImageLength field (within its PCIR) to 100 units
    # (50 KiB) so it overruns the 2 KiB file.
    pcir_offset = 0x20
    image_length_offset = pcir_offset + 0x10
    payload[image_length_offset : image_length_offset + 2] = (100).to_bytes(2, "little")
    synthetic_option_rom_path.write_bytes(bytes(payload))

    extractor = OptionRomExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert carves == []
    assert any("OPTION_ROM_OVERRUN" in e.error_message for e in context_for.manifest_builder.errors)


def test_extractor_returns_nothing_when_signature_missing(
    context_for: ExtractorContext, synthetic_option_rom_path: Path
) -> None:
    """Buffer without ``55 AA`` yields zero carves."""
    synthetic_option_rom_path.write_bytes(b"\x00" * 4096)
    extractor = OptionRomExtractor()
    assert list(extractor.extract(context_for, offset=0, length=None)) == []


def test_extractor_is_deterministic(context_for: ExtractorContext) -> None:
    extractor = OptionRomExtractor()
    a = list(extractor.extract(context_for, offset=0, length=None))
    b = list(extractor.extract(context_for, offset=0, length=None))
    assert [(c.offset, c.size, c.name, c.component_type_hint) for c in a] == [
        (c.offset, c.size, c.name, c.component_type_hint) for c in b
    ]
