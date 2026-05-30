"""Tests for the Intel Flash Descriptor extractor (task 14)."""

from __future__ import annotations

import struct
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
from loki.extraction.extractors.ifd import IfdExtractor, register
from loki.extraction.extractors.uefi_volume import (
    register as register_uefi_volume,
)
from loki.extraction.manifest import ManifestBuilder
from loki.extraction.streaming import StreamingHasher
from loki.models import FirmwareImage
from tests.extraction.fixtures import synthetic_uefi_volume


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    clear_registry()
    register()
    register_uefi_volume()  # IFD recursion needs the UEFI volume extractor.
    yield
    clear_registry()


def _build_ifd_image(tmp_path: Path) -> Path:
    """Synthesize a minimal IFD-described image: descriptor + BIOS region.

    Layout:
      0x0000-0x0FFF  Flash Descriptor (region 0)
      0x1000-0x4FFF  BIOS region (region 1) — contains a synthetic UEFI volume

    The descriptor encodes 2 regions (NR=2 -> encoded as 1) with FRBA
    at 0x40 (4 x 16-byte units).
    """

    descriptor = bytearray(0x1000)
    # FLVALSIG at +0x10.
    descriptor[0x10:0x14] = bytes((0x5A, 0xA5, 0xF0, 0x0F))
    # FLMAP0: NR=2 (encoded as 1) in bits [24:26], FRBA=4 in bits [16:23].
    flmap0 = (1 << 24) | (4 << 16)
    struct.pack_into("<I", descriptor, 0x14, flmap0)
    # Region 0 (descriptor itself): base=0, limit=0 (4 KiB region).
    struct.pack_into("<I", descriptor, 0x40, (0 << 16) | 0)
    # Region 1 (BIOS): base = 1 (4 KiB), limit = 4 (so spans 0x1000-0x4FFF).
    struct.pack_into("<I", descriptor, 0x44, (4 << 16) | 1)

    # Build the BIOS region — a synthetic UEFI volume.
    volume_dir = tmp_path / "volume_build"
    volume_path = synthetic_uefi_volume.build(volume_dir)
    volume_bytes = volume_path.read_bytes()

    # Assemble the full image: descriptor (4 KiB) + BIOS region (16 KiB).
    bios_region = bytearray(0x4000)
    bios_region[: len(volume_bytes)] = volume_bytes

    full_image = descriptor + bytes(bios_region)
    out = tmp_path / "ifd.bin"
    out.write_bytes(full_image)
    return out


@pytest.fixture()
def ifd_image_path(tmp_path: Path) -> Path:
    return _build_ifd_image(tmp_path)


@pytest.fixture()
def context_for(ifd_image_path: Path) -> ExtractorContext:
    file_hash, file_size, _ = StreamingHasher(ifd_image_path).hash_file()
    image = FirmwareImage(
        file_path=str(ifd_image_path),
        file_hash=file_hash,
        file_size=file_size,
    )
    builder = ManifestBuilder(
        source_image=image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )
    return ExtractorContext(
        binary_path=ifd_image_path,
        manifest_builder=builder,
        max_component_size=1_000_000,
    )


def test_extractor_registered_for_ifd_kind() -> None:
    extractor = dispatch_for(FormatKind.INTEL_IFD)
    assert extractor is not None
    assert isinstance(extractor, IfdExtractor)


def test_extractor_emits_descriptor_and_bios_regions(
    context_for: ExtractorContext,
) -> None:
    extractor = IfdExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    # We get at least the FLASH_DESCRIPTOR and BIOS region names.
    assert "FLASH_DESCRIPTOR" in [c.name for c in carves]
    assert "BIOS" in [c.name for c in carves]


def test_extractor_recurses_into_bios_region(
    context_for: ExtractorContext,
) -> None:
    """The BIOS region's UEFI volume produces an additional FFS-file carve."""
    extractor = IfdExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    # The synthetic BIOS region's UEFI volume contains one FFS file.
    ffs_carves = [c for c in carves if c.guid is not None]
    assert len(ffs_carves) == 1
    assert ffs_carves[0].guid == str(synthetic_uefi_volume.FFS_FILE_GUID)


def test_extractor_offsets_for_recursed_components_are_absolute(
    context_for: ExtractorContext, ifd_image_path: Path
) -> None:
    """Recursed FFS file offsets are absolute byte positions in the IFD image."""
    extractor = IfdExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    binary = ifd_image_path.read_bytes()
    for carve in carves:
        if carve.guid is None:
            continue
        actual = binary[carve.offset : carve.offset + 16].hex()
        expected = synthetic_uefi_volume.FFS_FILE_GUID.bytes_le.hex()
        assert actual == expected


def test_extractor_records_error_when_signature_missing(
    context_for: ExtractorContext, ifd_image_path: Path
) -> None:
    binary = bytearray(ifd_image_path.read_bytes())
    # Corrupt the FLVALSIG at offset 0x10.
    binary[0x10:0x14] = b"XXXX"
    ifd_image_path.write_bytes(bytes(binary))
    extractor = IfdExtractor()
    list(extractor.extract(context_for, offset=0, length=None))
    assert any(
        "IFD_MISSING_SIGNATURE" in e.error_message for e in context_for.manifest_builder.errors
    )


def test_extractor_supports_only_ifd() -> None:
    ext = IfdExtractor()
    assert ext.supports(FormatKind.INTEL_IFD) is True
    assert ext.supports(FormatKind.UEFI_PI_VOLUME) is False
