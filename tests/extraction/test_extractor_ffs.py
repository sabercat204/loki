"""Tests for the raw FFS extractor (task 13 — second half)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from loki.extraction.detection import FormatKind
from loki.extraction.extractors.base import ExtractorContext
from loki.extraction.extractors.ffs import RawFfsExtractor
from loki.extraction.manifest import ManifestBuilder
from loki.extraction.streaming import StreamingHasher
from loki.models import FirmwareImage
from tests.extraction.fixtures import synthetic_uefi_volume


@pytest.fixture()
def raw_ffs_path(tmp_path: Path) -> Path:
    """Build a synthetic UEFI volume, then strip the 0x48-byte FV header.

    What's left is a pure FFS blob — exactly the input the raw FFS
    extractor is designed to walk.
    """
    volume = synthetic_uefi_volume.build(tmp_path)
    binary = volume.read_bytes()
    fv_header_len = 0x48
    out = tmp_path / "raw_ffs.bin"
    out.write_bytes(binary[fv_header_len:])
    return out


@pytest.fixture()
def context_for(raw_ffs_path: Path) -> ExtractorContext:
    file_hash, file_size, _ = StreamingHasher(raw_ffs_path).hash_file()
    image = FirmwareImage(
        file_path=str(raw_ffs_path),
        file_hash=file_hash,
        file_size=file_size,
    )
    builder = ManifestBuilder(
        source_image=image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )
    return ExtractorContext(
        binary_path=raw_ffs_path,
        manifest_builder=builder,
        max_component_size=10_000,
    )


def test_raw_ffs_extractor_supports_returns_false_in_v1() -> None:
    """v1 detection doesn't surface a raw-FFS kind; the supports() returns False."""
    ext = RawFfsExtractor()
    assert ext.supports(FormatKind.UEFI_PI_VOLUME) is False
    assert ext.supports(FormatKind.UNKNOWN) is False


def test_extracts_ffs_file_from_header_stripped_volume(
    context_for: ExtractorContext,
) -> None:
    extractor = RawFfsExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert len(carves) == 1
    carve = carves[0]
    assert carve.guid == str(synthetic_uefi_volume.FFS_FILE_GUID)
    assert carve.name == synthetic_uefi_volume.FFS_FILE_NAME


def test_extractor_offsets_are_relative_to_input(
    context_for: ExtractorContext, raw_ffs_path: Path
) -> None:
    """The first FFS file lives at offset 0 of the header-stripped binary."""
    extractor = RawFfsExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert carves
    assert carves[0].offset == 0
    binary = raw_ffs_path.read_bytes()
    actual = binary[0:16].hex()
    expected = synthetic_uefi_volume.FFS_FILE_GUID.bytes_le.hex()
    assert actual == expected


def test_extractor_handles_empty_input(context_for: ExtractorContext, raw_ffs_path: Path) -> None:
    raw_ffs_path.write_bytes(b"")
    extractor = RawFfsExtractor()
    assert list(extractor.extract(context_for, offset=0, length=None)) == []


def test_extractor_is_deterministic(context_for: ExtractorContext) -> None:
    extractor = RawFfsExtractor()
    a = list(extractor.extract(context_for, offset=0, length=None))
    b = list(extractor.extract(context_for, offset=0, length=None))
    assert [(c.offset, c.size, c.guid, c.name) for c in a] == [
        (c.offset, c.size, c.guid, c.name) for c in b
    ]
