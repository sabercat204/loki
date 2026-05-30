"""Tests for the UEFI capsule extractor (task 15)."""

from __future__ import annotations

import struct
import uuid
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
from loki.extraction.extractors.capsule import CapsuleExtractor, register
from loki.extraction.extractors.uefi_volume import (
    register as register_uefi_volume,
)
from loki.extraction.manifest import ManifestBuilder
from loki.extraction.streaming import StreamingHasher
from loki.models import FirmwareImage
from tests.extraction.fixtures import synthetic_uefi_volume

_KNOWN_GUID = uuid.UUID("6dcbd5ed-e82d-4c44-bda1-7194199ad92a")


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    clear_registry()
    register()
    register_uefi_volume()
    yield
    clear_registry()


def _build_capsule_with_inner_volume(tmp_path: Path) -> Path:
    """Synthesize a capsule whose body holds a synthetic UEFI volume."""
    volume_dir = tmp_path / "volume_build"
    volume_path = synthetic_uefi_volume.build(volume_dir)
    volume_bytes = volume_path.read_bytes()

    header_size = 0x1C
    capsule_image_size = header_size + len(volume_bytes)
    header = bytearray(header_size)
    header[:16] = _KNOWN_GUID.bytes_le
    struct.pack_into("<I", header, 0x10, header_size)
    struct.pack_into("<I", header, 0x14, 0)  # flags
    struct.pack_into("<I", header, 0x18, capsule_image_size)

    out = tmp_path / "capsule.bin"
    out.write_bytes(bytes(header) + volume_bytes)
    return out


@pytest.fixture()
def capsule_path(tmp_path: Path) -> Path:
    return _build_capsule_with_inner_volume(tmp_path)


@pytest.fixture()
def context_for(capsule_path: Path) -> ExtractorContext:
    file_hash, file_size, _ = StreamingHasher(capsule_path).hash_file()
    image = FirmwareImage(
        file_path=str(capsule_path),
        file_hash=file_hash,
        file_size=file_size,
    )
    builder = ManifestBuilder(
        source_image=image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )
    return ExtractorContext(
        binary_path=capsule_path,
        manifest_builder=builder,
        max_component_size=1_000_000,
    )


def test_extractor_registered_for_capsule_kind() -> None:
    extractor = dispatch_for(FormatKind.UEFI_CAPSULE)
    assert extractor is not None
    assert isinstance(extractor, CapsuleExtractor)


def test_extractor_emits_body_and_recurses_into_volume(
    context_for: ExtractorContext,
) -> None:
    extractor = CapsuleExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    # At minimum we get the body wrapper plus the inner FFS file.
    assert len(carves) >= 2
    body_carves = [c for c in carves if c.component_type_hint == "UEFI_CAPSULE_BODY"]
    ffs_carves = [c for c in carves if c.guid is not None]
    assert len(body_carves) == 1
    assert len(ffs_carves) == 1
    assert ffs_carves[0].guid == str(synthetic_uefi_volume.FFS_FILE_GUID)


def test_extractor_records_error_on_truncated_header(
    context_for: ExtractorContext, capsule_path: Path
) -> None:
    capsule_path.write_bytes(b"\x00" * 8)
    extractor = CapsuleExtractor()
    list(extractor.extract(context_for, offset=0, length=None))
    assert any(
        "CAPSULE_HEADER_TRUNCATED" in e.error_message for e in context_for.manifest_builder.errors
    )


def test_extractor_records_error_on_invalid_header_size(
    context_for: ExtractorContext, capsule_path: Path
) -> None:
    binary = bytearray(capsule_path.read_bytes())
    # Set HeaderSize to 0 — invalid.
    struct.pack_into("<I", binary, 0x10, 0)
    capsule_path.write_bytes(bytes(binary))
    extractor = CapsuleExtractor()
    list(extractor.extract(context_for, offset=0, length=None))
    assert any(
        "CAPSULE_INVALID_HEADER_SIZE" in e.error_message
        for e in context_for.manifest_builder.errors
    )


def test_extractor_supports_only_capsule() -> None:
    ext = CapsuleExtractor()
    assert ext.supports(FormatKind.UEFI_CAPSULE) is True
    assert ext.supports(FormatKind.UEFI_PI_VOLUME) is False


def test_extractor_handles_header_only_capsule(
    context_for: ExtractorContext, capsule_path: Path
) -> None:
    """A capsule whose CapsuleImageSize equals HeaderSize has no body to emit."""
    binary = bytearray(capsule_path.read_bytes())
    # Set CapsuleImageSize == HeaderSize.
    header_size = struct.unpack_from("<I", binary, 0x10)[0]
    struct.pack_into("<I", binary, 0x18, header_size)
    capsule_path.write_bytes(bytes(binary[:header_size]))
    extractor = CapsuleExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert carves == []
