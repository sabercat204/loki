"""Tests for the Intel microcode extractor (task 17)."""

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
from loki.extraction.extractors.microcode import (
    MicrocodeExtractor,
    register,
)
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
def context_for(synthetic_microcode_path: Path) -> ExtractorContext:
    file_hash, file_size, _ = StreamingHasher(synthetic_microcode_path).hash_file()
    image = FirmwareImage(
        file_path=str(synthetic_microcode_path),
        file_hash=file_hash,
        file_size=file_size,
    )
    builder = ManifestBuilder(
        source_image=image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )
    return ExtractorContext(
        binary_path=synthetic_microcode_path,
        manifest_builder=builder,
        max_component_size=10_000,
    )


def test_extractor_registered_for_microcode_kind() -> None:
    extractor = dispatch_for(FormatKind.INTEL_MICROCODE)
    assert extractor is not None
    assert isinstance(extractor, MicrocodeExtractor)


def test_extractor_supports_only_microcode() -> None:
    ext = MicrocodeExtractor()
    assert ext.supports(FormatKind.INTEL_MICROCODE) is True
    assert ext.supports(FormatKind.UEFI_PI_VOLUME) is False


def test_extracts_two_blobs_from_synthetic_fixture(
    context_for: ExtractorContext, synthetic_microcode_path: Path
) -> None:
    """Synthetic fixture contains exactly two concatenated blobs."""
    extractor = MicrocodeExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert len(carves) == 2
    # Offsets are absolute and sequential.
    assert carves[0].offset == 0
    assert carves[1].offset == 0x800  # BLOB_SIZE
    # All carves are full microcode blobs.
    assert all(c.size == 0x800 for c in carves)
    # component_type_hint and name follow the contract.
    assert all(c.component_type_hint == "INTEL_MICROCODE" for c in carves)
    assert all(c.name is not None and "CPUID=" in c.name for c in carves)


def test_extractor_records_cpuid_and_revision_in_name(
    context_for: ExtractorContext,
) -> None:
    extractor = MicrocodeExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    # Synthetic builder uses these (cpuid, revision) pairs in order.
    assert carves[0].name == "CPUID=000506e3 REV=000000f0"
    assert carves[1].name == "CPUID=000906ea REV=000000f1"


def test_extractor_stops_when_total_size_overruns_remaining(
    context_for: ExtractorContext, synthetic_microcode_path: Path
) -> None:
    """A blob whose ``total_size`` overruns the file is dropped, error recorded."""

    # Truncate the second blob's total_size so it claims to be 16 KiB.
    payload = bytearray(synthetic_microcode_path.read_bytes())
    struct.pack_into("<I", payload, 0x800 + 0x20, 0x4000)
    synthetic_microcode_path.write_bytes(bytes(payload))

    extractor = MicrocodeExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    # First blob extracts fine; the second is dropped because its
    # claimed total_size > remaining bytes.
    assert len(carves) == 1
    assert any("MICROCODE_OVERRUN" in e.error_message for e in context_for.manifest_builder.errors)


def test_extractor_is_deterministic(
    context_for: ExtractorContext,
) -> None:
    """Two extraction passes produce identical carve sequences."""
    extractor = MicrocodeExtractor()
    a = list(extractor.extract(context_for, offset=0, length=None))
    b = list(extractor.extract(context_for, offset=0, length=None))
    assert [(c.offset, c.size, c.name, c.component_type_hint) for c in a] == [
        (c.offset, c.size, c.name, c.component_type_hint) for c in b
    ]


def test_extractor_returns_nothing_when_no_microcode_present(
    context_for: ExtractorContext, synthetic_microcode_path: Path
) -> None:
    """Pointing the extractor at random bytes yields zero carves."""
    synthetic_microcode_path.write_bytes(b"\x00" * 4096)
    extractor = MicrocodeExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert carves == []


def test_extractor_handles_offset_argument(
    context_for: ExtractorContext, synthetic_microcode_path: Path
) -> None:
    """Starting at a non-zero offset still extracts blobs from that point on."""
    # Prepend 0x1000 of pad bytes; rebuild fixture in place.
    original = synthetic_microcode_path.read_bytes()
    synthetic_microcode_path.write_bytes(b"\x00" * 0x1000 + original)
    extractor = MicrocodeExtractor()
    carves = list(extractor.extract(context_for, offset=0x1000, length=None))
    assert len(carves) == 2
    assert carves[0].offset == 0x1000
    assert carves[1].offset == 0x1800
