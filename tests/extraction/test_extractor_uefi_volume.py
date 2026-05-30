"""Tests for the UEFI PI volume extractor (task 13)."""

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
from loki.extraction.extractors.uefi_volume import (
    UefiVolumeExtractor,
    register,
)
from loki.extraction.manifest import ManifestBuilder
from loki.extraction.streaming import StreamingHasher
from loki.models import FirmwareImage
from tests.extraction.fixtures import synthetic_uefi_volume


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    clear_registry()
    register()
    yield
    clear_registry()


@pytest.fixture()
def context_for(synthetic_uefi_volume_path: Path) -> ExtractorContext:
    file_hash, file_size, _ = StreamingHasher(synthetic_uefi_volume_path).hash_file()
    image = FirmwareImage(
        file_path=str(synthetic_uefi_volume_path),
        file_hash=file_hash,
        file_size=file_size,
    )
    builder = ManifestBuilder(
        source_image=image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )
    return ExtractorContext(
        binary_path=synthetic_uefi_volume_path,
        manifest_builder=builder,
        max_component_size=10_000,
    )


def test_extractor_registered_for_uefi_pi_volume_kind() -> None:
    extractor = dispatch_for(FormatKind.UEFI_PI_VOLUME)
    assert extractor is not None
    assert isinstance(extractor, UefiVolumeExtractor)


def test_extractor_supports_only_pi_volume() -> None:
    ext = UefiVolumeExtractor()
    assert ext.supports(FormatKind.UEFI_PI_VOLUME) is True
    assert ext.supports(FormatKind.UEFI_CAPSULE) is False


def test_extracts_one_ffs_file_from_synthetic_fixture(
    context_for: ExtractorContext,
) -> None:
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert len(carves) == 1
    carve = carves[0]
    # The FFS file lives just after the FV header.
    assert carve.offset > 0
    # GUID is the canonical lowercase form of the synthetic builder's GUID.
    assert carve.guid == str(synthetic_uefi_volume.FFS_FILE_GUID)
    # UI section name surfaces in the carve.
    assert carve.name == synthetic_uefi_volume.FFS_FILE_NAME
    # Type label hint covers the FFS file type byte.
    assert carve.component_type_hint == "FFS_FILE_TYPE_0x07"


def test_extractor_offsets_are_absolute(
    context_for: ExtractorContext, synthetic_uefi_volume_path: Path
) -> None:
    """R3.6: offsets are absolute byte positions in the source binary."""
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert carves
    binary = synthetic_uefi_volume_path.read_bytes()
    for carve in carves:
        # The bytes at the reported offset start with the file's GUID.
        actual = binary[carve.offset : carve.offset + 16].hex()
        expected = synthetic_uefi_volume.FFS_FILE_GUID.bytes_le.hex()
        assert actual == expected


def test_extractor_records_error_when_fv_header_truncated(
    context_for: ExtractorContext, synthetic_uefi_volume_path: Path
) -> None:
    """A binary smaller than the FV header records a typed error."""
    synthetic_uefi_volume_path.write_bytes(b"\x00" * 8)
    extractor = UefiVolumeExtractor()
    list(extractor.extract(context_for, offset=0, length=None))
    assert any(
        "FV_HEADER_TRUNCATED" in e.error_message for e in context_for.manifest_builder.errors
    )


def test_extractor_handles_erased_volume_cleanly(
    context_for: ExtractorContext, synthetic_uefi_volume_path: Path
) -> None:
    """If the FFS body is all 0xFF (erased), zero carves are emitted."""
    binary = bytearray(synthetic_uefi_volume_path.read_bytes())
    # Overwrite everything past the FV header with 0xFF.
    fv_header_len = 0x48
    for i in range(fv_header_len, len(binary)):
        binary[i] = 0xFF
    synthetic_uefi_volume_path.write_bytes(bytes(binary))
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert carves == []


def test_extractor_is_deterministic(context_for: ExtractorContext) -> None:
    extractor = UefiVolumeExtractor()
    a = list(extractor.extract(context_for, offset=0, length=None))
    b = list(extractor.extract(context_for, offset=0, length=None))
    assert [(c.offset, c.size, c.guid, c.name) for c in a] == [
        (c.offset, c.size, c.guid, c.name) for c in b
    ]


def test_extractor_stops_when_ffs_size_overruns_remaining(
    context_for: ExtractorContext, synthetic_uefi_volume_path: Path
) -> None:
    """An FFS file claiming a size larger than remaining bytes is dropped."""
    binary = bytearray(synthetic_uefi_volume_path.read_bytes())
    # Bump the first FFS file's Size field (offset 0x48 + 0x14) to 0xFFFF.
    ffs_start = 0x48
    binary[ffs_start + 0x14 : ffs_start + 0x17] = (0x100000).to_bytes(3, "little")
    synthetic_uefi_volume_path.write_bytes(bytes(binary))
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert carves == []
    assert any("FFS_FILE_OVERRUN" in e.error_message for e in context_for.manifest_builder.errors)


# ---------------------------------------------------------------------
# Decompression (R3.1, R5.8)
# ---------------------------------------------------------------------


def _build_context_with_wrapper(binary_path: Path) -> ExtractorContext:
    """Construct an :class:`ExtractorContext` with a probed wrapper.

    The default ``context_for`` fixture omits the wrapper because
    the original extractor tests didn't need it. Decompression
    tests need a real :class:`UefiFirmwareWrapper` so the
    ``decompress_tiano`` / ``decompress_lzma`` calls actually
    invoke the library.
    """
    from loki.extraction.tools.uefi_firmware import UefiFirmwareWrapper

    file_hash, file_size, _ = StreamingHasher(binary_path).hash_file()
    image = FirmwareImage(
        file_path=str(binary_path),
        file_hash=file_hash,
        file_size=file_size,
    )
    builder = ManifestBuilder(
        source_image=image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )
    wrapper = UefiFirmwareWrapper()
    wrapper.probe()
    return ExtractorContext(
        binary_path=binary_path,
        manifest_builder=builder,
        max_component_size=10_000_000,
        uefi_firmware=wrapper,
    )


def test_extractor_decompresses_tiano_section(
    synthetic_uefi_volume_with_tiano_path: Path,
) -> None:
    """R3.1: a Tiano-compressed FFS file's payload lands on ``decompressed_payload``."""
    ctx = _build_context_with_wrapper(synthetic_uefi_volume_with_tiano_path)
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(ctx, offset=0, length=None))

    # Two FFS files: the canonical one + the Tiano-compressed one.
    assert len(carves) == 2
    tiano_carves = [c for c in carves if c.guid == str(synthetic_uefi_volume.FFS_TIANO_FILE_GUID)]
    assert len(tiano_carves) == 1
    tiano_carve = tiano_carves[0]
    assert tiano_carve.decompressed_payload == synthetic_uefi_volume.TIANO_PAYLOAD
    assert tiano_carve.name == synthetic_uefi_volume.FFS_TIANO_FILE_NAME
    # No DECOMPRESSION_FAILED errors recorded.
    decomp_errors = [
        e for e in ctx.manifest_builder.errors if "DECOMPRESSION_FAILED" in e.error_message
    ]
    assert decomp_errors == []


def test_extractor_decompresses_lzma_section(
    synthetic_uefi_volume_with_lzma_path: Path,
) -> None:
    """R3.1: an LZMA GUID-defined FFS file's payload lands on ``decompressed_payload``."""
    ctx = _build_context_with_wrapper(synthetic_uefi_volume_with_lzma_path)
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(ctx, offset=0, length=None))

    assert len(carves) == 2
    lzma_carves = [c for c in carves if c.guid == str(synthetic_uefi_volume.FFS_LZMA_FILE_GUID)]
    assert len(lzma_carves) == 1
    lzma_carve = lzma_carves[0]
    assert lzma_carve.decompressed_payload == synthetic_uefi_volume.LZMA_PAYLOAD
    assert lzma_carve.name == synthetic_uefi_volume.FFS_LZMA_FILE_NAME


def test_extractor_records_error_on_corrupt_compressed_section(
    synthetic_uefi_volume_with_corrupt_compressed_path: Path,
) -> None:
    """R5.8: corrupt compressed sections record a ``DECOMPRESSION_FAILED`` error.

    The outer FFS component is still emitted; the inner
    decompressed payload is ``None``. Per R5.8, ``raw_hash`` must
    cover the on-disk compressed bytes (i.e. the FFS file's own
    bytes — verified separately via the manifest builder's
    ``add_component`` path).
    """
    ctx = _build_context_with_wrapper(synthetic_uefi_volume_with_corrupt_compressed_path)
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(ctx, offset=0, length=None))

    # Both FFS files are still emitted (R5.8: outer component lives on).
    assert len(carves) == 2
    corrupt_carves = [
        c for c in carves if c.guid == str(synthetic_uefi_volume.FFS_CORRUPT_FILE_GUID)
    ]
    assert len(corrupt_carves) == 1
    corrupt_carve = corrupt_carves[0]
    assert corrupt_carve.decompressed_payload is None

    # Exactly one DECOMPRESSION_FAILED error was recorded.
    decomp_errors = [
        e for e in ctx.manifest_builder.errors if "DECOMPRESSION_FAILED" in e.error_message
    ]
    assert len(decomp_errors) == 1
    assert "tiano" in decomp_errors[0].error_message


def test_extractor_decompressed_payload_default_is_none(
    context_for: ExtractorContext,
) -> None:
    """A volume with no compressed sections leaves ``decompressed_payload`` ``None``."""
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(context_for, offset=0, length=None))
    assert all(c.decompressed_payload is None for c in carves)


def test_extractor_handles_missing_wrapper_gracefully(
    synthetic_uefi_volume_with_tiano_path: Path,
) -> None:
    """No wrapper => decompression is skipped + a single error per section.

    A test-only setup that omits the wrapper should not crash; the
    extractor simply records a ``DECOMPRESSION_FAILED`` error and
    leaves ``decompressed_payload`` ``None``.
    """
    file_hash, file_size, _ = StreamingHasher(synthetic_uefi_volume_with_tiano_path).hash_file()
    image = FirmwareImage(
        file_path=str(synthetic_uefi_volume_with_tiano_path),
        file_hash=file_hash,
        file_size=file_size,
    )
    builder = ManifestBuilder(
        source_image=image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )
    ctx = ExtractorContext(
        binary_path=synthetic_uefi_volume_with_tiano_path,
        manifest_builder=builder,
        max_component_size=10_000_000,
        # uefi_firmware=None — explicitly missing.
    )
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(ctx, offset=0, length=None))

    tiano_carves = [c for c in carves if c.guid == str(synthetic_uefi_volume.FFS_TIANO_FILE_GUID)]
    assert len(tiano_carves) == 1
    assert tiano_carves[0].decompressed_payload is None
    decomp_errors = [e for e in builder.errors if "DECOMPRESSION_FAILED" in e.error_message]
    assert len(decomp_errors) == 1


def test_extractor_decompression_is_deterministic(
    synthetic_uefi_volume_with_tiano_path: Path,
) -> None:
    """Two extractions of the same compressed volume yield identical payloads."""
    ctx_a = _build_context_with_wrapper(synthetic_uefi_volume_with_tiano_path)
    ctx_b = _build_context_with_wrapper(synthetic_uefi_volume_with_tiano_path)
    extractor = UefiVolumeExtractor()
    a = list(extractor.extract(ctx_a, offset=0, length=None))
    b = list(extractor.extract(ctx_b, offset=0, length=None))

    a_payloads = [c.decompressed_payload for c in a]
    b_payloads = [c.decompressed_payload for c in b]
    assert a_payloads == b_payloads


def test_extractor_outer_carve_size_covers_on_disk_bytes(
    synthetic_uefi_volume_with_tiano_path: Path,
) -> None:
    """R5.8 anchor: outer FFS component's offset+size cover its real on-disk bytes.

    The `raw_hash` for the FFS file is computed by the manifest
    builder via ``streaming_sha256_slice(binary_path, offset, size)``.
    For R5.8 to hold ("``raw_hash`` covering the on-disk compressed
    bytes"), the carve's ``(offset, size)`` must match the FFS file's
    real position in the source binary. Verify by reading the bytes
    at that range and confirming they start with the file's GUID.
    """
    ctx = _build_context_with_wrapper(synthetic_uefi_volume_with_tiano_path)
    extractor = UefiVolumeExtractor()
    carves = list(extractor.extract(ctx, offset=0, length=None))
    binary = synthetic_uefi_volume_with_tiano_path.read_bytes()

    tiano_carves = [c for c in carves if c.guid == str(synthetic_uefi_volume.FFS_TIANO_FILE_GUID)]
    [tiano_carve] = tiano_carves
    actual = binary[tiano_carve.offset : tiano_carve.offset + tiano_carve.size]
    assert actual[:16] == synthetic_uefi_volume.FFS_TIANO_FILE_GUID.bytes_le
    assert len(actual) == tiano_carve.size


# ---------------------------------------------------------------------
# Inner component emission (decompressed payloads)
# ---------------------------------------------------------------------


def test_full_pipeline_emits_inner_components_for_tiano_section(
    synthetic_uefi_volume_with_tiano_path: Path,
) -> None:
    """End-to-end: ``extract_firmware`` materializes inner components.

    The Tiano-compressed FFS file's decompressed payload is two
    sections (UI + RAW). The manifest should contain those two
    inner components alongside the two outer FFS files.
    """
    from loki.extraction import extract_firmware
    from loki.models import ExtractionConfig

    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    result = extract_firmware(synthetic_uefi_volume_with_tiano_path, config)

    # Two outer FFS files + two inner sections from the Tiano payload.
    assert result.manifest.total_components == 4
    inner_components = [
        c
        for c in result.manifest.components
        if c.component_type_hint is not None and c.component_type_hint.startswith("INNER_")
    ]
    assert len(inner_components) == 2
    inner_hints = {c.component_type_hint for c in inner_components}
    assert "INNER_SECTION_TYPE_USER_INTERFACE" in inner_hints
    assert "INNER_SECTION_TYPE_RAW" in inner_hints


def test_full_pipeline_inner_component_image_id_is_synthetic(
    synthetic_uefi_volume_with_tiano_path: Path,
) -> None:
    """Inner components carry a synthetic ``source_image_id`` per option 4B."""
    import uuid

    from loki.extraction import extract_firmware
    from loki.models import LOKI_NAMESPACE, ExtractionConfig

    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    result = extract_firmware(synthetic_uefi_volume_with_tiano_path, config)

    # The decompressed payload is the TIANO_PAYLOAD constant; compute
    # the expected synthetic image id from its hash.
    import hashlib

    expected_inner_image_id = uuid.uuid5(
        LOKI_NAMESPACE,
        hashlib.sha256(synthetic_uefi_volume.TIANO_PAYLOAD).hexdigest(),
    )
    inner_components = [
        c
        for c in result.manifest.components
        if c.component_type_hint is not None and c.component_type_hint.startswith("INNER_")
    ]
    for component in inner_components:
        assert component.source_image_id == expected_inner_image_id


def test_full_pipeline_inner_component_offsets_are_within_decompressed_buffer(
    synthetic_uefi_volume_with_tiano_path: Path,
) -> None:
    """Inner offsets are relative to the decompressed buffer, not the source binary."""
    from loki.extraction import extract_firmware
    from loki.models import ExtractionConfig

    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    result = extract_firmware(synthetic_uefi_volume_with_tiano_path, config)

    inner_components = [
        c
        for c in result.manifest.components
        if c.component_type_hint is not None and c.component_type_hint.startswith("INNER_")
    ]
    for component in inner_components:
        offset_int = int(component.offset, 16)
        assert offset_int < len(synthetic_uefi_volume.TIANO_PAYLOAD)


def test_full_pipeline_writes_inner_bytes_to_output_dir(
    synthetic_uefi_volume_with_tiano_path: Path,
    tmp_path: Path,
) -> None:
    """Inner components write to disk with the ``decompressed`` filename marker."""
    from loki.extraction import extract_firmware
    from loki.models import ExtractionConfig

    output_dir = tmp_path / "out"
    config = ExtractionConfig(
        default_output_dir=str(output_dir),
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    result = extract_firmware(synthetic_uefi_volume_with_tiano_path, config)

    decompressed_files = list(output_dir.glob("*-decompressed-*.bin"))
    # Two inner sections should produce two files.
    assert len(decompressed_files) == 2
    # And the inner components' ``raw_path`` reflects them.
    inner_components = [
        c
        for c in result.manifest.components
        if c.component_type_hint is not None and c.component_type_hint.startswith("INNER_")
    ]
    raw_paths = [c.raw_path for c in inner_components]
    assert all(rp is not None and "decompressed" in rp for rp in raw_paths)


def test_full_pipeline_inner_component_emission_is_deterministic(
    synthetic_uefi_volume_with_tiano_path: Path,
) -> None:
    """Two extractions of the same volume yield identical inner-component ids."""
    from loki.extraction import extract_firmware
    from loki.models import ExtractionConfig

    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    a = extract_firmware(synthetic_uefi_volume_with_tiano_path, config)
    b = extract_firmware(synthetic_uefi_volume_with_tiano_path, config)

    a_ids = sorted(str(c.component_id) for c in a.manifest.components)
    b_ids = sorted(str(c.component_id) for c in b.manifest.components)
    assert a_ids == b_ids


def test_full_pipeline_corrupt_compressed_section_emits_no_inner_components(
    synthetic_uefi_volume_with_corrupt_compressed_path: Path,
) -> None:
    """A failed decompression yields no inner components (the payload is empty)."""
    from loki.extraction import extract_firmware
    from loki.models import ExtractionConfig

    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    result = extract_firmware(synthetic_uefi_volume_with_corrupt_compressed_path, config)

    inner_components = [
        c
        for c in result.manifest.components
        if c.component_type_hint is not None and c.component_type_hint.startswith("INNER_")
    ]
    assert inner_components == []
