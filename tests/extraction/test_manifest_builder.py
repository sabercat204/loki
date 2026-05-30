"""Tests for ``ManifestBuilder`` (task 11)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loki.extraction.errors import ManifestConstructionError
from loki.extraction.ids import derive_component_id, derive_error_component_id
from loki.extraction.manifest import CarvedComponentInput, ManifestBuilder
from loki.models import ExtractionManifest, FirmwareImage

_TEST_HASH = "a" * 64


@pytest.fixture()
def binary(tmp_path: Path) -> Path:
    """Create a deterministic 4 KiB binary used as the extraction source."""
    payload = bytes(range(256)) * 16  # 4 KiB
    path = tmp_path / "fake-firmware.rom"
    path.write_bytes(payload)
    return path


@pytest.fixture()
def source_image(binary: Path) -> FirmwareImage:
    """Build a ``FirmwareImage`` whose ``file_hash`` matches the on-disk binary."""
    file_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    return FirmwareImage(
        file_path=str(binary),
        file_hash=file_hash,
        file_size=binary.stat().st_size,
    )


@pytest.fixture()
def builder(source_image: FirmwareImage) -> ManifestBuilder:
    return ManifestBuilder(
        source_image=source_image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )


# ---------------------------------------------------------------------
# add_component happy path
# ---------------------------------------------------------------------


def test_add_component_appends_validated_extracted_component(
    builder: ManifestBuilder, binary: Path, source_image: FirmwareImage
) -> None:
    component = builder.add_component(
        CarvedComponentInput(offset=0x100, size=128, name="DXE Driver: Foo"),
        binary_path=binary,
        max_component_size=10_000,
    )
    assert component is not None
    assert component.offset == "0x100"
    assert component.size == 128
    assert component.name == "DXE Driver: Foo"
    # raw_hash is the slice digest, not the whole-file hash.
    expected = hashlib.sha256(binary.read_bytes()[0x100 : 0x100 + 128]).hexdigest()
    assert component.raw_hash == expected
    # component_id matches the deterministic derivation.
    expected_id = derive_component_id(
        source_image_hash=source_image.file_hash,
        offset=0x100,
        raw_hash=expected,
    )
    assert component.component_id == expected_id


def test_add_component_records_raw_path_when_supplied(
    builder: ManifestBuilder, binary: Path, tmp_path: Path
) -> None:
    out_path = tmp_path / "carved" / "0x100-deadbeef.bin"
    component = builder.add_component(
        CarvedComponentInput(offset=0x200, size=64),
        binary_path=binary,
        max_component_size=10_000,
        raw_path=out_path,
    )
    assert component is not None
    assert component.raw_path == str(out_path)


def test_add_component_default_raw_path_is_none(builder: ManifestBuilder, binary: Path) -> None:
    """R3.13: when no output dir is configured, ``raw_path`` stays ``None``."""
    component = builder.add_component(
        CarvedComponentInput(offset=0x300, size=64),
        binary_path=binary,
        max_component_size=10_000,
    )
    assert component is not None
    assert component.raw_path is None


# ---------------------------------------------------------------------
# add_component edge cases
# ---------------------------------------------------------------------


def test_add_component_skips_when_oversized_and_records_error(
    builder: ManifestBuilder, binary: Path
) -> None:
    """R3.14: components exceeding ``max_component_size`` are skipped."""
    component = builder.add_component(
        CarvedComponentInput(offset=0x100, size=10_000),
        binary_path=binary,
        max_component_size=1_000,
    )
    assert component is None
    assert builder.components == []
    assert len(builder.errors) == 1
    err = builder.errors[0]
    assert "OVERSIZED" in err.error_message or "max_component_size" in err.error_message


def test_add_component_handles_duplicate_component_id(
    builder: ManifestBuilder, binary: Path
) -> None:
    """Two carves with identical (offset, raw_hash) collide; second is dropped."""
    first = builder.add_component(
        CarvedComponentInput(offset=0x100, size=128),
        binary_path=binary,
        max_component_size=10_000,
    )
    second = builder.add_component(
        CarvedComponentInput(offset=0x100, size=128),
        binary_path=binary,
        max_component_size=10_000,
    )
    assert first is not None
    assert second is None
    # Original component still in the list; one error recorded.
    assert len(builder.components) == 1
    assert len(builder.errors) == 1
    err_message = builder.errors[0].error_message
    assert "components share id" in err_message
    assert "0x100" in err_message


def test_add_component_rejects_non_positive_size(builder: ManifestBuilder, binary: Path) -> None:
    with pytest.raises(ValueError, match=r"carved.size must be > 0"):
        builder.add_component(
            CarvedComponentInput(offset=0, size=0),
            binary_path=binary,
            max_component_size=10_000,
        )


def test_add_component_rejects_non_positive_max_size(
    builder: ManifestBuilder, binary: Path
) -> None:
    with pytest.raises(ValueError, match=r"max_component_size must be > 0"):
        builder.add_component(
            CarvedComponentInput(offset=0, size=10),
            binary_path=binary,
            max_component_size=0,
        )


# ---------------------------------------------------------------------
# record_error
# ---------------------------------------------------------------------


def test_record_error_with_offset_derives_stable_component_id(
    builder: ManifestBuilder, source_image: FirmwareImage
) -> None:
    err = builder.record_error(
        error_kind="FFS_HEADER_CRC",
        message="CRC mismatch",
        offset=0x40000,
    )
    expected = derive_error_component_id(
        source_image_hash=source_image.file_hash,
        offset=0x40000,
        error_kind="FFS_HEADER_CRC",
    )
    assert err.component_id == expected


def test_record_error_whole_file_leaves_component_id_none(
    builder: ManifestBuilder,
) -> None:
    """R5.5: whole-file errors carry ``component_id=None``."""
    err = builder.record_error(
        error_kind="OUT_OF_SCOPE_FORMAT",
        message="binary uses an unsupported format",
        offset=None,
    )
    assert err.component_id is None


def test_record_error_rejects_empty_message(builder: ManifestBuilder) -> None:
    with pytest.raises(ValueError, match=r"message must be non-empty"):
        builder.record_error(
            error_kind="ANY",
            message="   ",
            offset=None,
        )


def test_record_error_preserves_explicit_component_id(
    builder: ManifestBuilder,
) -> None:
    """An explicit ``component_id`` overrides the auto-derived one."""
    explicit = derive_error_component_id(
        source_image_hash=builder._source_image.file_hash,
        offset=0x100,
        error_kind="EXTRA",
    )
    err = builder.record_error(
        error_kind="OVERRIDDEN",
        message="explicit id wins",
        offset=0x100,
        component_id=explicit,
    )
    assert err.component_id == explicit


# ---------------------------------------------------------------------
# finalize
# ---------------------------------------------------------------------


def test_finalize_returns_validated_manifest(builder: ManifestBuilder, binary: Path) -> None:
    builder.add_component(
        CarvedComponentInput(offset=0x100, size=64),
        binary_path=binary,
        max_component_size=10_000,
    )
    manifest = builder.finalize()
    assert isinstance(manifest, ExtractionManifest)
    assert manifest.total_components == len(manifest.components) == 1
    assert manifest.extractor_version == "0.1.0"


def test_finalize_sorts_components_by_offset(builder: ManifestBuilder, binary: Path) -> None:
    """R6.5: components are ordered by ascending integer offset."""
    for offset in (0x300, 0x100, 0x200):
        builder.add_component(
            CarvedComponentInput(offset=offset, size=32),
            binary_path=binary,
            max_component_size=10_000,
        )
    manifest = builder.finalize()
    offsets = [int(c.offset, 16) for c in manifest.components]
    assert offsets == sorted(offsets) == [0x100, 0x200, 0x300]


def test_finalize_round_trips_through_json(builder: ManifestBuilder, binary: Path) -> None:
    """R6.7 / R7.6: manifests serialize losslessly."""
    builder.add_component(
        CarvedComponentInput(offset=0x100, size=64),
        binary_path=binary,
        max_component_size=10_000,
    )
    builder.record_error(error_kind="DEMO", message="just a demo error", offset=None)
    manifest = builder.finalize()
    restored = ExtractionManifest.model_validate_json(manifest.model_dump_json())
    assert restored == manifest


def test_finalize_propagates_validation_error_as_typed(
    builder: ManifestBuilder, binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Pydantic ``ValidationError`` is wrapped in :class:`ManifestConstructionError`.

    Forces a synthetic Pydantic failure by patching
    :class:`ExtractionManifest` with a stub whose constructor always
    raises. The wrapper guarantees R6.6 — callers see a typed
    pipeline exception, not a raw Pydantic error.
    """

    builder.add_component(
        CarvedComponentInput(offset=0x100, size=64),
        binary_path=binary,
        max_component_size=10_000,
    )

    real_manifest = ExtractionManifest

    def _exploding_manifest(*args: object, **kwargs: object) -> ExtractionManifest:
        # Build a real manifest first to obtain a real ValidationError
        # surface (Pydantic v2 expects a specific shape), then re-raise
        # it via constructing the model with an invalid field.
        return real_manifest.model_validate({"source_image": "not-a-firmware-image"})

    monkeypatch.setattr("loki.extraction.manifest.ExtractionManifest", _exploding_manifest)

    with pytest.raises(ManifestConstructionError):
        builder.finalize()


def test_finalize_includes_recorded_errors(builder: ManifestBuilder, binary: Path) -> None:
    builder.record_error(error_kind="WHOLE_FILE", message="file is unreadable", offset=None)
    builder.add_component(
        CarvedComponentInput(offset=0x100, size=64),
        binary_path=binary,
        max_component_size=10_000,
    )
    manifest = builder.finalize()
    assert len(manifest.extraction_errors) == 1
    assert manifest.extraction_errors[0].component_id is None


# ---------------------------------------------------------------------
# add_inner_component
# ---------------------------------------------------------------------


def _decompressed_payload_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def test_add_inner_component_appends_with_synthetic_image_id(
    builder: ManifestBuilder,
) -> None:
    """The inner component carries a synthetic ``source_image_id``.

    Derived as ``uuid5(LOKI_NAMESPACE, decompressed_hash)`` per the
    design's option 4B; distinct from the firmware file's
    ``image_id`` so callers can recognize inner components without
    a model-layer change.
    """
    import uuid

    from loki.models import LOKI_NAMESPACE

    decompressed = b"\x00" * 256
    decomp_hash = _decompressed_payload_hash(decompressed)
    inner_bytes = b"\x42" * 64

    component = builder.add_inner_component(
        offset=0x10,
        size=64,
        raw_bytes=inner_bytes,
        decompressed_payload_hash=decomp_hash,
        max_component_size=1_000_000,
        component_type_hint="INNER_SECTION_TYPE_RAW",
    )

    assert component is not None
    assert component.offset == "0x10"
    assert component.size == 64
    assert component.component_type_hint == "INNER_SECTION_TYPE_RAW"
    expected_image_id = uuid.uuid5(LOKI_NAMESPACE, decomp_hash)
    assert component.source_image_id == expected_image_id


def test_add_inner_component_raw_hash_matches_in_memory_bytes(
    builder: ManifestBuilder,
) -> None:
    """``raw_hash`` is the SHA-256 of the supplied ``raw_bytes``."""
    decompressed = b"\xab" * 256
    inner_bytes = b"\xcd" * 32
    component = builder.add_inner_component(
        offset=0,
        size=32,
        raw_bytes=inner_bytes,
        decompressed_payload_hash=_decompressed_payload_hash(decompressed),
        max_component_size=1_000_000,
    )
    assert component is not None
    assert component.raw_hash == hashlib.sha256(inner_bytes).hexdigest()


def test_add_inner_component_id_is_deterministic(builder: ManifestBuilder) -> None:
    """Inner component ids derive from ``(decompressed_hash, offset, raw_hash)``."""
    decompressed = b"\xef" * 256
    decomp_hash = _decompressed_payload_hash(decompressed)
    inner_bytes = b"\x99" * 16
    inner_raw_hash = hashlib.sha256(inner_bytes).hexdigest()

    component = builder.add_inner_component(
        offset=0x40,
        size=16,
        raw_bytes=inner_bytes,
        decompressed_payload_hash=decomp_hash,
        max_component_size=1_000_000,
    )
    assert component is not None
    expected_id = derive_component_id(
        source_image_hash=decomp_hash,
        offset=0x40,
        raw_hash=inner_raw_hash,
    )
    assert component.component_id == expected_id


def test_add_inner_component_skips_when_oversized(builder: ManifestBuilder) -> None:
    """Oversized inner components are skipped with an ``OVERSIZED_COMPONENT`` error."""
    inner_bytes = b"\x00" * 256
    component = builder.add_inner_component(
        offset=0,
        size=256,
        raw_bytes=inner_bytes,
        decompressed_payload_hash=_decompressed_payload_hash(b"x"),
        max_component_size=128,  # smaller than the 256-byte inner component
    )
    assert component is None
    assert any(
        "OVERSIZED_COMPONENT" in e.error_message and "inner component" in e.error_message
        for e in builder.errors
    )


def test_add_inner_component_rejects_size_mismatch(builder: ManifestBuilder) -> None:
    """``raw_bytes`` length must match ``size``."""
    with pytest.raises(ValueError, match="raw_bytes length"):
        builder.add_inner_component(
            offset=0,
            size=128,
            raw_bytes=b"\x00" * 64,  # mismatch
            decompressed_payload_hash=_decompressed_payload_hash(b"x"),
            max_component_size=1_000_000,
        )


def test_add_inner_component_handles_duplicate_id(builder: ManifestBuilder) -> None:
    """A duplicate inner-component id is dropped with a ``DUPLICATE_COMPONENT_ID`` error."""
    decompressed = b"\x00" * 256
    inner_bytes = b"\x77" * 8
    decomp_hash = _decompressed_payload_hash(decompressed)

    first = builder.add_inner_component(
        offset=0,
        size=8,
        raw_bytes=inner_bytes,
        decompressed_payload_hash=decomp_hash,
        max_component_size=1_000_000,
    )
    second = builder.add_inner_component(
        offset=0,
        size=8,
        raw_bytes=inner_bytes,  # same offset + same bytes -> same id
        decompressed_payload_hash=decomp_hash,
        max_component_size=1_000_000,
    )
    assert first is not None
    assert second is None
    assert any("DUPLICATE_COMPONENT_ID" in e.error_message for e in builder.errors)


def test_add_inner_component_records_raw_path_when_supplied(
    builder: ManifestBuilder, tmp_path: Path
) -> None:
    """The inner-component ``raw_path`` is recorded on the model."""
    raw_path = tmp_path / "0x100-decompressed-0x0-raw.bin"
    raw_path.write_bytes(b"x" * 16)
    component = builder.add_inner_component(
        offset=0,
        size=16,
        raw_bytes=b"x" * 16,
        decompressed_payload_hash=_decompressed_payload_hash(b"x"),
        max_component_size=1_000_000,
        raw_path=raw_path,
    )
    assert component is not None
    assert component.raw_path == str(raw_path)


def test_inner_component_image_id_distinct_from_outer(
    builder: ManifestBuilder, source_image: FirmwareImage
) -> None:
    """Inner components don't share ``source_image_id`` with the firmware file.

    The synthetic virtual id is derived from the decompressed
    payload's hash, which is by construction different from the
    firmware file's hash. Same-content collisions across the two
    are vanishingly unlikely (different uuid5 input).
    """
    component = builder.add_inner_component(
        offset=0,
        size=4,
        raw_bytes=b"abcd",
        decompressed_payload_hash=_decompressed_payload_hash(b"different"),
        max_component_size=1_000_000,
    )
    assert component is not None
    assert component.source_image_id != source_image.image_id
