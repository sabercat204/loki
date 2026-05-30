"""Hypothesis property tests for determinism (task 22, properties 18-21).

Drives :func:`loki.extraction.extract_firmware` against synthetic
binaries built by ``tests/extraction/fixtures``. Each property is
checked over a small but representative set of inputs.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.extraction import extract_firmware
from loki.extraction.extractors.base import clear_registry
from loki.extraction.ids import (
    derive_component_id,
    derive_error_component_id,
)
from loki.models import ExtractionConfig
from tests.extraction.fixtures import (
    synthetic_microcode,
    synthetic_uefi_volume,
)


@pytest.fixture(autouse=True)
def _registry_isolation() -> Iterator[None]:
    clear_registry()
    yield
    clear_registry()


def _make_config(tmp_path: Path) -> ExtractionConfig:
    return ExtractionConfig(
        default_output_dir=str(tmp_path / "extracted"),
        max_component_size=10_000_000,
        timeout_per_component=30,
    )


def _strip_timestamps(payload: dict[str, object]) -> None:
    """Recursively None-out every timestamp field in a manifest dump."""

    if not isinstance(payload, dict):
        return
    for key in list(payload):
        value = payload[key]
        if key in {"extraction_timestamp", "timestamp"}:
            payload[key] = None
        elif isinstance(value, dict):
            _strip_timestamps(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _strip_timestamps(item)


# ---------------------------------------------------------------------
# Property 18: deterministic modulo timestamps
# ---------------------------------------------------------------------


@given(
    fixture_kind=st.sampled_from(["uefi_volume", "microcode"]),
)
@settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_18_deterministic_modulo_timestamps(
    fixture_kind: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Property 18: same input + config produces equal manifests minus timestamps."""

    tmp_path = tmp_path_factory.mktemp("p18")
    config = _make_config(tmp_path)

    if fixture_kind == "uefi_volume":
        binary = synthetic_uefi_volume.build(tmp_path / "in")
    else:
        binary = synthetic_microcode.build(tmp_path / "in")

    a = extract_firmware(binary, config).manifest
    b = extract_firmware(binary, config).manifest

    a_dump = a.model_dump(mode="json")
    b_dump = b.model_dump(mode="json")
    _strip_timestamps(a_dump)
    _strip_timestamps(b_dump)
    # raw_path includes a tmp_path prefix that varies between runs;
    # strip it so we're comparing manifest *shape* not filesystem
    # accidents.
    for dump in (a_dump, b_dump):
        components = dump["components"]
        if isinstance(components, list):
            for component in components:
                if isinstance(component, dict):
                    component["raw_path"] = None

    assert a_dump == b_dump


# ---------------------------------------------------------------------
# Property 19: component_id matches derive_component_id
# ---------------------------------------------------------------------


@given(
    fixture_kind=st.sampled_from(["uefi_volume", "microcode"]),
)
@settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_19_component_id_matches_derivation(
    fixture_kind: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Property 19: every emitted component_id == derive_component_id(...)."""

    tmp_path = tmp_path_factory.mktemp("p19")
    config = _make_config(tmp_path)

    if fixture_kind == "uefi_volume":
        binary = synthetic_uefi_volume.build(tmp_path / "in")
    else:
        binary = synthetic_microcode.build(tmp_path / "in")

    result = extract_firmware(binary, config)
    file_hash = result.manifest.source_image.file_hash

    for component in result.manifest.components:
        offset_int = int(component.offset, 16)
        expected = derive_component_id(
            source_image_hash=file_hash,
            offset=offset_int,
            raw_hash=component.raw_hash,
        )
        assert component.component_id == expected


# ---------------------------------------------------------------------
# Property 20: error component_ids match derive_error_component_id
# ---------------------------------------------------------------------


def test_property_20_error_id_matches_derivation(tmp_path: Path) -> None:
    """Property 20: per-component errors carry derive_error_component_id IDs."""

    # Provoke a per-component error: oversized cap so a real component
    # is skipped and recorded as an error with offset+kind.
    binary = synthetic_microcode.build(tmp_path)
    config = ExtractionConfig(
        default_output_dir=str(tmp_path / "extracted"),
        max_component_size=100,  # smaller than any blob → skip + error
        timeout_per_component=30,
    )
    result = extract_firmware(binary, config)
    errors_with_offsets = [
        e for e in result.manifest.extraction_errors if e.component_id is not None
    ]
    assert errors_with_offsets

    file_hash = result.manifest.source_image.file_hash
    for err in errors_with_offsets:
        # Recover the (offset, error_kind) pair from the message tag.
        # ManifestBuilder embeds `[KIND]` at the start of the message
        # *and* an `at 0x{offset:x}` clause; we use both to reconstruct.
        msg = err.error_message
        kind = msg.split("]", 1)[0].lstrip("[").strip()
        offset_str = msg.split("at 0x", 1)[1].split()[0]
        offset = int(offset_str, 16)
        expected = derive_error_component_id(
            source_image_hash=file_hash,
            offset=offset,
            error_kind=kind,
        )
        assert err.component_id == expected


# ---------------------------------------------------------------------
# Property 21: output filenames are pure functions of (offset, raw_hash)
# ---------------------------------------------------------------------


def test_property_21_output_filenames_are_pure(tmp_path: Path) -> None:
    """Property 21: every written file name == ``f"0x{offset:x}-{raw_hash}.bin"``."""

    binary = synthetic_microcode.build(tmp_path / "in")
    config = _make_config(tmp_path)
    result = extract_firmware(binary, config)
    for component in result.manifest.components:
        assert component.raw_path is not None
        path = Path(component.raw_path)
        offset_int = int(component.offset, 16)
        assert path.name == f"0x{offset_int:x}-{component.raw_hash}.bin"
