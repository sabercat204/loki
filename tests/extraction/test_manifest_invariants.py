"""Hypothesis property tests for manifest invariants (task 22, properties 12-17).

These are the invariants the model layer enforces but we re-pin them
at the extraction level: a regression in :mod:`loki.extraction` that
violated one of these would silently corrupt every downstream
subsystem.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.extraction import extract_firmware
from loki.extraction.extractors.base import clear_registry
from loki.models import ExtractionConfig, ExtractionManifest
from tests.extraction.fixtures import (
    synthetic_microcode,
    synthetic_option_rom,
    synthetic_uefi_volume,
)


@pytest.fixture(autouse=True)
def _registry_isolation() -> Iterator[None]:
    clear_registry()
    yield
    clear_registry()


_FIXTURE_KINDS = ["uefi_volume", "microcode", "option_rom"]


def _build_fixture(kind: str, base: Path) -> Path:
    if kind == "uefi_volume":
        return synthetic_uefi_volume.build(base / "in")
    if kind == "microcode":
        return synthetic_microcode.build(base / "in")
    if kind == "option_rom":
        return synthetic_option_rom.build(base / "in")
    raise ValueError(f"unknown fixture kind: {kind!r}")


def _config(base: Path) -> ExtractionConfig:
    return ExtractionConfig(
        default_output_dir=str(base / "extracted"),
        max_component_size=10_000_000,
        timeout_per_component=30,
    )


# ---------------------------------------------------------------------
# Property 12: validated on return
# ---------------------------------------------------------------------


@given(fixture_kind=st.sampled_from(_FIXTURE_KINDS))
@settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_12_manifest_is_pydantic_validated(
    fixture_kind: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Property 12: returned manifest survives a re-validate round-trip."""

    tmp = tmp_path_factory.mktemp("p12")
    binary = _build_fixture(fixture_kind, tmp)
    result = extract_firmware(binary, _config(tmp))
    revalidated = ExtractionManifest.model_validate(
        result.manifest.model_dump(mode="json"),
        strict=False,
    )
    assert revalidated == result.manifest


# ---------------------------------------------------------------------
# Property 13: total_components == len(components)
# ---------------------------------------------------------------------


@given(fixture_kind=st.sampled_from(_FIXTURE_KINDS))
@settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_13_total_components_matches_length(
    fixture_kind: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Property 13: ``total_components == len(components)``."""

    tmp = tmp_path_factory.mktemp("p13")
    binary = _build_fixture(fixture_kind, tmp)
    result = extract_firmware(binary, _config(tmp))
    assert result.manifest.total_components == len(result.manifest.components)


# ---------------------------------------------------------------------
# Property 14: component_id uniqueness
# ---------------------------------------------------------------------


@given(fixture_kind=st.sampled_from(_FIXTURE_KINDS))
@settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_14_component_id_unique(
    fixture_kind: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Property 14: every component_id is unique within the manifest."""

    tmp = tmp_path_factory.mktemp("p14")
    binary = _build_fixture(fixture_kind, tmp)
    result = extract_firmware(binary, _config(tmp))
    ids = [c.component_id for c in result.manifest.components]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------
# Property 15: components ordered by ascending offset
# ---------------------------------------------------------------------


@given(fixture_kind=st.sampled_from(_FIXTURE_KINDS))
@settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_15_components_ordered_by_offset(
    fixture_kind: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Property 15: integer offsets are non-decreasing in ``components``."""

    tmp = tmp_path_factory.mktemp("p15")
    binary = _build_fixture(fixture_kind, tmp)
    result = extract_firmware(binary, _config(tmp))
    offsets = [int(c.offset, 16) for c in result.manifest.components]
    assert offsets == sorted(offsets)


# ---------------------------------------------------------------------
# Property 16: JSON round-trip
# ---------------------------------------------------------------------


@given(fixture_kind=st.sampled_from(_FIXTURE_KINDS))
@settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_16_json_round_trip(
    fixture_kind: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Property 16: ``model_validate_json(model_dump_json()) == manifest``."""

    tmp = tmp_path_factory.mktemp("p16")
    binary = _build_fixture(fixture_kind, tmp)
    manifest = extract_firmware(binary, _config(tmp)).manifest
    restored = ExtractionManifest.model_validate_json(manifest.model_dump_json())
    assert restored == manifest


# ---------------------------------------------------------------------
# Property 17: YAML round-trip
# ---------------------------------------------------------------------


@given(fixture_kind=st.sampled_from(_FIXTURE_KINDS))
@settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_17_yaml_round_trip(
    fixture_kind: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Property 17: YAML serialization round-trips losslessly."""

    tmp = tmp_path_factory.mktemp("p17")
    binary = _build_fixture(fixture_kind, tmp)
    manifest = extract_firmware(binary, _config(tmp)).manifest
    yaml_text = yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=False)
    parsed = yaml.safe_load(yaml_text)
    # ``strict=False`` mirrors ``LokiConfig.from_yaml``: lets ISO datetime
    # strings coerce back to ``datetime`` while keeping the field-level
    # validators (hash format, hex offset, etc.) live.
    restored = ExtractionManifest.model_validate(parsed, strict=False)
    assert restored == manifest
