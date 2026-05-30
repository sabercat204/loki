"""Tests for the public ``extract_firmware`` entry point (task 19).

Covers R1, R5.1, R5.9, R9.1-9.5, R10 logging hooks. Per-format
extraction details belong in the per-extractor test modules; this
suite only checks the public contract.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from loki.extraction import (
    ExtractionPipelineError,
    ExtractionResult,
    InvalidInputError,
    ProgressEvent,
    extract_firmware,
)
from loki.extraction.extractors.base import clear_registry
from loki.models import ExtractionConfig
from tests.extraction.fixtures import (
    synthetic_microcode,
    synthetic_uefi_volume,
)


@pytest.fixture(autouse=True)
def _registry_isolation() -> Iterator[None]:
    """Each test starts and ends with an empty registry."""
    clear_registry()
    yield
    clear_registry()


@pytest.fixture()
def config(tmp_path: Path) -> ExtractionConfig:
    return ExtractionConfig(
        default_output_dir=str(tmp_path / "extracted"),
        max_component_size=10_000_000,
        timeout_per_component=30,
    )


# ---------------------------------------------------------------------
# R1.1-R1.4 — input validation
# ---------------------------------------------------------------------


def test_raises_invalid_input_when_path_missing(config: ExtractionConfig, tmp_path: Path) -> None:
    with pytest.raises(InvalidInputError, match="path does not exist"):
        extract_firmware(tmp_path / "missing.rom", config)


def test_raises_invalid_input_when_path_is_directory(
    config: ExtractionConfig, tmp_path: Path
) -> None:
    target = tmp_path / "as-dir"
    target.mkdir()
    with pytest.raises(InvalidInputError, match="not a regular file"):
        extract_firmware(target, config)


def test_raises_invalid_input_when_file_empty(config: ExtractionConfig, tmp_path: Path) -> None:
    target = tmp_path / "empty.rom"
    target.write_bytes(b"")
    with pytest.raises(InvalidInputError, match="file is empty"):
        extract_firmware(target, config)


# ---------------------------------------------------------------------
# Happy path on synthetic fixtures
# ---------------------------------------------------------------------


def test_extracts_microcode_fixture_into_validated_manifest(
    config: ExtractionConfig, tmp_path: Path
) -> None:
    binary = synthetic_microcode.build(tmp_path / "mc")
    result = extract_firmware(binary, config)
    assert isinstance(result, ExtractionResult)
    assert result.manifest.total_components == 2  # two synthetic blobs
    assert result.duration_seconds >= 0
    # File hash matches a fresh hashlib call.
    expected = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert result.manifest.source_image.file_hash == expected


def test_extracts_uefi_volume_fixture(config: ExtractionConfig, tmp_path: Path) -> None:
    binary = synthetic_uefi_volume.build(tmp_path / "uefi")
    result = extract_firmware(binary, config)
    assert result.manifest.total_components == 1
    component = result.manifest.components[0]
    assert component.name == synthetic_uefi_volume.FFS_FILE_NAME


# ---------------------------------------------------------------------
# R3.12-R3.13 — output_dir handling
# ---------------------------------------------------------------------


def test_writes_carved_bytes_when_output_dir_writable(
    config: ExtractionConfig, tmp_path: Path
) -> None:
    binary = synthetic_microcode.build(tmp_path / "mc")
    result = extract_firmware(binary, config)
    for component in result.manifest.components:
        assert component.raw_path is not None
        path = Path(component.raw_path)
        assert path.exists()
        # Filename is `0x{offset:x}-{raw_hash}.bin` per R7.4.
        assert path.name == f"0x{int(component.offset, 16):x}-{component.raw_hash}.bin"


def test_skips_raw_path_when_no_output_dir(config: ExtractionConfig, tmp_path: Path) -> None:
    binary = synthetic_microcode.build(tmp_path / "mc")
    bare_config = ExtractionConfig(
        default_output_dir="",
        max_component_size=config.max_component_size,
        timeout_per_component=config.timeout_per_component,
    )
    result = extract_firmware(binary, bare_config)
    for component in result.manifest.components:
        assert component.raw_path is None


# ---------------------------------------------------------------------
# R2.8 — out-of-scope binaries still produce a manifest
# ---------------------------------------------------------------------


def test_unrecognized_binary_produces_manifest_with_one_error(
    config: ExtractionConfig, tmp_path: Path
) -> None:
    target = tmp_path / "garbage.rom"
    target.write_bytes(b"\x00" * 4096)
    result = extract_firmware(target, config)
    assert result.manifest.components == []
    assert any("OUT_OF_SCOPE_FORMAT" in e.error_message for e in result.manifest.extraction_errors)


# ---------------------------------------------------------------------
# R9.2-R9.3 — progress callback
# ---------------------------------------------------------------------


def test_progress_callback_observes_phase_transitions(
    config: ExtractionConfig, tmp_path: Path
) -> None:
    binary = synthetic_microcode.build(tmp_path / "mc")
    events: list[ProgressEvent] = []
    extract_firmware(binary, config, progress=events.append)
    phases = {ev.phase for ev in events}
    assert "input-check" in phases
    assert "detect" in phases
    assert "extract" in phases


# ---------------------------------------------------------------------
# R9.4 — cancellation
# ---------------------------------------------------------------------


def test_cancel_token_short_circuits_between_components(
    config: ExtractionConfig, tmp_path: Path
) -> None:
    binary = synthetic_microcode.build(tmp_path / "mc")
    state = {"checks": 0}

    def cancel() -> bool:
        state["checks"] += 1
        # Cancel after the first cancellation check, which happens
        # before the first component is added.
        return state["checks"] >= 1

    result = extract_firmware(binary, config, cancel=cancel)
    assert any(
        e.error_message == "extraction cancelled by caller"
        for e in result.manifest.extraction_errors
    )
    # No components should have been added since cancel triggered
    # before the first add_component call.
    assert result.manifest.components == []


# ---------------------------------------------------------------------
# R4.5 — optional tool absence is reported, doesn't abort
# ---------------------------------------------------------------------


def test_optional_tool_absence_records_informational_error(
    config: ExtractionConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When UEFIExtract / chipsec_util aren't on PATH, extraction
    still completes and emits one info ExtractionError per missing tool."""

    # Force ``shutil.which`` to return None for both optional tools
    # in the wrapper modules. Patching it on the wrapper module
    # itself is more reliable than patching the global stdlib import.
    monkeypatch.setattr("loki.extraction.tools.uefitool.shutil.which", lambda name: None)
    monkeypatch.setattr("loki.extraction.tools.chipsec.shutil.which", lambda name: None)

    binary = synthetic_microcode.build(tmp_path / "mc")
    result = extract_firmware(binary, config)

    assert result.tools_available["uefi_firmware"] is True
    assert result.tools_available["uefitool"] is False
    assert result.tools_available["chipsec"] is False
    missing_errors = [
        e for e in result.manifest.extraction_errors if "OPTIONAL_TOOL_MISSING" in e.error_message
    ]
    assert len(missing_errors) == 2


# ---------------------------------------------------------------------
# R4.5 (negative case) — required tool absence aborts
# ---------------------------------------------------------------------


def test_required_tool_absence_raises_pipeline_error(
    config: ExtractionConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``uefi_firmware`` can't be imported, the pipeline aborts
    with a typed :class:`ExtractionPipelineError` rather than producing
    a partial manifest."""

    binary = synthetic_microcode.build(tmp_path / "mc")

    class _BrokenWrapper:
        name = "uefi_firmware"
        required = True

        def probe(self) -> None:
            raise ExtractionPipelineError("simulated missing required tool")

        def shutdown(self) -> None:
            pass

    monkeypatch.setattr("loki.extraction.api.UefiFirmwareWrapper", _BrokenWrapper)

    with pytest.raises(ExtractionPipelineError):
        extract_firmware(binary, config)


# ---------------------------------------------------------------------
# R7.1 — determinism modulo timestamps
# ---------------------------------------------------------------------


def test_two_runs_produce_identical_manifests_modulo_timestamps(
    config: ExtractionConfig, tmp_path: Path
) -> None:
    binary = synthetic_microcode.build(tmp_path / "mc")
    a = extract_firmware(binary, config).manifest
    b = extract_firmware(binary, config).manifest

    a_dump = a.model_dump(mode="json")
    b_dump = b.model_dump(mode="json")
    # Strip timestamp-bearing fields before comparison.
    for dump in (a_dump, b_dump):
        dump["extraction_timestamp"] = None
        dump["source_image"]["extraction_timestamp"] = None
        for err in dump["extraction_errors"]:
            err["timestamp"] = None
        # raw_path may differ across tmp_path runs — strip from each component
        # for the determinism comparison.
        for comp in dump["components"]:
            comp["raw_path"] = None

    assert a_dump == b_dump
