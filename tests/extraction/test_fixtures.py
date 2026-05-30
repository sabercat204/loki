"""Smoke tests for the synthetic-binary fixtures (task 18).

Each fixture is paired with the format detector to confirm the
generated binaries are at least format-valid enough that
:func:`detect_formats` recognizes them. Per-extractor tests in
tasks 13-17 exercise the builders in more depth.
"""

from __future__ import annotations

from pathlib import Path

from loki.extraction.detection import FormatKind, detect_formats
from loki.extraction.streaming import StreamingHasher
from tests.extraction.fixtures import (
    synthetic_microcode,
    synthetic_option_rom,
    synthetic_uefi_volume,
)


def _detect_for(path: Path) -> list[FormatKind]:
    _, file_size, peek = StreamingHasher(path).hash_file()
    return [d.kind for d in detect_formats(peek, file_size=file_size)]


def test_synthetic_uefi_volume_is_detected(synthetic_uefi_volume_path: Path) -> None:
    kinds = _detect_for(synthetic_uefi_volume_path)
    assert FormatKind.UEFI_PI_VOLUME in kinds


def test_synthetic_option_rom_is_detected(synthetic_option_rom_path: Path) -> None:
    kinds = _detect_for(synthetic_option_rom_path)
    assert FormatKind.PCI_OPTION_ROM in kinds


def test_synthetic_microcode_is_detected(synthetic_microcode_path: Path) -> None:
    kinds = _detect_for(synthetic_microcode_path)
    assert FormatKind.INTEL_MICROCODE in kinds


def test_synthetic_uefi_volume_size_is_stable(tmp_path: Path) -> None:
    """The builder is deterministic; same inputs produce the same bytes."""
    a = synthetic_uefi_volume.build(tmp_path / "a")
    b = synthetic_uefi_volume.build(tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()
    assert a.stat().st_size == synthetic_uefi_volume.FV_LENGTH


def test_synthetic_option_rom_size_is_stable(tmp_path: Path) -> None:
    a = synthetic_option_rom.build(tmp_path / "a")
    b = synthetic_option_rom.build(tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()


def test_synthetic_microcode_size_is_stable(tmp_path: Path) -> None:
    a = synthetic_microcode.build(tmp_path / "a")
    b = synthetic_microcode.build(tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()
