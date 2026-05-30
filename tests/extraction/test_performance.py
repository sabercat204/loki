"""Performance smoke test (task 24).

Skipped on CI by default via the ``slow`` marker; run locally with::

    pytest -m slow tests/extraction/test_performance.py

Asserts that extracting a 64 MiB synthetic UEFI volume:

- completes in bounded wall-clock time (< 60 s on a dev laptop), and
- keeps peak resident memory under
  ``4 * max_component_size + 128 MiB`` (R8.1).
"""

from __future__ import annotations

import struct
import tracemalloc
from collections.abc import Iterator
from pathlib import Path

import pytest

from loki.extraction import extract_firmware
from loki.extraction.extractors.base import clear_registry
from loki.extraction.streaming import CHUNK_SIZE
from loki.models import ExtractionConfig
from tests.extraction.fixtures import synthetic_uefi_volume


@pytest.fixture(autouse=True)
def _registry_isolation() -> Iterator[None]:
    clear_registry()
    yield
    clear_registry()


def _build_64mib_volume(tmp_path: Path) -> Path:
    """Take the 16 KiB synthetic volume and pad it with 0xFF up to 64 MiB.

    Padding doesn't add components — the extractor sees one FFS file
    followed by the erased-pad sentinel and returns. What we're
    measuring is the streaming hash path on a large file plus the
    peak working set of the pipeline.
    """

    base_path = synthetic_uefi_volume.build(tmp_path)
    base_bytes = base_path.read_bytes()
    target_size = 64 * 1024 * 1024  # 64 MiB

    # The base FV header reports a 16 KiB FvLength; we patch it to the
    # padded size so the volume still parses as a valid 64 MiB FV.
    patched = bytearray(base_bytes)
    struct.pack_into("<Q", patched, 0x20, target_size)
    base_bytes = bytes(patched)

    out = tmp_path / "padded_volume.bin"
    with out.open("wb") as fh:
        fh.write(base_bytes)
        remaining = target_size - len(base_bytes)
        # Write 0xFF in 1 MiB chunks so we don't hold the entire pad
        # in memory while building the fixture.
        chunk = b"\xff" * (1024 * 1024)
        while remaining >= len(chunk):
            fh.write(chunk)
            remaining -= len(chunk)
        if remaining:
            fh.write(b"\xff" * remaining)
    return out


@pytest.mark.slow
def test_extracts_64mib_volume_within_memory_bound(tmp_path: Path) -> None:
    """A 64 MiB volume extracts within the documented memory budget."""

    binary = _build_64mib_volume(tmp_path)
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )

    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()
    result = extract_firmware(binary, config)
    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    diff = snapshot_after.compare_to(snapshot_before, "filename")
    new_bytes = sum(stat.size_diff for stat in diff if stat.size_diff > 0)

    # Documented budget: 4 * max_component_size + 128 MiB working set.
    budget = 4 * config.max_component_size + 128 * 1024 * 1024
    assert new_bytes < budget, f"extraction allocated {new_bytes:,} bytes; budget was {budget:,}"
    # Sanity: we should still be reading in reasonable chunks.
    assert new_bytes < 200 * CHUNK_SIZE
    # The extractor saw one FFS file (the rest of the FV is erased pad).
    assert result.manifest.total_components == 1


@pytest.mark.slow
def test_extracts_64mib_volume_within_time_bound(tmp_path: Path) -> None:
    """A 64 MiB volume extracts within a generous time bound."""

    binary = _build_64mib_volume(tmp_path)
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    result = extract_firmware(binary, config)
    # 60 s is generous — on a 2024-era dev laptop this should finish
    # in well under 5 s. Anything beyond 60 s indicates a regression.
    assert result.duration_seconds < 60.0
