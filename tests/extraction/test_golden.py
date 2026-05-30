"""Golden-file regression test (task 23).

Builds the synthetic UEFI volume fixture, extracts it, and compares
the resulting manifest against a checked-in JSON snapshot. Catches
accidental changes to the extractor's output shape — anything that
would cause a baseline mismatch in downstream consumers.

Regenerating the snapshot:

1. Set ``LOKI_REGENERATE_GOLDEN=1`` and re-run this test.
2. Inspect the diff and bump the fixture filename if the change is
   intentional (``uefi_volume_v1.bin`` -> ``uefi_volume_v2.bin``).
3. Commit both the updated fixture builder *and* the regenerated
   snapshot together.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from loki.extraction import extract_firmware
from loki.extraction.extractors.base import clear_registry
from loki.models import ExtractionConfig
from tests.extraction.fixtures import synthetic_uefi_volume

# Snapshot lives next to the synthetic fixture builder so future
# revisions stay co-located.
_GOLDEN_DIR: Path = Path(__file__).parent / "fixtures" / "golden"
_GOLDEN_PATH: Path = _GOLDEN_DIR / "uefi_volume_v1.json"


@pytest.fixture(autouse=True)
def _registry_isolation() -> Iterator[None]:
    clear_registry()
    yield
    clear_registry()


def _strip_volatile_fields(payload: dict[str, object]) -> None:
    """None-out timestamps and the absolute path fields that vary per-run."""

    if not isinstance(payload, dict):
        return
    for key in list(payload):
        value = payload[key]
        if key in {"extraction_timestamp", "timestamp"}:
            payload[key] = None
        elif key == "file_path":
            # The synthetic volume's tmp_path differs per run.
            payload[key] = None
        elif key == "raw_path":
            payload[key] = None
        elif isinstance(value, dict):
            _strip_volatile_fields(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _strip_volatile_fields(item)


def test_synthetic_uefi_volume_manifest_matches_golden(tmp_path: Path) -> None:
    """The synthetic UEFI volume's extracted manifest matches the snapshot."""

    binary = synthetic_uefi_volume.build(tmp_path)
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=1_000_000,
        timeout_per_component=30,
    )
    result = extract_firmware(binary, config)
    payload = result.manifest.model_dump(mode="json")
    _strip_volatile_fields(payload)

    if os.environ.get("LOKI_REGENERATE_GOLDEN") == "1":
        _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        _GOLDEN_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
        pytest.skip("snapshot regenerated; re-run without env var to verify")

    assert _GOLDEN_PATH.exists(), (
        f"golden snapshot missing at {_GOLDEN_PATH}; run with LOKI_REGENERATE_GOLDEN=1 to create it"
    )

    expected = json.loads(_GOLDEN_PATH.read_text())
    assert payload == expected
