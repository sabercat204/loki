"""Golden-file regression test (task 17).

Builds a deterministic :class:`BaselineRecord` via the synthetic
fixture, saves it through the full :class:`BaselineStore` pipeline,
and compares the resulting Baseline_File against checked-in
snapshots. Catches accidental drift in:

- The envelope's serialized YAML shape (R3.4-R3.7).
- The model layer's ``model_dump(mode="json")`` output for
  :class:`BaselineRecord` and its nested
  :class:`ClassificationRecord` instances.
- The on-disk byte stream produced by ``yaml.safe_dump`` with
  ``sort_keys=True``, ``default_flow_style=False``, and
  ``allow_unicode=True``.

Two snapshots:

- ``canonical_v1.yaml`` is the full Baseline_File as written to disk
  (including the envelope). Compared modulo the volatile
  ``written_at`` envelope field.
- ``canonical_v1.json`` is the re-loaded baseline payload after
  stripping volatile fields. Compared as a Python dict so any drift
  in the model layer's serialization shape surfaces with a clean
  diff rather than a YAML-byte mismatch.

Regenerating the snapshots:

1. Set ``LOKI_REGENERATE_GOLDEN=1`` and re-run this test.
2. Inspect the diffs and bump the snapshot filename if the change
   is intentional (``canonical_v1.*`` -> ``canonical_v2.*``).
3. Commit both the updated builder *and* the regenerated snapshots
   together.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC
from datetime import datetime as real_datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from loki.baseline.naming import filename_for
from loki.baseline.store import BaselineStore
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.fixtures import synthetic_baseline

#: Snapshot directory; lives next to the synthetic fixture builder so
#: future revisions stay co-located with their inputs.
_GOLDEN_DIR: Path = Path(__file__).parent / "fixtures" / "golden"
_GOLDEN_YAML: Path = _GOLDEN_DIR / "canonical_v1.yaml"
_GOLDEN_JSON: Path = _GOLDEN_DIR / "canonical_v1.json"

#: Frozen ``written_at`` value used for snapshot generation. Holds
#: the envelope's volatile field steady so two runs of the test
#: produce byte-identical output.
_FROZEN_WRITTEN_AT = real_datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


class _FrozenDatetime(real_datetime):
    """Freezes ``datetime.now(tz=...)`` to :data:`_FROZEN_WRITTEN_AT`.

    Patched into :mod:`loki.baseline.store` for the duration of the
    snapshot-comparison test so the envelope's ``written_at`` field
    matches the on-disk YAML byte-for-byte.
    """

    @classmethod
    def now(cls, tz: object | None = None) -> real_datetime:  # type: ignore[override]
        return _FROZEN_WRITTEN_AT


def _build_canonical_record() -> BaselineRecord:
    """Build the deterministic :class:`BaselineRecord` for the snapshot."""
    return synthetic_baseline.build(
        vendor="INTEL",
        model="DEMO-X1",
        firmware_version="1.0",
        classification_count=3,
    )


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def _store(path: Path) -> BaselineStore:
    return BaselineStore(_config(path))


def _strip_envelope_volatile(parsed: dict[str, Any]) -> dict[str, Any]:
    """Return the ``baseline`` subtree only.

    The envelope's ``written_at`` is the only legitimately volatile
    field, but stripping the entire envelope on the JSON snapshot
    keeps the comparison focused on the baseline payload — the
    persistence layer's reason for existing.
    """
    subtree = parsed["baseline"]
    assert isinstance(subtree, dict), (
        f"baseline subtree must be a mapping, got {type(subtree).__name__}"
    )
    return subtree


def _normalize_written_by(text: str) -> str:
    """Replace ``written_by_extractor_version`` with a stable token.

    ``loki.baseline.store._DEFAULT_WRITTEN_BY`` is computed at
    module-import time from ``importlib.metadata.version('loki')``,
    so the value drifts whenever the project version is bumped.
    Normalize it for the YAML snapshot so a version bump doesn't
    invalidate the golden file.
    """
    return re.sub(
        r"^written_by_extractor_version: .*$",
        'written_by_extractor_version: "loki-GOLDEN"',
        text,
        flags=re.MULTILINE,
    )


# ---------------------------------------------------------------------
# Snapshot comparison
# ---------------------------------------------------------------------


def test_canonical_baseline_matches_yaml_snapshot(tmp_path: Path) -> None:
    """The full Baseline_File matches ``canonical_v1.yaml`` byte-for-byte.

    Modulo the ``written_by_extractor_version`` field, which is
    normalized via :func:`_normalize_written_by` so version bumps
    don't invalidate the snapshot.
    """
    record = _build_canonical_record()
    store = _store(tmp_path)
    with patch("loki.baseline.store.datetime", _FrozenDatetime):
        saved_path = store.save(record, written_by="loki-GOLDEN")

    actual_yaml = _normalize_written_by(saved_path.read_text(encoding="utf-8"))

    if os.environ.get("LOKI_REGENERATE_GOLDEN") == "1":
        _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        _GOLDEN_YAML.write_text(actual_yaml, encoding="utf-8")
        pytest.skip("YAML snapshot regenerated; re-run without env var to verify")

    assert _GOLDEN_YAML.exists(), (
        f"golden YAML snapshot missing at {_GOLDEN_YAML}; "
        f"run with LOKI_REGENERATE_GOLDEN=1 to create it"
    )

    expected = _GOLDEN_YAML.read_text(encoding="utf-8")
    assert actual_yaml == expected


def test_canonical_baseline_matches_json_snapshot(tmp_path: Path) -> None:
    """The re-loaded baseline payload matches ``canonical_v1.json``.

    Strips envelope fields entirely; only the baseline subtree is
    compared. The JSON form is committed because diffs against
    arbitrary Python dicts are noisy in failure output, while
    JSON diffs are clean.
    """
    record = _build_canonical_record()
    store = _store(tmp_path)
    with patch("loki.baseline.store.datetime", _FrozenDatetime):
        saved_path = store.save(record, written_by="loki-GOLDEN")

    parsed = yaml.safe_load(saved_path.read_bytes())
    baseline_payload = _strip_envelope_volatile(parsed)

    if os.environ.get("LOKI_REGENERATE_GOLDEN") == "1":
        _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        _GOLDEN_JSON.write_text(
            json.dumps(baseline_payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        pytest.skip("JSON snapshot regenerated; re-run without env var to verify")

    assert _GOLDEN_JSON.exists(), (
        f"golden JSON snapshot missing at {_GOLDEN_JSON}; "
        f"run with LOKI_REGENERATE_GOLDEN=1 to create it"
    )

    expected = json.loads(_GOLDEN_JSON.read_text(encoding="utf-8"))
    assert baseline_payload == expected


def test_canonical_baseline_round_trips_through_load_one(tmp_path: Path) -> None:
    """A baseline saved at ``written_at=frozen`` then loaded round-trips losslessly.

    Belt-and-braces complement to the JSON snapshot: even if the
    snapshot were stale, this test confirms the round-trip
    contract holds for the deterministic fixture. Property 24
    in spirit, but pinned to the canonical record rather than
    a Hypothesis-generated one.
    """
    record = _build_canonical_record()
    store = _store(tmp_path)
    with patch("loki.baseline.store.datetime", _FrozenDatetime):
        saved_path = store.save(record, written_by="loki-GOLDEN")

    loaded = store.load_one(saved_path)
    assert loaded.model_dump(mode="json") == record.model_dump(mode="json")


def test_canonical_filename_is_stable() -> None:
    """The canonical record's Baseline_Filename is stable across runs.

    A regression in ``naming.slug`` or ``naming.filename_for`` would
    change the on-disk filename. The golden snapshot lives at a
    stable path; this test pins that path so a slugification change
    surfaces clearly rather than as a confusing snapshot mismatch.
    """
    record = _build_canonical_record()
    assert filename_for(record) == "intel-demo-x1-1.0.yaml"
