"""Hypothesis-backed determinism + round-trip properties (task 14).

Covers Properties 24, 25, and 26 from the design's "Correctness
Properties" section:

- **Property 24** — save → load round-trips losslessly. For every
  ``BaselineRecord`` ``r`` and every fresh ``BaselineStore`` ``s``,
  ``s.load_one(s.save(r))`` returns a record equal to ``r`` under
  ``model_dump(mode="json")``.
- **Property 25** — two saves produce byte-identical files modulo
  the ``written_at`` envelope field. ``yaml.safe_dump`` with
  ``sort_keys=True`` plus ``model_dump(mode="json")`` for the
  payload is what makes this hold.
- **Property 26** — load → save → load preserves the baseline
  payload subtree under ``yaml.safe_load``. Envelope fields are
  excluded from the equality check.

The matching invariant property (Property 23) lives in its own
file (``test_manifest_invariants.py``) so it can be run in
isolation when the model layer changes.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime as real_datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml
from hypothesis import HealthCheck, given, settings

from loki.baseline.store import BaselineStore
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.conftest import parameterized_baseline_record

# Hypothesis settings tuned to the persistence layer's per-example
# cost: each example saves a YAML file to disk and reads it back, so
# we keep ``max_examples`` modest. The model-layer PBT files use 50;
# 25 here gives the same coverage in roughly the same wall time
# because each persistence example does more work per draw.
_PERSISTENCE_HEALTH = settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    deadline=None,
)


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def _store(path: Path) -> BaselineStore:
    return BaselineStore(_config(path))


def _strip_envelope_volatile(loaded: dict[str, Any]) -> dict[str, Any]:
    """Return the ``baseline`` subtree with envelope fields stripped.

    Property 26's equality check excludes ``schema_version``,
    ``written_at``, and ``written_by_extractor_version`` since
    only the baseline payload itself must round-trip.
    """
    subtree = loaded["baseline"]
    assert isinstance(subtree, dict), (
        f"baseline subtree must be a mapping, got {type(subtree).__name__}"
    )
    return subtree


# ---------------------------------------------------------------------
# Property 24: save → load round-trip is lossless
# ---------------------------------------------------------------------


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_24_save_load_round_trip_is_lossless(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 24: ``s.load_one(s.save(r))`` equals ``r``."""
    # ``tmp_path_factory`` is a pytest fixture but Hypothesis won't
    # accept it via the @given signature, so we cast to its real
    # type and use ``mktemp``.
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p24_save_load")
    store = _store(storage)
    saved_path = store.save(record)

    # ``load_one`` is the natural single-record surface — task 12
    # implements it as a typed-error sibling of ``load``.
    loaded = store.load_one(saved_path)
    assert loaded.model_dump(mode="json") == record.model_dump(mode="json")


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_24_round_trip_preserves_baseline_id(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 24 sub-invariant: ``baseline_id`` is preserved exactly."""
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p24_baseline_id")
    store = _store(storage)
    saved_path = store.save(record)
    loaded = store.load_one(saved_path)
    assert loaded.baseline_id == record.baseline_id


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_24_round_trip_preserves_component_manifest(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 24 sub-invariant: ``component_manifest`` is preserved.

    Validates that the persistence layer's YAML serialization
    doesn't reorder, drop, or coerce the classifications inside
    the manifest. This is the property that would break first if
    the envelope's ``sort_keys=True`` accidentally bled into the
    payload.
    """
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p24_manifest")
    store = _store(storage)
    saved_path = store.save(record)
    loaded = store.load_one(saved_path)
    assert len(loaded.component_manifest) == len(record.component_manifest)
    for original, round_tripped in zip(
        record.component_manifest, loaded.component_manifest, strict=True
    ):
        assert original.model_dump(mode="json") == round_tripped.model_dump(mode="json")


# ---------------------------------------------------------------------
# Property 25: two saves produce byte-identical files modulo `written_at`
# ---------------------------------------------------------------------


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_25_byte_identical_modulo_written_at(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 25: same record + same ``written_at`` → identical bytes.

    Freezes ``datetime.now(tz=UTC)`` to a fixed value and saves the
    same record twice. The bytes must match exactly. This pins
    R3.7 (sort_keys=True) and R3.6 (model_dump(mode="json"))
    against future regressions in the YAML emitter.
    """
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p25")
    store = _store(storage)

    fixed = real_datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)

    class _FrozenDatetime(real_datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> real_datetime:  # type: ignore[override]
            return fixed

    with patch("loki.baseline.store.datetime", _FrozenDatetime):
        first_path = store.save(record)
        first_bytes = first_path.read_bytes()
        # Second save would normally trip the mtime check because
        # the snapshot just got refreshed, but we want bytewise
        # equality so we use force=True to skip the check.
        second_path = store.save(record, force=True)
        second_bytes = second_path.read_bytes()

    assert first_bytes == second_bytes


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_25_envelope_keys_are_sorted(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 25 sub-invariant: envelope keys land in sorted order.

    R3.7 mandates ``sort_keys=True`` on the YAML emitter. Verify
    by parsing the saved file's top-level keys and asserting they
    appear in lexicographic order — the contract that makes
    determinism testable in the first place.
    """
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p25_keys")
    store = _store(storage)
    saved = store.save(record)
    text = saved.read_text(encoding="utf-8")

    # Find the four top-level keys in the order they appear in the
    # serialized text (i.e. column-zero ``key:`` lines).
    keys_in_order = [
        line.split(":", 1)[0]
        for line in text.splitlines()
        if line and not line.startswith(" ") and not line.startswith("-") and ":" in line
    ]
    # The four required envelope keys must be present in sorted order.
    expected = ["baseline", "schema_version", "written_at", "written_by_extractor_version"]
    found = [k for k in keys_in_order if k in expected]
    assert found == expected


# ---------------------------------------------------------------------
# Property 26: load → save → load preserves the baseline payload
# ---------------------------------------------------------------------


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_26_load_save_load_preserves_payload(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 26: load → save → load preserves the baseline subtree.

    The full sequence: save the record, load the file, save it
    again, load the file again. The ``baseline`` subtree under
    ``yaml.safe_load`` of the second-loaded file must equal the
    same subtree of the first-loaded file. Envelope fields are
    excluded since ``written_at`` legitimately drifts.
    """
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p26")
    store = _store(storage)

    # First save → load
    first_path = store.save(record)
    first_loaded_yaml = yaml.safe_load(first_path.read_bytes())
    first_baseline_subtree = _strip_envelope_volatile(first_loaded_yaml)

    # Mutate-free re-save: load_one then save again. The store's
    # snapshot for this baseline_id is from the first save, so a
    # second save must replace at the same path.
    record_again = store.load_one(first_path)
    second_path = store.save(record_again)
    assert second_path == first_path  # same canonical filename

    second_loaded_yaml = yaml.safe_load(second_path.read_bytes())
    second_baseline_subtree = _strip_envelope_volatile(second_loaded_yaml)

    assert first_baseline_subtree == second_baseline_subtree


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_26_envelope_fields_are_volatile_only_for_written_at(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 26 sub-invariant: only ``written_at`` legitimately drifts.

    ``schema_version`` and ``written_by_extractor_version`` are
    constants for a given store + loki version, so they must
    match across the save → save sequence even though the spec
    only mandates the baseline subtree.
    """
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p26_envelope")
    store = _store(storage)

    first_path = store.save(record)
    first_yaml = yaml.safe_load(first_path.read_bytes())

    record_again = store.load_one(first_path)
    second_path = store.save(record_again)
    second_yaml = yaml.safe_load(second_path.read_bytes())

    assert first_yaml["schema_version"] == second_yaml["schema_version"]
    assert first_yaml["written_by_extractor_version"] == second_yaml["written_by_extractor_version"]
