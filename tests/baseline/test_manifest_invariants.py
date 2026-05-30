"""Hypothesis-backed manifest invariants (task 14).

Covers Property 23 from the design's "Correctness Properties":

- **Property 23** — every record in the registry returned by
  :meth:`BaselineStore.load` passes Pydantic re-validation. Any
  caller can use the registry without re-validating.

The persistence layer's ``model_validate`` calls use
``strict=False`` per the design's deferred decision (datetime
strings need to coerce when re-loaded from YAML). Property 23
asserts that the *output* of those calls — the records that
land in :attr:`LoadResult.registry.baselines` — re-validate
cleanly under the same relaxed rules. If a record snuck through
that re-validation rejects, the load contract is broken.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings

from loki.baseline.envelope import serialize
from loki.baseline.naming import filename_for
from loki.baseline.schema import SCHEMA_VERSION
from loki.baseline.store import BaselineStore
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.conftest import parameterized_baseline_record

_FIXED_TIMESTAMP = datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


_PERSISTENCE_HEALTH = settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    deadline=None,
)


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def _store(path: Path) -> BaselineStore:
    return BaselineStore(_config(path))


def _seed(storage: Path, record: BaselineRecord) -> Path:
    """Write ``record`` into ``storage`` so a fresh store can load it."""
    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=_FIXED_TIMESTAMP,
        written_by_extractor_version="loki-test-0.1",
    )
    file_path = storage / filename_for(record)
    file_path.write_bytes(payload)
    return file_path


# ---------------------------------------------------------------------
# Property 23: every loaded record re-validates
# ---------------------------------------------------------------------


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_23_loaded_records_pass_pydantic_revalidation(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 23: every record in the registry re-validates cleanly.

    Save then load via the bulk-load path. Each record from
    ``LoadResult.registry.baselines`` must survive a second
    ``BaselineRecord.model_validate(..., strict=False)`` call
    without raising. ``strict=False`` matches the production
    code path; the design's deferred decision §3 documents that
    YAML's datetime/UUID coercion requires the relaxed mode.
    """
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p23_load")
    _seed(storage, record)

    store = _store(storage)
    result = store.load()

    assert len(result.registry.baselines) == 1
    [loaded] = result.registry.baselines
    # Re-validation: round-trip the loaded record through
    # model_validate again. Any failure here would mean the load
    # contract returned a record that callers can't safely re-use.
    BaselineRecord.model_validate(loaded.model_dump(mode="json"), strict=False)


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_23_loaded_record_equals_input_under_model_dump(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 23 sub-invariant: re-validation produces an equal record.

    Stronger than just "re-validates without raising": the
    re-validated record must be byte-equal under ``model_dump``
    to the originally-loaded record. This catches any silent
    coercion (e.g. re-validation rounding a float, dropping a
    None field) that would otherwise hide.
    """
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p23_equal")
    _seed(storage, record)

    store = _store(storage)
    result = store.load()
    [loaded] = result.registry.baselines

    revalidated = BaselineRecord.model_validate(
        loaded.model_dump(mode="json"),
        strict=False,
    )
    assert revalidated.model_dump(mode="json") == loaded.model_dump(mode="json")


@_PERSISTENCE_HEALTH
@given(parameterized_baseline_record())
def test_property_23_loaded_record_is_baseline_record_instance(
    tmp_path_factory: object,
    record: BaselineRecord,
) -> None:
    """Property 23 sub-invariant: every loaded record is the right type.

    Pydantic's strict-mode validators run on the
    :class:`BaselineRecord` constructor; if the load path
    returned a dict-shaped pretend-record, callers would get
    runtime ``AttributeError``s when they tried to read fields.
    """
    factory: Any = tmp_path_factory
    storage = factory.mktemp("p23_isinstance")
    _seed(storage, record)

    store = _store(storage)
    [loaded] = store.load().registry.baselines
    assert isinstance(loaded, BaselineRecord)
