"""Tests for ``BaselineStore.load_one`` and ``BaselineStore.delete`` (task 12).

These two entry points share their parse + validate pipeline with
:meth:`BaselineStore.load`, so the failure-mode coverage here mirrors
``test_store_load.py`` but asserts typed errors instead of
:class:`QuarantineSet` entries.
"""

from __future__ import annotations

import errno
import logging
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from loki.baseline.envelope import serialize
from loki.baseline.errors import (
    BaselineNotFoundError,
    BaselineSerializationError,
    BaselineStorageUnwritableError,
)
from loki.baseline.naming import filename_for
from loki.baseline.schema import SCHEMA_VERSION
from loki.baseline.store import MAX_FILE_SIZE, BaselineStore
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.fixtures import synthetic_baseline

_FIXED_TIMESTAMP = datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def _store(path: Path) -> BaselineStore:
    return BaselineStore(_config(path))


def _write_baseline(
    storage: Path,
    record: BaselineRecord,
    *,
    schema_version: str = SCHEMA_VERSION,
    filename: str | None = None,
) -> Path:
    """Write ``record`` to disk via the envelope serializer.

    Mirrors the helper in ``test_store_load.py`` so the two test
    files share an identical fixture-write contract.
    """
    payload = serialize(
        record,
        schema_version=schema_version,
        written_at=_FIXED_TIMESTAMP,
        written_by_extractor_version="loki-test-0.1",
    )
    path = storage / (filename or filename_for(record))
    path.write_bytes(payload)
    return path


# ---------------------------------------------------------------------
# load_one: happy path
# ---------------------------------------------------------------------


def test_load_one_returns_validated_record(tmp_path: Path) -> None:
    """Happy path: a valid Baseline_File round-trips through ``load_one``."""
    record = synthetic_baseline.build()
    file_path = _write_baseline(tmp_path, record)

    store = _store(tmp_path)
    loaded = store.load_one(file_path)

    assert isinstance(loaded, BaselineRecord)
    assert loaded.baseline_id == record.baseline_id
    assert loaded.vendor == record.vendor


def test_load_one_does_not_pollute_registry(tmp_path: Path) -> None:
    """``load_one`` must never touch the store's snapshot map (R7.4 anchor).

    The GUI's "Open Baseline Registry…" action loads a single file
    *without* persisting it; if ``load_one`` populated the snapshot
    map the next ``save`` would treat the foreign file as owned by
    this store and skip the existence check (R5.3).
    """
    record = synthetic_baseline.build()
    file_path = _write_baseline(tmp_path, record)

    store = _store(tmp_path)
    store.load_one(file_path)

    assert store._snapshots == {}


def test_load_one_accepts_path_outside_storage_directory(
    tmp_path: Path,
) -> None:
    """``load_one`` works against any path the user picks, not just storage_path."""
    record = synthetic_baseline.build()
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    file_path = _write_baseline(foreign, record)

    storage = tmp_path / "storage"
    store = _store(storage)
    loaded = store.load_one(file_path)

    assert loaded.baseline_id == record.baseline_id


# ---------------------------------------------------------------------
# load_one: typed-error coverage for each failure mode
# ---------------------------------------------------------------------


def test_load_one_raises_on_missing_file(tmp_path: Path) -> None:
    """A path that doesn't exist surfaces as a typed error, not OSError."""
    store = _store(tmp_path)
    with pytest.raises(BaselineSerializationError) as excinfo:
        store.load_one(tmp_path / "nope.yaml")
    assert "could not stat" in excinfo.value.message


def test_load_one_raises_on_malformed_yaml(tmp_path: Path) -> None:
    """R8.2 → typed error rather than quarantine."""
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"key: value\n: malformed: : :")
    store = _store(tmp_path)
    with pytest.raises(BaselineSerializationError) as excinfo:
        store.load_one(bad)
    assert "malformed yaml" in excinfo.value.message


def test_load_one_raises_on_missing_envelope_key(tmp_path: Path) -> None:
    """R8.3 → typed error rather than quarantine."""
    payload = (
        b"schema_version: '1.0.0'\n"
        b"written_at: '2026-01-01T00:00:00+00:00'\n"
        b"written_by_extractor_version: 'loki'\n"
    )
    bad = tmp_path / "no_baseline.yaml"
    bad.write_bytes(payload)
    store = _store(tmp_path)
    with pytest.raises(BaselineSerializationError) as excinfo:
        store.load_one(bad)
    assert "missing required envelope key: baseline" in excinfo.value.message


def test_load_one_raises_on_unsupported_schema_version(tmp_path: Path) -> None:
    """R4.4 → typed error rather than quarantine."""
    record = synthetic_baseline.build()
    file_path = _write_baseline(tmp_path, record, schema_version="0.0.1")
    store = _store(tmp_path)
    with pytest.raises(BaselineSerializationError) as excinfo:
        store.load_one(file_path)
    assert "unsupported schema_version: 0.0.1" in excinfo.value.message


def test_load_one_raises_on_validation_failure(tmp_path: Path) -> None:
    """R8.4 → typed error rather than quarantine."""
    record = synthetic_baseline.build()
    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=_FIXED_TIMESTAMP,
        written_by_extractor_version="loki-test-0.1",
    )
    parsed = yaml.safe_load(payload)
    parsed["baseline"]["source_image_hash"] = "NOT_HEX"
    bad = tmp_path / filename_for(record)
    bad.write_bytes(yaml.safe_dump(parsed, sort_keys=True).encode("utf-8"))

    store = _store(tmp_path)
    with pytest.raises(BaselineSerializationError) as excinfo:
        store.load_one(bad)
    assert "validation failed" in excinfo.value.message
    assert "source_image_hash" in excinfo.value.message


def test_load_one_raises_on_invalid_baseline_id(tmp_path: Path) -> None:
    """R8.5 → typed error rather than quarantine."""
    record = synthetic_baseline.build()
    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=_FIXED_TIMESTAMP,
        written_by_extractor_version="loki-test-0.1",
    )
    parsed = yaml.safe_load(payload)
    parsed["baseline"]["baseline_id"] = "not-a-uuid"
    bad = tmp_path / filename_for(record)
    bad.write_bytes(yaml.safe_dump(parsed, sort_keys=True).encode("utf-8"))

    store = _store(tmp_path)
    with pytest.raises(BaselineSerializationError) as excinfo:
        store.load_one(bad)
    assert "invalid baseline_id" in excinfo.value.message


def test_load_one_raises_on_oversized_file(tmp_path: Path) -> None:
    """R9.7 → typed error rather than quarantine."""
    big = tmp_path / "big.yaml"
    big.write_bytes(b"x: 1\n" + (b"\x00" * (MAX_FILE_SIZE)))
    store = _store(tmp_path)
    with pytest.raises(BaselineSerializationError) as excinfo:
        store.load_one(big)
    assert "exceeds 16 MiB" in excinfo.value.message


# ---------------------------------------------------------------------
# delete: happy path
# ---------------------------------------------------------------------


def test_delete_removes_file_and_clears_snapshot(tmp_path: Path) -> None:
    record = synthetic_baseline.build()
    store = _store(tmp_path)
    store.save(record)
    file_path = tmp_path / filename_for(record)
    assert file_path.exists()
    assert record.baseline_id in store._snapshots

    removed = store.delete(record.baseline_id)
    assert removed == file_path.resolve()
    assert not file_path.exists()
    assert record.baseline_id not in store._snapshots


def test_delete_returns_absolute_resolved_path(tmp_path: Path) -> None:
    """``delete`` returns the same path the snapshot recorded."""
    record = synthetic_baseline.build()
    store = _store(tmp_path)
    store.save(record)

    removed = store.delete(record.baseline_id)
    assert removed.is_absolute()


def test_delete_emits_info_log(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``delete`` logs an INFO record naming the baseline_id and path."""
    record = synthetic_baseline.build()
    store = _store(tmp_path)
    store.save(record)

    caplog.set_level(logging.INFO, logger="loki.baseline.store")
    store.delete(record.baseline_id)

    delete_messages = [
        rec.getMessage()
        for rec in caplog.records
        if rec.levelno == logging.INFO and rec.getMessage().startswith("baseline delete")
    ]
    assert delete_messages
    msg = delete_messages[0]
    assert str(record.baseline_id) in msg


def test_delete_works_after_load(tmp_path: Path) -> None:
    """``delete`` works on baselines loaded from disk, not just saved ones."""
    record = synthetic_baseline.build()
    _write_baseline(tmp_path, record)
    store = _store(tmp_path)
    store.load()
    assert record.baseline_id in store._snapshots

    removed = store.delete(record.baseline_id)
    assert not removed.exists()


# ---------------------------------------------------------------------
# delete: error paths
# ---------------------------------------------------------------------


def test_delete_raises_for_unknown_baseline_id(tmp_path: Path) -> None:
    """The handoff is explicit: missing baseline_id → typed error."""
    store = _store(tmp_path)
    unknown = uuid.uuid4()
    with pytest.raises(BaselineNotFoundError) as excinfo:
        store.delete(unknown)
    assert excinfo.value.baseline_id == unknown
    assert excinfo.value.path is None


def test_delete_raises_when_file_already_gone(tmp_path: Path) -> None:
    """If the file vanished between load and delete, raise NotFoundError.

    The handoff calls this out explicitly: "missing file at the
    expected path also raises (since the user asked for that
    specific id)."
    """
    record = synthetic_baseline.build()
    store = _store(tmp_path)
    store.save(record)
    # Some external process removes the file between the snapshot
    # and the delete call.
    (tmp_path / filename_for(record)).unlink()

    with pytest.raises(BaselineNotFoundError) as excinfo:
        store.delete(record.baseline_id)
    assert excinfo.value.baseline_id == record.baseline_id
    assert excinfo.value.path is not None
    # The stale snapshot is dropped so a follow-up save wouldn't
    # silently overwrite the (now-missing) old file.
    assert record.baseline_id not in store._snapshots


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits don't apply on Windows",
)
@pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root bypasses permission checks",
)
def test_delete_raises_storage_unwritable_on_permission_error(
    tmp_path: Path,
) -> None:
    """A permission-denied unlink surfaces as ``BaselineStorageUnwritableError``."""
    record = synthetic_baseline.build()
    store = _store(tmp_path)
    store.save(record)
    # Lock the storage dir so the unlink fails with EACCES.
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(BaselineStorageUnwritableError) as excinfo:
            store.delete(record.baseline_id)
        assert excinfo.value.errno in {errno.EACCES, errno.EPERM}
    finally:
        tmp_path.chmod(0o755)


# ---------------------------------------------------------------------
# Round-trip: delete + save re-creates the file
# ---------------------------------------------------------------------


def test_delete_then_save_recreates_file(tmp_path: Path) -> None:
    """The handoff: ``delete`` followed by ``save`` of the same record works."""
    record = synthetic_baseline.build()
    store = _store(tmp_path)
    store.save(record)
    file_path = tmp_path / filename_for(record)
    assert file_path.exists()

    store.delete(record.baseline_id)
    assert not file_path.exists()
    assert record.baseline_id not in store._snapshots

    # Re-save via the canonical-filename path; force=False is the
    # default and should succeed because the snapshot is gone and
    # the file is gone.
    re_dest = store.save(record)
    assert re_dest == file_path.resolve()
    assert file_path.exists()
    # And the snapshot map is back in sync with the new file.
    assert record.baseline_id in store._snapshots


def test_load_one_followed_by_save_persists_to_storage(tmp_path: Path) -> None:
    """``load_one`` + ``save`` is the import-from-elsewhere path (R6.6).

    The GUI / CLI workflow: pick a Baseline_File from anywhere on
    disk, load it without polluting the registry, then save it
    into the Storage_Directory. The save must succeed without
    triggering ``BaselineAlreadyExistsError`` because the foreign
    file isn't tracked by this store.
    """
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    record = synthetic_baseline.build()
    foreign_file = _write_baseline(foreign, record)

    storage = tmp_path / "storage"
    store = _store(storage)
    loaded = store.load_one(foreign_file)
    dest = store.save(loaded)

    assert dest.parent == storage.resolve()
    assert dest.name == filename_for(record)
    # The foreign file is left untouched.
    assert foreign_file.exists()
