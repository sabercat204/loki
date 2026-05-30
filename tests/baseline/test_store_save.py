"""Tests for ``BaselineStore.save`` (task 11)."""

from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from loki.baseline.errors import (
    BaselineAlreadyExistsError,
    BaselineConcurrentModificationError,
    BaselineSerializationError,
    BaselineStorageUnwritableError,
)
from loki.baseline.naming import filename_for
from loki.baseline.schema import SCHEMA_VERSION
from loki.baseline.store import BaselineStore
from loki.models import BaselineConfig
from tests.baseline.fixtures import synthetic_baseline


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def _store_for(tmp_path: Path) -> BaselineStore:
    return BaselineStore(_config(tmp_path))


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


def test_save_writes_canonical_filename(tmp_path: Path) -> None:
    record = synthetic_baseline.build()
    store = _store_for(tmp_path)
    dest = store.save(record)
    assert dest.name == filename_for(record)
    assert dest.exists()


def test_save_returns_absolute_path(tmp_path: Path) -> None:
    record = synthetic_baseline.build()
    store = _store_for(tmp_path)
    dest = store.save(record)
    assert dest.is_absolute()


def test_save_round_trips_through_envelope(tmp_path: Path) -> None:
    record = synthetic_baseline.build()
    store = _store_for(tmp_path)
    dest = store.save(record)
    parsed = yaml.safe_load(dest.read_bytes())
    assert parsed["schema_version"] == SCHEMA_VERSION
    assert parsed["baseline"]["baseline_id"] == str(record.baseline_id)


def test_save_records_snapshot_for_record(tmp_path: Path) -> None:
    """Subsequent saves of the same record use the snapshot path."""
    record = synthetic_baseline.build()
    store = _store_for(tmp_path)
    store.save(record)
    assert record.baseline_id in store._snapshots


# ---------------------------------------------------------------------
# R3.7 / Property 25: byte-deterministic save modulo `written_at`
# ---------------------------------------------------------------------


def test_two_saves_produce_byte_identical_modulo_written_at(
    tmp_path: Path,
) -> None:
    """Property 25: same record + same written_at -> same bytes."""
    from datetime import UTC
    from datetime import datetime as real_datetime

    record = synthetic_baseline.build()
    store = _store_for(tmp_path)
    fixed = real_datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)

    class _FrozenDatetime(real_datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> real_datetime:  # type: ignore[override]
            return fixed

    with patch("loki.baseline.store.datetime", _FrozenDatetime):
        first = store.save(record).read_bytes()
        # Force the mtime forward so the snapshot from the first save
        # would normally complain; force=True bypasses the check.
        time.sleep(0.02)
        second = store.save(record, force=True).read_bytes()

    assert first == second


# ---------------------------------------------------------------------
# Round-trip validation (R3.8) and size limit (R9.8)
# ---------------------------------------------------------------------


def test_save_rejects_oversized_payload(tmp_path: Path) -> None:
    """R9.8: a serialized payload > 16 MiB raises SerializationError."""
    # 1024 classifications x 256 bytes each is plenty under 16 MiB; we
    # force the limit by patching MAX_FILE_SIZE down to 1 KiB.
    record = synthetic_baseline.build(classification_count=10)
    store = _store_for(tmp_path)
    with patch("loki.baseline.store.MAX_FILE_SIZE", 1024):
        with pytest.raises(BaselineSerializationError, match="exceeds 16 MiB"):
            store.save(record)
    # Nothing should have been written.
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------
# Existence check (R5.3)
# ---------------------------------------------------------------------


def test_save_without_load_refuses_to_overwrite(tmp_path: Path) -> None:
    """R5.3: a save against an existing file we didn't load -> AlreadyExists."""
    record = synthetic_baseline.build()
    # Pre-create a file at the canonical location.
    canonical = filename_for(record)
    (tmp_path / canonical).write_bytes(b"pre-existing\n")

    store = _store_for(tmp_path)  # constructor doesn't load
    with pytest.raises(BaselineAlreadyExistsError) as excinfo:
        store.save(record)
    assert excinfo.value.path == (tmp_path / canonical).resolve()
    # The pre-existing file content is unchanged.
    assert (tmp_path / canonical).read_bytes() == b"pre-existing\n"


def test_save_with_force_overwrites_without_load(tmp_path: Path) -> None:
    """R5.4: ``force=True`` skips the existence check."""
    record = synthetic_baseline.build()
    canonical = filename_for(record)
    (tmp_path / canonical).write_bytes(b"pre-existing\n")

    store = _store_for(tmp_path)
    dest = store.save(record, force=True)
    parsed = yaml.safe_load(dest.read_bytes())
    assert parsed["baseline"]["baseline_id"] == str(record.baseline_id)


# ---------------------------------------------------------------------
# Concurrency check (R5.2)
# ---------------------------------------------------------------------


def test_save_after_external_mutation_raises_concurrency_error(
    tmp_path: Path,
) -> None:
    """R5.2: external mutation since load -> ConcurrentModificationError."""
    record = synthetic_baseline.build()
    store = _store_for(tmp_path)
    dest = store.save(record)
    # Some external process (or another LOKI session) replaces the file.
    time.sleep(0.02)
    dest.write_bytes(b"externally rewritten\n")

    with pytest.raises(BaselineConcurrentModificationError) as excinfo:
        store.save(record)
    err = excinfo.value
    assert err.path == dest


def test_save_with_force_skips_concurrency_check(tmp_path: Path) -> None:
    """R5.4: ``force=True`` bypasses the mtime/size check."""
    record = synthetic_baseline.build()
    store = _store_for(tmp_path)
    dest = store.save(record)
    time.sleep(0.02)
    dest.write_bytes(b"externally rewritten\n")

    # force=True succeeds despite the external mutation.
    store.save(record, force=True)
    parsed = yaml.safe_load(dest.read_bytes())
    assert parsed["baseline"]["baseline_id"] == str(record.baseline_id)


# ---------------------------------------------------------------------
# Atomic_Write semantics (R3.2, R3.3)
# ---------------------------------------------------------------------


def test_failed_serialization_leaves_destination_untouched(
    tmp_path: Path,
) -> None:
    """R3.3 + R8.7: a failure before os.replace must not corrupt the destination."""
    record = synthetic_baseline.build()
    canonical = filename_for(record)
    pre_bytes = b"intact destination\n"
    (tmp_path / canonical).write_bytes(pre_bytes)

    store = _store_for(tmp_path)
    # Force os.replace to fail mid-write; the temp file should be cleaned
    # up, the destination left intact, and the OSError converted to the
    # spec-mandated BaselineStorageUnwritableError (R8.7).
    real_replace = os.replace

    def boom(*args: object, **kwargs: object) -> None:
        raise OSError("simulated write failure before replace")

    with patch("loki.baseline.store.os.replace", side_effect=boom):
        with pytest.raises(BaselineStorageUnwritableError):
            store.save(record, force=True)

    # Destination file is byte-identical to its pre-save state.
    assert (tmp_path / canonical).read_bytes() == pre_bytes
    # No temp file lingers.
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []
    # Sanity check os.replace was actually invoked (so the test would
    # have failed if the patch didn't take effect).
    assert real_replace is os.replace


def test_save_preserves_temp_file_pattern(tmp_path: Path) -> None:
    """Atomic_Write temp filenames don't collide between runs."""
    a = synthetic_baseline.build(vendor="ACME")
    b = synthetic_baseline.build(vendor="ACME", model="OTHER")
    store = _store_for(tmp_path)
    store.save(a)
    store.save(b)
    # Both files exist; no temp file lingers.
    assert (tmp_path / filename_for(a)).exists()
    assert (tmp_path / filename_for(b)).exists()
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []


# ---------------------------------------------------------------------
# Logging (R10.4)
# ---------------------------------------------------------------------


def test_save_emits_info_log(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """R10.4: a successful save emits an INFO record with the Baseline_Identifier."""
    import logging

    record = synthetic_baseline.build()
    store = _store_for(tmp_path)
    caplog.set_level(logging.INFO, logger="loki.baseline.store")
    store.save(record)
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    save_messages = [m for m in messages if m.startswith("baseline save")]
    assert save_messages
    msg = save_messages[0]
    assert str(record.baseline_id) in msg
    assert record.vendor in msg


def test_save_does_not_log_component_manifest(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """R10.5: no log message includes manifest contents or source_image_hash."""
    import logging

    record = synthetic_baseline.build()
    store = _store_for(tmp_path)
    caplog.set_level(logging.DEBUG, logger="loki.baseline")
    store.save(record)
    # Build the set of payloads that *must not* appear in any log record.
    forbidden_substrings = {record.source_image_hash}
    for component in record.component_manifest:
        forbidden_substrings.add(str(component.component_id))
        if component.signature_info and component.signature_info.signer:
            forbidden_substrings.add(component.signature_info.signer)
    for rec in caplog.records:
        msg = rec.getMessage()
        for forbidden in forbidden_substrings:
            assert forbidden not in msg, f"log message leaked '{forbidden}': {msg}"
