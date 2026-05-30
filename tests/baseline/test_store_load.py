"""Tests for ``BaselineStore.load`` (task 10)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from loki.baseline.envelope import serialize
from loki.baseline.naming import filename_for
from loki.baseline.schema import SCHEMA_VERSION
from loki.baseline.store import MAX_FILE_SIZE, BaselineStore, LoadResult
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.fixtures import synthetic_baseline

_FIXED_TIMESTAMP = datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def _write_baseline(
    storage: Path,
    record: BaselineRecord,
    *,
    schema_version: str = SCHEMA_VERSION,
    filename: str | None = None,
) -> Path:
    """Write ``record`` to disk via the envelope serializer."""
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
# Empty / no-files
# ---------------------------------------------------------------------


def test_load_empty_directory_returns_empty_result(tmp_path: Path) -> None:
    """R2.6: empty Storage_Directory returns an empty registry + quarantine."""
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert isinstance(result, LoadResult)
    assert result.registry.baselines == []
    assert len(result.quarantine) == 0
    assert result.duration_ms >= 0


def test_load_skips_non_yaml_files(tmp_path: Path) -> None:
    """R1.4: files not ending in ``.yaml`` are ignored entirely."""
    (tmp_path / "README.md").write_text("# notes\n")
    (tmp_path / "extra.json").write_text("{}\n")
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert result.registry.baselines == []
    assert len(result.quarantine) == 0


def test_load_skips_subdirectories(tmp_path: Path) -> None:
    """R1.4: only depth-1 ``*.yaml`` files participate in Discovery_Scan."""
    sub = tmp_path / "nested"
    sub.mkdir()
    record = synthetic_baseline.build()
    _write_baseline(sub, record)  # nested baselines aren't seen
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert result.registry.baselines == []


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


def test_load_one_good_file(tmp_path: Path) -> None:
    record = synthetic_baseline.build()
    _write_baseline(tmp_path, record)
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert len(result.registry.baselines) == 1
    loaded = result.registry.baselines[0]
    assert loaded.baseline_id == record.baseline_id
    assert loaded.vendor == record.vendor


def test_load_multiple_baselines_in_lexicographic_order(tmp_path: Path) -> None:
    """Files are loaded in lexicographic Baseline_Filename order (R2.7 anchor)."""
    a = synthetic_baseline.build(vendor="ACME", model="X1", firmware_version="1.0")
    b = synthetic_baseline.build(vendor="ZIPCO", model="Y1", firmware_version="2.0")
    _write_baseline(tmp_path, a)
    _write_baseline(tmp_path, b)
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert [r.vendor for r in result.registry.baselines] == ["ACME", "ZIPCO"]


def test_load_records_snapshot_for_each_baseline(tmp_path: Path) -> None:
    """The store remembers ``(mtime_ns, size)`` for every loaded record."""
    record = synthetic_baseline.build()
    _write_baseline(tmp_path, record)
    store = BaselineStore(_config(tmp_path))
    store.load()
    assert record.baseline_id in store._snapshots


# ---------------------------------------------------------------------
# Quarantine paths
# ---------------------------------------------------------------------


def test_load_quarantines_malformed_yaml(tmp_path: Path) -> None:
    """R8.2: yaml.YAMLError -> quarantine with ``malformed yaml`` reason."""
    (tmp_path / "bad.yaml").write_bytes(b"key: value\n: malformed: : :")
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert entry.reason.startswith("malformed yaml")
    assert entry.path.name == "bad.yaml"


def test_load_quarantines_missing_envelope_key(tmp_path: Path) -> None:
    """R8.3: the four envelope keys are required."""
    payload = b"schema_version: '1.0.0'\nwritten_at: '2026-01-01T00:00:00+00:00'\nwritten_by_extractor_version: 'loki'\n"
    (tmp_path / "no_baseline.yaml").write_bytes(payload)
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert "missing required envelope key: baseline" in entry.reason


def test_load_quarantines_unsupported_schema_version(tmp_path: Path) -> None:
    """R4.4: schema_version mismatch -> quarantine, no auto-upgrade."""
    record = synthetic_baseline.build()
    _write_baseline(tmp_path, record, schema_version="0.0.1")
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert "unsupported schema_version: 0.0.1" in entry.reason
    assert result.registry.baselines == []


def test_load_quarantines_validation_failures(tmp_path: Path) -> None:
    """R8.4: payload validation failures quarantine with the field path."""
    record = synthetic_baseline.build()
    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=_FIXED_TIMESTAMP,
        written_by_extractor_version="loki-test-0.1",
    )
    # Corrupt the payload's source_image_hash to something invalid
    # (must be 64 lowercase hex chars).
    parsed = yaml.safe_load(payload)
    parsed["baseline"]["source_image_hash"] = "NOT_HEX"
    bad = yaml.safe_dump(parsed, sort_keys=True).encode("utf-8")
    (tmp_path / filename_for(record)).write_bytes(bad)

    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert entry.reason.startswith("validation failed")
    assert "source_image_hash" in entry.reason


def test_load_quarantines_invalid_baseline_id(tmp_path: Path) -> None:
    """R8.5: a non-UUID ``baseline_id`` surfaces a specific reason."""
    record = synthetic_baseline.build()
    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=_FIXED_TIMESTAMP,
        written_by_extractor_version="loki-test-0.1",
    )
    parsed = yaml.safe_load(payload)
    parsed["baseline"]["baseline_id"] = "not-a-uuid"
    bad = yaml.safe_dump(parsed, sort_keys=True).encode("utf-8")
    (tmp_path / filename_for(record)).write_bytes(bad)

    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert entry.reason == "invalid baseline_id"


def test_load_quarantines_oversized_file(tmp_path: Path) -> None:
    """R9.7: files > 16 MiB are quarantined without being read into memory."""
    big = tmp_path / "big.yaml"
    # 17 MiB of zeros — pad with newlines so yaml.safe_load doesn't choke
    # on a binary header (the file gets quarantined before the loader
    # touches it anyway).
    big.write_bytes(b"x: 1\n" + (b"\x00" * (MAX_FILE_SIZE)))
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert entry.reason == "file exceeds 16 MiB size limit"
    assert entry.raw is None  # never read into memory


# ---------------------------------------------------------------------
# Duplicate baseline_id (R2.7)
# ---------------------------------------------------------------------


def test_load_duplicate_baseline_id_keeps_first_lexicographic(
    tmp_path: Path,
) -> None:
    """R2.7: duplicate baseline_id -> first lexicographic file wins."""
    record = synthetic_baseline.build()
    _write_baseline(tmp_path, record, filename="aaa.yaml")
    _write_baseline(tmp_path, record, filename="zzz.yaml")
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert len(result.registry.baselines) == 1
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert entry.path.name == "zzz.yaml"
    assert entry.reason == "duplicate baseline_id"


# ---------------------------------------------------------------------
# Mixed scenario
# ---------------------------------------------------------------------


def test_load_mixed_good_and_bad_files(tmp_path: Path) -> None:
    """One good file + one malformed file = one loaded, one quarantined."""
    record = synthetic_baseline.build()
    _write_baseline(tmp_path, record)
    (tmp_path / "broken.yaml").write_bytes(b"key: : malformed")
    store = BaselineStore(_config(tmp_path))
    result = store.load()
    assert len(result.registry.baselines) == 1
    assert len(result.quarantine) == 1


def test_load_logs_start_and_finish_records(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """R10.1, R10.2: load emits start + finish INFO records."""
    import logging

    caplog.set_level(logging.INFO, logger="loki.baseline.store")
    record = synthetic_baseline.build()
    _write_baseline(tmp_path, record)
    BaselineStore(_config(tmp_path)).load()

    messages = [rec.getMessage() for rec in caplog.records]
    assert any(m.startswith("baseline load starting") for m in messages)
    assert any(m.startswith("baseline load finished") for m in messages)


def test_load_logs_quarantine_warning(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """R10.3: quarantined files get a WARNING record naming the path + reason."""
    import logging

    caplog.set_level(logging.WARNING, logger="loki.baseline.store")
    (tmp_path / "bad.yaml").write_bytes(b"::: not yaml :::")
    BaselineStore(_config(tmp_path)).load()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("baseline quarantine" in r.getMessage() for r in warnings)


def test_load_resets_snapshots(tmp_path: Path) -> None:
    """A second load() clears stale snapshots from a previous load()."""
    record = synthetic_baseline.build()
    _write_baseline(tmp_path, record)
    store = BaselineStore(_config(tmp_path))
    store.load()
    assert len(store._snapshots) == 1
    # Remove the file and re-load; the snapshot for the deleted record
    # must not survive.
    (tmp_path / filename_for(record)).unlink()
    store.load()
    assert store._snapshots == {}
