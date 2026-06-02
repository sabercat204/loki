"""Edge-case typed-error tests (task 13).

Collects the failure modes that don't fit cleanly into the
per-feature test files: malformed UTF-8 input, empty / whitespace
files, and save-time failures into an unwritable Storage_Directory.

The spec citations:

- R8.2 (malformed YAML quarantines with the right reason).
- R8.3 (missing envelope keys quarantine).
- R8.7 (unwritable storage path raises ``BaselineStorageUnwritableError``
  from both the constructor *and* the save entry point).
- R10.3 (every quarantined file gets a WARNING log record).

The constructor-time R8.7 path is already covered in
``test_store_basics.py``; this file targets the save-time path.
"""

from __future__ import annotations

import errno
import logging
import sys
from pathlib import Path

import pytest

from loki.baseline.errors import BaselineStorageUnwritableError
from loki.baseline.store import BaselineStore
from loki.models import BaselineConfig
from tests.baseline.conftest import running_as_root
from tests.baseline.fixtures import synthetic_baseline


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def _store(path: Path) -> BaselineStore:
    return BaselineStore(_config(path))


# ---------------------------------------------------------------------
# Empty / whitespace / non-UTF-8 input on the load side
# ---------------------------------------------------------------------


def test_load_quarantines_empty_file(tmp_path: Path) -> None:
    """R8.2 boundary: a zero-byte file isn't valid YAML for a Baseline_File.

    ``yaml.safe_load(b"")`` returns ``None``, which the envelope
    deserializer then rejects as "top-level YAML must be a mapping".
    Either way it lands in the Quarantine_Set rather than blowing
    up the load.
    """
    (tmp_path / "empty.yaml").write_bytes(b"")
    store = _store(tmp_path)
    result = store.load()
    assert result.registry.baselines == []
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert entry.path.name == "empty.yaml"
    # The reason is human-readable and identifies the failure mode
    # without leaking content. Either of the two paths through the
    # envelope deserializer is acceptable.
    assert any(
        marker in entry.reason for marker in ("must be a mapping", "missing required envelope key")
    )


def test_load_quarantines_whitespace_only_file(tmp_path: Path) -> None:
    """R8.2 boundary: whitespace-only YAML parses as ``None``.

    Pure spaces and newlines parse as ``None`` in PyYAML, which the
    envelope deserializer rejects with "top-level YAML must be a
    mapping". (Mixing in a tab would make PyYAML raise a YAMLError
    instead — both paths land in the Quarantine_Set, but the
    spaces-only case is the cleanest "only whitespace" reading.)
    """
    (tmp_path / "blank.yaml").write_bytes(b"   \n   \n\n")
    store = _store(tmp_path)
    result = store.load()
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert "must be a mapping" in entry.reason


def test_load_quarantines_non_utf8_bytes(tmp_path: Path) -> None:
    """Malformed UTF-8 surfaces through the YAML parser as a YAMLError.

    ``yaml.safe_load`` decodes bytes as UTF-8 and raises
    ``yaml.reader.ReaderError`` (a ``yaml.YAMLError``) on invalid
    UTF-8 sequences. The envelope deserializer catches this and
    converts to ``EnvelopeMalformedError``, which the bulk-load
    path turns into a quarantine entry with the
    ``"malformed yaml"`` prefix.
    """
    # 0xFF 0xFE 0xFD is not valid UTF-8 in the YAML stream context.
    (tmp_path / "bad_utf8.yaml").write_bytes(b"baseline:\n  \xff\xfe\xfd\n")
    store = _store(tmp_path)
    result = store.load()
    assert len(result.quarantine) == 1
    [entry] = list(result.quarantine)
    assert entry.reason.startswith("malformed yaml")


def test_load_quarantines_only_whitespace_does_not_leak_into_registry(
    tmp_path: Path,
) -> None:
    """A whitespace-only file plus a valid file: only the valid file loads."""
    (tmp_path / "blank.yaml").write_bytes(b"   \n")
    record = synthetic_baseline.build()
    from datetime import UTC, datetime

    from loki.baseline.envelope import serialize as envelope_serialize
    from loki.baseline.naming import filename_for
    from loki.baseline.schema import SCHEMA_VERSION

    payload = envelope_serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC),
        written_by_extractor_version="loki-test-0.1",
    )
    (tmp_path / filename_for(record)).write_bytes(payload)

    store = _store(tmp_path)
    result = store.load()
    assert len(result.registry.baselines) == 1
    assert result.registry.baselines[0].baseline_id == record.baseline_id
    assert len(result.quarantine) == 1


def test_load_logs_warning_for_each_edge_case(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """R10.3: every quarantined file emits exactly one WARNING."""
    caplog.set_level(logging.WARNING, logger="loki.baseline.store")
    (tmp_path / "empty.yaml").write_bytes(b"")
    (tmp_path / "blank.yaml").write_bytes(b"   \n")
    (tmp_path / "bad_utf8.yaml").write_bytes(b"baseline:\n  \xff\xfe\xfd\n")
    _store(tmp_path).load()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    quarantine_warnings = [r for r in warnings if "baseline quarantine" in r.getMessage()]
    assert len(quarantine_warnings) == 3


# ---------------------------------------------------------------------
# Save-time R8.7: unwritable Storage_Directory
# ---------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits don't apply on Windows",
)
@pytest.mark.skipif(
    running_as_root(),
    reason="root bypasses permission checks; can't simulate read-only directory",
)
def test_save_into_readonly_directory_raises_storage_unwritable(
    tmp_path: Path,
) -> None:
    """R8.7: save into a read-only Storage_Directory raises typed error.

    The save can't create its temp file when the directory is mode
    ``0o500``. The implementation converts the underlying
    ``PermissionError`` into ``BaselineStorageUnwritableError`` so
    the GUI / CLI can render the right diagnostic.
    """
    record = synthetic_baseline.build()
    store = _store(tmp_path)
    # Lock the directory after construction so the constructor's
    # writability probe doesn't pre-empt the test.
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(BaselineStorageUnwritableError) as excinfo:
            store.save(record)
        assert excinfo.value.path == tmp_path.resolve()
        assert excinfo.value.errno in {errno.EACCES, errno.EPERM}
    finally:
        tmp_path.chmod(0o755)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits don't apply on Windows",
)
@pytest.mark.skipif(
    running_as_root(),
    reason="root bypasses permission checks",
)
def test_save_into_readonly_directory_leaves_no_temp_file(tmp_path: Path) -> None:
    """R3.3 + R8.7: a failed save into an unwritable dir leaves no debris."""
    record = synthetic_baseline.build()
    store = _store(tmp_path)
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(BaselineStorageUnwritableError):
            store.save(record)
        # The chmod blocks listing too on some systems; restore briefly
        # for the cleanup check.
    finally:
        tmp_path.chmod(0o755)
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []
