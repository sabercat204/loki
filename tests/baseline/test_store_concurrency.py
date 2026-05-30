"""Store-level concurrency tests (task 13).

The module-level snapshot helpers are exercised by ``test_concurrency.py``;
this file walks the full :class:`BaselineStore` save flow against two
concurrent store instances backed by the same Storage_Directory. The
scenarios mirror the design's "Save flow" + R5 contract: each store
loads the same baseline, both hold a snapshot, the first writes, the
second's write must trip the mtime/size check and raise
:class:`BaselineConcurrentModificationError`.

Property 30 ("concurrent modification is detected, not silently
overwritten") is the underlying invariant. Hypothesis-style PBT for
this property lives in task 14; this file is the targeted-scenario
sibling.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

from loki.baseline.envelope import serialize
from loki.baseline.errors import BaselineConcurrentModificationError
from loki.baseline.naming import filename_for
from loki.baseline.schema import SCHEMA_VERSION
from loki.baseline.store import BaselineStore
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.fixtures import synthetic_baseline


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def _store(path: Path) -> BaselineStore:
    return BaselineStore(_config(path))


def _seed(storage: Path, record: BaselineRecord) -> Path:
    """Write ``record`` into ``storage`` so two stores can both load it."""
    from datetime import UTC, datetime

    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC),
        written_by_extractor_version="loki-test-0.1",
    )
    file_path = storage / filename_for(record)
    file_path.write_bytes(payload)
    return file_path


# ---------------------------------------------------------------------
# Two-store race: second save trips the concurrency check
# ---------------------------------------------------------------------


def test_two_stores_second_save_raises_concurrency_error(tmp_path: Path) -> None:
    """R5.2 + Property 30: lost-race save raises with recorded vs observed."""
    record = synthetic_baseline.build()
    file_path = _seed(tmp_path, record)

    alpha = _store(tmp_path)
    beta = _store(tmp_path)
    alpha.load()
    beta.load()
    # Both stores agree on the file's identity at load time.
    assert alpha._snapshots[record.baseline_id].mtime_ns == (
        beta._snapshots[record.baseline_id].mtime_ns
    )

    # Pause to ensure the next save bumps mtime_ns to a distinct value.
    time.sleep(0.02)
    alpha.save(record)

    with pytest.raises(BaselineConcurrentModificationError) as excinfo:
        beta.save(record)
    err = excinfo.value
    assert err.path == file_path.resolve()
    # ``recorded`` matches beta's stale snapshot, ``observed`` matches
    # the file's post-alpha-save state.
    assert err.recorded != err.observed


def test_two_stores_force_skips_concurrency_check(tmp_path: Path) -> None:
    """R5.4: ``force=True`` lets the second save win the race."""
    record = synthetic_baseline.build()
    _seed(tmp_path, record)

    alpha = _store(tmp_path)
    beta = _store(tmp_path)
    alpha.load()
    beta.load()

    time.sleep(0.02)
    alpha.save(record)
    # beta's save with force=True succeeds despite the stale snapshot.
    dest = beta.save(record, force=True)
    parsed = yaml.safe_load(dest.read_bytes())
    assert parsed["baseline"]["baseline_id"] == str(record.baseline_id)


def test_two_stores_first_save_succeeds_for_both_orderings(tmp_path: Path) -> None:
    """The race-loser is whoever saves second; both stores can be the winner."""
    record = synthetic_baseline.build()
    _seed(tmp_path, record)

    # Order 1: alpha wins
    alpha = _store(tmp_path)
    beta = _store(tmp_path)
    alpha.load()
    beta.load()
    time.sleep(0.02)
    alpha.save(record)
    with pytest.raises(BaselineConcurrentModificationError):
        beta.save(record)

    # Order 2: beta wins. Reset by reloading both.
    alpha2 = _store(tmp_path)
    beta2 = _store(tmp_path)
    alpha2.load()
    beta2.load()
    time.sleep(0.02)
    beta2.save(record)
    with pytest.raises(BaselineConcurrentModificationError):
        alpha2.save(record)


# ---------------------------------------------------------------------
# Property 30 anchor: file is byte-unchanged after a failed save
# ---------------------------------------------------------------------


def test_concurrency_failure_leaves_destination_byte_identical(
    tmp_path: Path,
) -> None:
    """Property 30: a failed concurrent save must not modify the destination.

    The first store wrote new bytes; the second store's failed save
    must not overwrite or corrupt those bytes.
    """
    record = synthetic_baseline.build()
    _seed(tmp_path, record)

    alpha = _store(tmp_path)
    beta = _store(tmp_path)
    alpha.load()
    beta.load()
    time.sleep(0.02)
    dest = alpha.save(record)
    expected = dest.read_bytes()

    with pytest.raises(BaselineConcurrentModificationError):
        beta.save(record)

    assert dest.read_bytes() == expected


def test_concurrency_failure_cleans_up_temp_file(tmp_path: Path) -> None:
    """Property 27 anchor: failed save leaves no ``*.tmp`` artifact."""
    record = synthetic_baseline.build()
    _seed(tmp_path, record)

    alpha = _store(tmp_path)
    beta = _store(tmp_path)
    alpha.load()
    beta.load()
    time.sleep(0.02)
    alpha.save(record)
    with pytest.raises(BaselineConcurrentModificationError):
        beta.save(record)

    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []


def test_concurrency_failure_does_not_update_loser_snapshot(
    tmp_path: Path,
) -> None:
    """A losing save must leave the loser's snapshot stale, not advance it.

    Otherwise a follow-up save with ``force=False`` would silently
    succeed against the *new* bytes — the exact race-handoff bug
    R5 is meant to catch.
    """
    record = synthetic_baseline.build()
    _seed(tmp_path, record)

    alpha = _store(tmp_path)
    beta = _store(tmp_path)
    alpha.load()
    beta.load()
    snap_before = beta._snapshots[record.baseline_id]
    time.sleep(0.02)
    alpha.save(record)
    with pytest.raises(BaselineConcurrentModificationError):
        beta.save(record)

    snap_after = beta._snapshots[record.baseline_id]
    assert snap_after == snap_before
