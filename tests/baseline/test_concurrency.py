"""Tests for the file-snapshot helpers (task 6)."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from loki.baseline.concurrency import FileSnapshot, check_unchanged, snapshot
from loki.baseline.errors import BaselineConcurrentModificationError


def _write(path: Path, data: bytes = b"hello") -> None:
    path.write_bytes(data)


def test_snapshot_captures_mtime_and_size(tmp_path: Path) -> None:
    target = tmp_path / "x.yaml"
    _write(target, b"hello world")
    snap = snapshot(target)
    assert isinstance(snap, FileSnapshot)
    assert snap.path == target
    assert snap.size == 11
    assert snap.mtime_ns == os.stat(target).st_mtime_ns


def test_snapshot_raises_on_missing_file(tmp_path: Path) -> None:
    target = tmp_path / "missing.yaml"
    with pytest.raises(FileNotFoundError):
        snapshot(target)


def test_check_unchanged_passes_when_file_unchanged(tmp_path: Path) -> None:
    target = tmp_path / "x.yaml"
    _write(target)
    snap = snapshot(target)
    # No mutation; check should not raise.
    check_unchanged(snap)


def test_check_unchanged_raises_when_size_changed(tmp_path: Path) -> None:
    target = tmp_path / "x.yaml"
    _write(target, b"hello")
    snap = snapshot(target)
    _write(target, b"hello extended")  # different size
    with pytest.raises(BaselineConcurrentModificationError) as excinfo:
        check_unchanged(snap)
    err = excinfo.value
    assert err.path == target
    assert err.recorded == (snap.mtime_ns, snap.size)
    assert err.observed[1] != snap.size


def test_check_unchanged_raises_when_mtime_changed(tmp_path: Path) -> None:
    target = tmp_path / "x.yaml"
    _write(target, b"hello")
    snap = snapshot(target)
    # Force the mtime forward by 1 second, keep size the same.
    new_mtime = time.time() + 60
    os.utime(target, (new_mtime, new_mtime))
    with pytest.raises(BaselineConcurrentModificationError):
        check_unchanged(snap)


def test_check_unchanged_treats_missing_file_as_modification(tmp_path: Path) -> None:
    """Deleting the file between load and save is a concurrent modification."""
    target = tmp_path / "x.yaml"
    _write(target)
    snap = snapshot(target)
    target.unlink()
    with pytest.raises(BaselineConcurrentModificationError) as excinfo:
        check_unchanged(snap)
    err = excinfo.value
    assert err.path == target
    assert err.observed == (-1, -1)


def test_file_snapshot_is_frozen() -> None:
    snap = FileSnapshot(path=Path("/x"), mtime_ns=0, size=0)
    with pytest.raises((AttributeError, Exception)):
        snap.size = 999  # type: ignore[misc]
