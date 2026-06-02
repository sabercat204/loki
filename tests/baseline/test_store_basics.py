"""Tests for ``BaselineStore`` constructor + storage_path handling (task 9)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from loki.baseline.errors import BaselineStorageUnwritableError
from loki.baseline.schema import SCHEMA_VERSION
from loki.baseline.store import BaselineStore, LoadResult
from loki.models import BaselineConfig
from tests.baseline.conftest import running_as_root


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def test_constructor_creates_missing_directory(tmp_path: Path) -> None:
    """R1.6: missing Storage_Directory is created with mode 0o755."""
    target = tmp_path / "nested" / "baselines"
    assert not target.exists()
    store = BaselineStore(_config(target))
    assert target.is_dir()
    # POSIX mode bits are POSIX-specific. Windows ignores ``os.chmod``'s
    # group/other bits and reports mode 0o777 by default, so the
    # 0o755-mode contract from R1.6 is only assertable on POSIX hosts.
    if sys.platform != "win32":
        # Mode bits beyond the permission mask vary by umask; check the
        # permission portion only.
        mode_perms = target.stat().st_mode & 0o777
        assert mode_perms == 0o755
    assert store.storage_path == target.resolve()


def test_constructor_reuses_existing_directory(tmp_path: Path) -> None:
    target = tmp_path / "baselines"
    target.mkdir(mode=0o755)
    # Drop a marker file so we can tell the constructor didn't wipe anything.
    (target / "marker.txt").write_text("hello")
    store = BaselineStore(_config(target))
    assert store.storage_path == target.resolve()
    assert (target / "marker.txt").read_text() == "hello"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits don't apply on Windows",
)
@pytest.mark.skipif(
    running_as_root(),
    reason="root bypasses permission checks; can't simulate unwritable directory",
)
def test_constructor_raises_when_directory_unwritable(tmp_path: Path) -> None:
    """R8.7: an existing-but-unwritable storage path raises a typed error."""
    target = tmp_path / "ro"
    target.mkdir(mode=0o500)  # read+execute only
    try:
        with pytest.raises(BaselineStorageUnwritableError) as excinfo:
            BaselineStore(_config(target))
        err = excinfo.value
        assert err.path == target.resolve()
        # ``errno`` is a POSIX errno; on Linux/macOS for "permission
        # denied" the typical value is 13 (EACCES) but we only assert
        # it's positive.
        assert err.errno > 0
    finally:
        # Restore mode so pytest can clean up.
        target.chmod(0o755)


def test_constructor_raises_when_parent_unwritable(tmp_path: Path) -> None:
    """Parent directory is read-only -> creating the child fails."""
    parent = tmp_path / "ro_parent"
    parent.mkdir(mode=0o500)
    try:
        target = parent / "child"
        if running_as_root():
            pytest.skip("root bypasses permission checks")
        with pytest.raises(BaselineStorageUnwritableError):
            BaselineStore(_config(target))
    finally:
        parent.chmod(0o755)


def test_storage_path_is_resolved_absolute(tmp_path: Path) -> None:
    """The store always exposes an absolute resolved path."""
    target = tmp_path / "baselines"
    store = BaselineStore(_config(target))
    assert store.storage_path.is_absolute()


def test_schema_version_property_matches_module_constant(tmp_path: Path) -> None:
    store = BaselineStore(_config(tmp_path))
    assert store.schema_version == SCHEMA_VERSION


def test_load_result_dataclass_is_frozen() -> None:
    from loki.baseline.quarantine import QuarantineSet
    from loki.models import BaselineRegistry

    result = LoadResult(
        registry=BaselineRegistry(),
        quarantine=QuarantineSet(),
        duration_ms=12.5,
    )
    assert result.duration_ms == 12.5
    with pytest.raises((AttributeError, Exception)):
        result.duration_ms = 99.0  # type: ignore[misc]


def test_constructor_does_not_load(tmp_path: Path) -> None:
    """The constructor does not trigger a Discovery_Scan; load() is explicit."""
    target = tmp_path / "baselines"
    # Drop an obvious-malformed yaml so a load would touch it.
    target.mkdir()
    (target / "bad.yaml").write_text(":::\n")
    # Constructor should succeed even with malformed files present.
    store = BaselineStore(_config(target))
    assert store.storage_path == target.resolve()
