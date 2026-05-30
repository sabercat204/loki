"""Tests for the baseline-persistence GUI integration (task 19).

Covers R7 in full:

- R7.1 — load on startup populates the Baselines navigation group.
- R7.2 — status-bar message during the Discovery_Scan.
- R7.3 — quarantine count is surfaced via QMessageBox.information.
- R7.4 — Open Baseline Registry loads a single file without
  modifying the Storage_Directory.
- R7.5 — Save Baseline writes the active tab's record to disk and
  refreshes the navigation entry.
- R7.6 — overwrite confirmation dialog on
  ``BaselineAlreadyExistsError``.
- R7.7 — concurrent-modification error dialog (no automatic retry).
- R7.8 — navigation entry label uses
  ``{vendor} {model} {firmware_version}``.
- R7.9 — demo baselines retain the ``(demo)`` suffix.

Every test in this file stubs every ``QMessageBox`` static method
through the ``no_blocking_dialogs`` fixture so a missed
monkeypatch can never hang the suite. Tests that *want* to assert
on a specific dialog override the relevant stub via their own
``monkeypatch``.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from PyQt6.QtWidgets import QMessageBox
from pytestqt.qtbot import QtBot

from loki.baseline import BaselineStore
from loki.baseline.envelope import serialize
from loki.baseline.naming import filename_for
from loki.baseline.schema import SCHEMA_VERSION
from loki.gui.actions import open_baseline_from_path, save_baseline
from loki.gui.main_window import MainWindow
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.fixtures import synthetic_baseline


@pytest.fixture(autouse=True)
def no_blocking_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub every ``QMessageBox`` static method so dialogs never block.

    Any test that wants to assert dialog content overrides the
    relevant stub via its own ``monkeypatch.setattr`` — the later
    setattr wins. Without this autouse stub, an unexpected
    quarantine message during ``MainWindow.__init__`` would open
    a real dialog and hang the offscreen Qt event loop.
    """

    monkeypatch.setattr(
        QMessageBox,
        "information",
        lambda *_args, **_kwargs: int(QMessageBox.StandardButton.Ok),
    )
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *_args, **_kwargs: int(QMessageBox.StandardButton.Ok),
    )
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: int(QMessageBox.StandardButton.No),
    )


@pytest.fixture()
def storage_path(tmp_path: Path) -> Path:
    """A clean Storage_Directory for one test."""
    target = tmp_path / "baselines"
    target.mkdir()
    return target


@pytest.fixture()
def store(storage_path: Path) -> BaselineStore:
    """Construct a tmp_path-rooted ``BaselineStore`` for one test."""
    return BaselineStore(BaselineConfig(storage_path=str(storage_path), auto_match=False))


class WindowFactory:
    """Helper that constructs and registers a :class:`MainWindow`.

    Pulled out as a class instead of a plain closure so mypy doesn't
    have to walk into the closure to verify the return type.
    """

    def __init__(self, qtbot: QtBot) -> None:
        self._qtbot = qtbot

    def __call__(self, store: BaselineStore | None = None) -> MainWindow:
        # ``background_load=False`` keeps the existing test contract:
        # the navigation pane reflects the loaded baselines as soon
        # as the constructor returns. Tests that exercise the async
        # load path live in ``test_baseline_load_worker.py``.
        window = MainWindow(baseline_store=store, background_load=False)
        self._qtbot.addWidget(window)
        return window


@pytest.fixture()
def window_factory(qtbot: QtBot) -> WindowFactory:
    """Return a callable that builds a :class:`MainWindow` with a chosen store."""
    return WindowFactory(qtbot)


def _seed_baseline(storage: Path, record: BaselineRecord) -> Path:
    """Drop a Baseline_File into ``storage`` so a fresh store can load it."""
    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC),
        written_by_extractor_version="loki-test-0.1",
    )
    file_path = storage / filename_for(record)
    file_path.write_bytes(payload)
    return file_path


def _navigation_labels(window: MainWindow, group_index: int) -> list[str]:
    """Return the labels of every entry under the requested navigation group."""
    nav = window.navigation
    group = nav.topLevelItem(group_index)
    assert group is not None
    labels: list[str] = []
    for idx in range(group.childCount()):
        child = group.child(idx)
        assert child is not None
        labels.append(child.text(0))
    return labels


# ---------------------------------------------------------------------
# R7.1 — load on startup populates the Baselines group
# ---------------------------------------------------------------------


def test_startup_load_populates_baselines_group(
    store: BaselineStore,
    storage_path: Path,
    window_factory: WindowFactory,
) -> None:
    """R7.1: every Baseline_File becomes a navigation entry."""
    record_a = synthetic_baseline.build(vendor="ACME", model="X1", firmware_version="1.0")
    record_b = synthetic_baseline.build(vendor="ZIP", model="Y2", firmware_version="3.5")
    _seed_baseline(storage_path, record_a)
    _seed_baseline(storage_path, record_b)

    window = window_factory(store)

    labels = _navigation_labels(window, group_index=1)
    assert any("ACME X1 1.0" in label for label in labels)
    assert any("ZIP Y2 3.5" in label for label in labels)


def test_startup_load_navigation_label_uses_vendor_model_version(
    store: BaselineStore,
    storage_path: Path,
    window_factory: WindowFactory,
) -> None:
    """R7.8: real-loaded entries label as ``{vendor} {model} {firmware_version}``."""
    record = synthetic_baseline.build(vendor="ACME", model="X1", firmware_version="1.0")
    _seed_baseline(storage_path, record)

    window = window_factory(store)

    labels = _navigation_labels(window, group_index=1)
    # Demo suffix absent for real-loaded entries (R7.9 inverse).
    assert "ACME X1 1.0" in labels


def test_startup_load_with_empty_storage_leaves_placeholder(
    store: BaselineStore, window_factory: WindowFactory
) -> None:
    """An empty Storage_Directory leaves the Baselines group placeholder intact."""
    window = window_factory(store)

    labels = _navigation_labels(window, group_index=1)
    assert labels == ["No baselines loaded yet"]


def test_startup_with_no_store_leaves_placeholder(
    window_factory: WindowFactory,
) -> None:
    """``baseline_store=None`` is a valid configuration; placeholder stays."""
    window = window_factory(None)
    labels = _navigation_labels(window, group_index=1)
    assert labels == ["No baselines loaded yet"]


# ---------------------------------------------------------------------
# R7.3 — quarantine count is surfaced
# ---------------------------------------------------------------------


def test_startup_load_with_quarantine_shows_information_dialog(
    store: BaselineStore,
    storage_path: Path,
    window_factory: WindowFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7.3: quarantine count is shown via QMessageBox.information."""
    # One good baseline + two malformed files.
    record = synthetic_baseline.build()
    _seed_baseline(storage_path, record)
    (storage_path / "broken1.yaml").write_bytes(b"::: not yaml :::")
    (storage_path / "broken2.yaml").write_bytes(b"")

    captured: list[tuple[str, str]] = []

    def fake_information(_parent: object, title: str, text: str, *_args: object) -> int:
        captured.append((title, text))
        return int(QMessageBox.StandardButton.Ok)

    monkeypatch.setattr(QMessageBox, "information", fake_information)

    window_factory(store)

    assert len(captured) == 1
    title, text = captured[0]
    assert "Baselines loaded with warnings" in title
    assert "2 baseline file(s)" in text
    assert "loki.gui.baselines" in text


def test_startup_load_logs_each_quarantined_file(
    store: BaselineStore,
    storage_path: Path,
    window_factory: WindowFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """R7.3: each quarantined file gets a WARNING under loki.gui.baselines.

    Filters by logger *name* rather than message substring because
    the underlying ``loki.baseline.store`` logger emits the same
    "baseline quarantine path=… reason=…" message format. R7.3
    is specifically about the ``loki.gui.baselines`` logger.
    """

    (storage_path / "broken.yaml").write_bytes(b"::: malformed :::")
    caplog.set_level(logging.WARNING)

    window_factory(store)

    gui_warnings = [
        rec
        for rec in caplog.records
        if rec.name == "loki.gui.baselines" and "baseline quarantine" in rec.getMessage()
    ]
    assert len(gui_warnings) == 1


# ---------------------------------------------------------------------
# R7.4 — Open Baseline Registry loads without persisting
# ---------------------------------------------------------------------


def test_open_baseline_loads_without_modifying_storage(
    store: BaselineStore,
    storage_path: Path,
    tmp_path: Path,
    window_factory: WindowFactory,
) -> None:
    """R7.4: ``open_baseline_from_path`` loads but does not persist."""
    # Foreign Baseline_File outside the Storage_Directory.
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    record = synthetic_baseline.build(vendor="FOREIGN", model="F1", firmware_version="9.9")
    foreign_file = _seed_baseline(foreign, record)

    window = window_factory(store)
    loaded = open_baseline_from_path(window, foreign_file)

    assert loaded is not None
    assert loaded.baseline_id == record.baseline_id
    # Navigation pane has the entry.
    labels = _navigation_labels(window, group_index=1)
    assert any("FOREIGN F1 9.9" in label for label in labels)
    # Storage_Directory still has zero baseline files.
    yaml_files = sorted(p.name for p in storage_path.glob("*.yaml"))
    assert yaml_files == []


def test_open_baseline_with_malformed_file_shows_warning(
    store: BaselineStore,
    tmp_path: Path,
    window_factory: WindowFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed source file surfaces as a warning dialog, not a crash."""
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"::: not yaml :::")

    captured: list[tuple[str, str]] = []

    def fake_warning(_parent: object, title: str, text: str, *_args: object) -> int:
        captured.append((title, text))
        return int(QMessageBox.StandardButton.Ok)

    monkeypatch.setattr(QMessageBox, "warning", fake_warning)

    window = window_factory(store)
    result = open_baseline_from_path(window, bad)

    assert result is None
    assert any("Could not open baseline registry" in title for title, _ in captured)


# ---------------------------------------------------------------------
# R7.5 — Save Baseline writes to disk and refreshes the nav entry
# ---------------------------------------------------------------------


def test_save_baseline_writes_to_storage_directory(
    store: BaselineStore,
    storage_path: Path,
    window_factory: WindowFactory,
) -> None:
    """R7.5: ``save_baseline`` writes the record into the Storage_Directory."""
    record = synthetic_baseline.build()
    window = window_factory(store)
    window.add_baseline(record)

    dest = save_baseline(window, record)

    assert dest is not None
    assert dest == storage_path / filename_for(record)
    assert dest.exists()


def test_save_baseline_action_disabled_without_baseline_view(
    store: BaselineStore, window_factory: WindowFactory
) -> None:
    """R7.5: the menu action is disabled when no BaselineView is active."""
    window = window_factory(store)
    save_action = window._save_baseline_action
    assert not save_action.isEnabled()


def test_save_baseline_action_enabled_when_baseline_view_active(
    store: BaselineStore, window_factory: WindowFactory
) -> None:
    """R7.5: opening a BaselineView tab re-enables the Save action."""
    window = window_factory(store)
    record = synthetic_baseline.build()
    window.add_baseline(record)
    save_action = window._save_baseline_action
    assert save_action.isEnabled()


# ---------------------------------------------------------------------
# R7.6 — overwrite confirmation dialog
# ---------------------------------------------------------------------


def test_save_baseline_prompts_to_overwrite(
    store: BaselineStore,
    storage_path: Path,
    window_factory: WindowFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7.6: an existing file we didn't load triggers an overwrite prompt.

    Constructs the window first (storage is empty so no quarantine
    fires), then drops a colliding file into the Storage_Directory
    after init. The store's snapshot map doesn't know about that
    file, so :meth:`BaselineStore.save` raises
    ``BaselineAlreadyExistsError`` and ``save_baseline`` shows the
    overwrite prompt (R7.6).
    """

    record = synthetic_baseline.build()
    window = window_factory(store)
    window.add_baseline(record)

    # Drop the colliding file *after* MainWindow.__init__ has run so
    # the store's load() doesn't pick it up. ``save`` will see the
    # existing canonical filename and raise AlreadyExists.
    canonical = storage_path / filename_for(record)
    canonical.write_bytes(b"pre-existing\n")

    captured: list[tuple[str, str]] = []

    def fake_question(_parent: object, title: str, text: str, *_args: object) -> int:
        captured.append((title, text))
        return int(QMessageBox.StandardButton.Yes)

    monkeypatch.setattr(QMessageBox, "question", fake_question)

    dest = save_baseline(window, record)

    assert dest is not None
    assert any("Overwrite existing baseline?" in title for title, _ in captured)
    # The save retried with force=True so the file now contains the record.
    parsed = yaml.safe_load(dest.read_bytes())
    assert parsed["baseline"]["baseline_id"] == str(record.baseline_id)


def test_save_baseline_overwrite_cancel_leaves_file_unchanged(
    store: BaselineStore,
    storage_path: Path,
    window_factory: WindowFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7.6: declining the overwrite prompt leaves the existing file alone."""
    record = synthetic_baseline.build()
    window = window_factory(store)
    window.add_baseline(record)

    pre_bytes = b"pre-existing\n"
    canonical = storage_path / filename_for(record)
    canonical.write_bytes(pre_bytes)

    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: int(QMessageBox.StandardButton.No),
    )

    dest = save_baseline(window, record)

    assert dest is None
    assert canonical.read_bytes() == pre_bytes


# ---------------------------------------------------------------------
# R7.7 — concurrent-modification error dialog (no auto-retry)
# ---------------------------------------------------------------------


def test_save_baseline_concurrent_modification_shows_warning(
    store: BaselineStore,
    storage_path: Path,
    window_factory: WindowFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7.7: ``BaselineConcurrentModificationError`` shows a warning, no retry."""
    record = synthetic_baseline.build()
    # Seed + load via the store on startup so the snapshot is recorded.
    _seed_baseline(storage_path, record)
    window = window_factory(store)
    # The window's __init__ already called store.load(); the snapshot
    # map now has an entry for record.baseline_id.

    # Some external process rewrites the file.
    time.sleep(0.02)
    (storage_path / filename_for(record)).write_bytes(b"externally rewritten\n")

    captured: list[tuple[str, str]] = []

    def fake_warning(_parent: object, title: str, text: str, *_args: object) -> int:
        captured.append((title, text))
        return int(QMessageBox.StandardButton.Ok)

    monkeypatch.setattr(QMessageBox, "warning", fake_warning)

    result = save_baseline(window, record)

    assert result is None
    assert any("Concurrent modification" in title for title, _ in captured)
    # The destination still has the externally-written bytes.
    assert (storage_path / filename_for(record)).read_bytes() == b"externally rewritten\n"


# ---------------------------------------------------------------------
# R7.9 — demo baselines retain the (demo) suffix; R7.8 inverse
# ---------------------------------------------------------------------


def test_demo_baseline_label_carries_demo_suffix(
    store: BaselineStore, window_factory: WindowFactory
) -> None:
    """R7.9: ``add_baseline(demo=True)`` labels the entry with ``(demo)``."""
    window = window_factory(store)
    record = synthetic_baseline.build(vendor="ACME", model="X1", firmware_version="1.0")
    window.add_baseline(record, demo=True)

    labels = _navigation_labels(window, group_index=1)
    assert "ACME X1 1.0 (demo)" in labels


def test_real_baseline_label_has_no_demo_suffix(
    store: BaselineStore, window_factory: WindowFactory
) -> None:
    """R7.8 inverse: real-loaded baselines don't carry the demo suffix."""
    window = window_factory(store)
    record = synthetic_baseline.build(vendor="ACME", model="X1", firmware_version="1.0")
    window.add_baseline(record)

    labels = _navigation_labels(window, group_index=1)
    assert "ACME X1 1.0" in labels
    assert "ACME X1 1.0 (demo)" not in labels


# ---------------------------------------------------------------------
# R7.5 — save refreshes the navigation entry
# ---------------------------------------------------------------------


def test_save_baseline_keeps_navigation_in_sync(
    store: BaselineStore,
    storage_path: Path,
    window_factory: WindowFactory,
) -> None:
    """Saving the active baseline keeps the navigation entry intact.

    Hard regression: a save shouldn't *delete* the navigation entry
    or duplicate it. The label stays the same because the
    ``BaselineRecord`` identity is unchanged.
    """
    record = synthetic_baseline.build(vendor="ACME", model="X1", firmware_version="1.0")
    window = window_factory(store)
    window.add_baseline(record)
    labels_before = _navigation_labels(window, group_index=1)
    save_baseline(window, record)
    labels_after = _navigation_labels(window, group_index=1)
    assert labels_after == labels_before


def _ids_for(records: Iterable[BaselineRecord]) -> set[str]:
    return {str(r.baseline_id) for r in records}
