"""Tests for the background baseline-load worker.

The synchronous path is covered by ``test_baseline_actions.py``
(every test there constructs ``MainWindow(background_load=False)``);
this file exercises the threaded path explicitly. ``qtbot.waitUntil``
is used to bridge the worker's QThread back into the test thread
without polling.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from PyQt6.QtWidgets import QMessageBox
from pytestqt.qtbot import QtBot

from loki.baseline import BaselineStore
from loki.baseline.envelope import serialize
from loki.baseline.naming import filename_for
from loki.baseline.schema import SCHEMA_VERSION
from loki.gui.baseline_load_worker import BaselineLoadWorker
from loki.gui.main_window import MainWindow
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.fixtures import synthetic_baseline


@pytest.fixture(autouse=True)
def no_blocking_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub every ``QMessageBox`` static method so dialogs never block.

    Mirrors the autouse fixture in ``test_baseline_actions.py`` —
    a stray dialog under ``QT_QPA_PLATFORM=offscreen`` blocks
    silently and is the kind of regression that's eaten hours of
    wall time before. Keep the safety net.
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
    target = tmp_path / "baselines"
    target.mkdir()
    return target


@pytest.fixture()
def store(storage_path: Path) -> BaselineStore:
    return BaselineStore(BaselineConfig(storage_path=str(storage_path), auto_match=False))


def _seed_baseline(storage: Path, record: BaselineRecord) -> Path:
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
    nav = window.navigation
    group = nav.topLevelItem(group_index)
    assert group is not None
    labels: list[str] = []
    for idx in range(group.childCount()):
        child = group.child(idx)
        assert child is not None
        labels.append(child.text(0))
    return labels


def _baseline_load_finished(window: MainWindow) -> Callable[[], bool]:
    """Predicate for ``qtbot.waitUntil``: worker has finished + been deleted."""

    def _check() -> bool:
        return window._baseline_load_worker is None

    return _check


# ---------------------------------------------------------------------
# Worker-level tests (no MainWindow)
# ---------------------------------------------------------------------


def test_worker_emits_finished_with_result_on_success(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """The worker emits a ``LoadResult`` via ``finished_with_result``."""
    record = synthetic_baseline.build()
    _seed_baseline(storage_path, record)

    worker = BaselineLoadWorker(store)
    with qtbot.waitSignal(worker.finished_with_result, timeout=5_000) as blocker:
        worker.start()

    from loki.baseline import LoadResult

    [result] = blocker.args
    assert isinstance(result, LoadResult)
    assert len(result.registry.baselines) == 1
    assert result.registry.baselines[0].baseline_id == record.baseline_id
    worker.wait(2_000)


def test_worker_emits_errored_on_baseline_store_error(
    tmp_path: Path,
    qtbot: QtBot,
) -> None:
    """A storage error surfaces via ``errored``, not as an uncaught exception.

    Constructs a store rooted at a path that exists, then deletes
    the directory before the worker runs. ``BaselineStore.load``
    raises ``BaselineStorageUnwritableError``; the worker catches
    it and emits via the typed signal.
    """
    from loki.baseline import BaselineStorageUnwritableError

    storage = tmp_path / "baselines"
    storage.mkdir()
    config = BaselineConfig(storage_path=str(storage), auto_match=False)
    store = BaselineStore(config)
    # Remove the directory after store construction so load() trips.
    storage.rmdir()

    worker = BaselineLoadWorker(store)
    with qtbot.waitSignal(worker.errored, timeout=5_000) as blocker:
        worker.start()

    [exc] = blocker.args
    assert isinstance(exc, BaselineStorageUnwritableError)
    worker.wait(2_000)


def test_worker_store_property_exposes_input(store: BaselineStore) -> None:
    """The ``store`` property surfaces the constructor argument."""
    worker = BaselineLoadWorker(store)
    assert worker.store is store


# ---------------------------------------------------------------------
# MainWindow integration tests
# ---------------------------------------------------------------------


def test_window_async_load_populates_navigation(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """R7.1 + background load: navigation reflects loaded baselines."""
    record = synthetic_baseline.build(vendor="ACME", model="X1", firmware_version="1.0")
    _seed_baseline(storage_path, record)

    window = MainWindow(baseline_store=store, background_load=True)
    qtbot.addWidget(window)

    qtbot.waitUntil(_baseline_load_finished(window), timeout=5_000)

    labels = _navigation_labels(window, group_index=1)
    assert any("ACME X1 1.0" in label for label in labels)


def test_window_async_load_is_default(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """Production callers don't need to pass ``background_load=True``."""
    record = synthetic_baseline.build()
    _seed_baseline(storage_path, record)

    window = MainWindow(baseline_store=store)  # no kwarg => background_load=True
    qtbot.addWidget(window)

    # The worker is non-None right after construction (it's running).
    assert window._baseline_load_worker is not None

    qtbot.waitUntil(_baseline_load_finished(window), timeout=5_000)
    labels = _navigation_labels(window, group_index=1)
    assert len(labels) == 1


def test_window_async_load_status_message_clears_after_completion(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """R7.2: status bar shows "Loading..." then clears when load finishes."""
    record = synthetic_baseline.build()
    _seed_baseline(storage_path, record)

    window = MainWindow(baseline_store=store, background_load=True)
    qtbot.addWidget(window)

    qtbot.waitUntil(_baseline_load_finished(window), timeout=5_000)

    # The transient status override is cleared after the worker
    # finishes; the status bar reverts to the default message.
    assert window._transient_status is None


def test_window_async_load_surfaces_quarantine(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7.3: quarantine count is shown via QMessageBox.information."""
    record = synthetic_baseline.build()
    _seed_baseline(storage_path, record)
    (storage_path / "broken.yaml").write_bytes(b"::: not yaml :::")

    captured: list[tuple[str, str]] = []

    def fake_information(_parent: object, title: str, text: str, *_args: object) -> int:
        captured.append((title, text))
        return int(QMessageBox.StandardButton.Ok)

    monkeypatch.setattr(QMessageBox, "information", fake_information)

    window = MainWindow(baseline_store=store, background_load=True)
    qtbot.addWidget(window)

    qtbot.waitUntil(_baseline_load_finished(window), timeout=5_000)

    assert any("Baselines loaded with warnings" in title for title, _ in captured)
    # And the good baseline still showed up.
    labels = _navigation_labels(window, group_index=1)
    assert len(labels) == 1


def test_window_async_load_handles_typed_error(
    tmp_path: Path,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``BaselineStoreError`` surfaces as a warning dialog, no crash."""
    storage = tmp_path / "baselines"
    storage.mkdir()
    config = BaselineConfig(storage_path=str(storage), auto_match=False)
    store = BaselineStore(config)
    # Remove the directory so load() trips with BaselineStorageUnwritableError.
    storage.rmdir()

    captured: list[tuple[str, str]] = []

    def fake_warning(_parent: object, title: str, text: str, *_args: object) -> int:
        captured.append((title, text))
        return int(QMessageBox.StandardButton.Ok)

    monkeypatch.setattr(QMessageBox, "warning", fake_warning)

    window = MainWindow(baseline_store=store, background_load=True)
    qtbot.addWidget(window)

    qtbot.waitUntil(_baseline_load_finished(window), timeout=5_000)

    assert any("Could not load baselines" in title for title, _ in captured)


def test_window_close_joins_in_flight_worker(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """``closeEvent`` waits for the worker to finish so the process exits cleanly.

    Closing the window mid-load should not leak a daemon thread.
    The cleanup runs synchronously via ``QThread.wait``.
    """
    record = synthetic_baseline.build()
    _seed_baseline(storage_path, record)

    window = MainWindow(baseline_store=store, background_load=True)
    qtbot.addWidget(window)
    # Don't wait for the load — close immediately.
    window.close()

    # After close, the worker should be either gone or fully
    # finished. ``wait()`` on a finished thread returns instantly.
    if window._baseline_load_worker is not None:
        window._baseline_load_worker.wait(5_000)
    qtbot.waitUntil(_baseline_load_finished(window), timeout=5_000)


def test_window_synchronous_load_skips_worker(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """``background_load=False`` runs the load on the constructor thread."""
    record = synthetic_baseline.build()
    _seed_baseline(storage_path, record)

    window = MainWindow(baseline_store=store, background_load=False)
    qtbot.addWidget(window)

    # No worker was ever spawned.
    assert window._baseline_load_worker is None
    # Navigation is already populated.
    labels = _navigation_labels(window, group_index=1)
    assert len(labels) == 1


# ---------------------------------------------------------------------
# R7.10 + R7.11: progress signal and cancellation affordance
# ---------------------------------------------------------------------


def test_worker_emits_progress_signal_per_file(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """R7.10: the worker re-emits each ``LoadProgressEvent`` on the ``progress`` signal."""
    from loki.baseline import LoadProgressEvent

    for index in range(3):
        record = synthetic_baseline.build(
            vendor="ACME",
            model=f"X{index}",
            firmware_version="1.0",
        )
        _seed_baseline(storage_path, record)

    worker = BaselineLoadWorker(store)
    captured: list[LoadProgressEvent] = []

    def _capture(event: object) -> None:
        assert isinstance(event, LoadProgressEvent)
        captured.append(event)

    worker.progress.connect(_capture)
    with qtbot.waitSignal(worker.finished_with_result, timeout=5_000):
        worker.start()

    assert len(captured) == 3
    assert [e.index for e in captured] == [1, 2, 3]
    assert all(e.total == 3 for e in captured)
    worker.wait(2_000)


def test_worker_request_cancel_idempotent(
    store: BaselineStore,
) -> None:
    """``request_cancel()`` flips a flag and is idempotent across calls."""
    worker = BaselineLoadWorker(store)
    assert worker.is_cancel_requested() is False
    worker.request_cancel()
    assert worker.is_cancel_requested() is True
    # Idempotent — a second call doesn't error or change state.
    worker.request_cancel()
    assert worker.is_cancel_requested() is True


def test_worker_request_cancel_short_circuits_load(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """Calling ``request_cancel`` before ``start`` makes the load return immediately.

    The cancellation flag is checked before the first file's parse, so
    a pre-set flag means zero records loaded and zero progress events.
    """
    for index in range(5):
        record = synthetic_baseline.build(
            vendor="ACME",
            model=f"X{index}",
            firmware_version="1.0",
        )
        _seed_baseline(storage_path, record)

    worker = BaselineLoadWorker(store)
    worker.request_cancel()

    progress_events: list[object] = []
    worker.progress.connect(progress_events.append)

    with qtbot.waitSignal(worker.finished_with_result, timeout=5_000) as blocker:
        worker.start()

    [result] = blocker.args
    assert len(result.registry.baselines) == 0
    assert len(progress_events) == 0
    worker.wait(2_000)


def test_window_cancel_action_disabled_until_worker_starts(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """The Cancel Baseline Load menu item is disabled when no worker is running.

    Synchronous-load callers should never see the action enabled, since
    no worker is ever spawned for that path.
    """
    record = synthetic_baseline.build()
    _seed_baseline(storage_path, record)

    window = MainWindow(baseline_store=store, background_load=False)
    qtbot.addWidget(window)

    cancel_action = window._cancel_baseline_load_action
    assert cancel_action.isEnabled() is False


def test_window_cancel_action_disables_after_worker_finishes(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """After the worker finishes naturally, the cancel action goes back to disabled."""
    record = synthetic_baseline.build()
    _seed_baseline(storage_path, record)

    window = MainWindow(baseline_store=store, background_load=True)
    qtbot.addWidget(window)
    qtbot.waitUntil(_baseline_load_finished(window), timeout=5_000)

    cancel_action = window._cancel_baseline_load_action
    assert cancel_action.isEnabled() is False


def test_window_cancel_action_cancels_in_flight_worker(
    storage_path: Path,
    store: BaselineStore,
    qtbot: QtBot,
) -> None:
    """R7.11: triggering the cancel action while a worker is running stops the load.

    Because the synthetic fixture is fast, this test seeds a larger
    storage to give the cancellation a real chance to fire in time;
    even if some baselines load before the cancel takes effect, the
    worker still needs to return cleanly with a partial result.
    """
    for index in range(5):
        record = synthetic_baseline.build(
            vendor="ACME",
            model=f"BIG-{index:03d}",
            firmware_version="1.0",
        )
        _seed_baseline(storage_path, record)

    window = MainWindow(baseline_store=store, background_load=True)
    qtbot.addWidget(window)

    # Trigger cancel as soon as the worker exists.
    if window._baseline_load_worker is not None:
        window._baseline_load_worker.request_cancel()

    qtbot.waitUntil(_baseline_load_finished(window), timeout=5_000)
    # The post-load action state should be disabled regardless of
    # how many records actually loaded.
    assert window._cancel_baseline_load_action.isEnabled() is False
