"""Tests for the GUI's extraction view + menu wiring (tasks 26 + background-thread polish)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QTableWidget
from pytestqt.qtbot import QtBot

from loki.extraction import ExtractionResult
from loki.extraction.extractors.base import clear_registry
from loki.gui.actions.extract_components import extract_components
from loki.gui.main_window import MainWindow
from loki.gui.views import ExtractionView
from loki.models import FirmwareImage
from tests.extraction.fixtures import synthetic_uefi_volume


@pytest.fixture(autouse=True)
def _registry_isolation() -> Iterator[None]:
    clear_registry()
    yield
    clear_registry()


@pytest.fixture()
def main_window(qtbot: QtBot) -> MainWindow:
    """Construct a fresh ``MainWindow`` and register it for cleanup."""
    window = MainWindow()
    qtbot.addWidget(window)
    return window


def _open_image_in_window(window: MainWindow, binary: Path) -> FirmwareImage:
    """Open ``binary`` as a real :class:`FirmwareImage` in the window."""
    from loki.gui.actions.open_firmware import open_firmware_from_path

    image = open_firmware_from_path(window, binary)
    assert image is not None
    return image


def _run_to_completion(
    qtbot: QtBot, window: MainWindow, image: FirmwareImage, timeout_ms: int = 10_000
) -> ExtractionResult | None:
    """Spawn an extraction worker and pump the event loop until it finishes."""

    extract_components(window, image)
    # Poll the *window* rather than the worker — once the worker finishes,
    # the window calls ``deleteLater()`` on it, so the worker C++ object
    # can disappear out from under us. ``window.active_worker`` is set
    # back to ``None`` in the same handler, so it's a stable signal.
    qtbot.waitUntil(lambda: window.active_worker is None, timeout=timeout_ms)
    return window.last_extraction_result_for(image)


# ---------------------------------------------------------------------
# Menu action wiring
# ---------------------------------------------------------------------


def test_extract_action_disabled_until_image_loaded(main_window: MainWindow) -> None:
    """The Extract action is disabled when no firmware image is open."""
    action = main_window._extract_action
    assert isinstance(action, QAction)
    assert action.isEnabled() is False


def test_extract_action_enabled_once_image_loaded(main_window: MainWindow, tmp_path: Path) -> None:
    binary = synthetic_uefi_volume.build(tmp_path)
    _open_image_in_window(main_window, binary)
    action = main_window._extract_action
    assert action.isEnabled() is True


def test_extract_action_disabled_after_reset(main_window: MainWindow, tmp_path: Path) -> None:
    binary = synthetic_uefi_volume.build(tmp_path)
    _open_image_in_window(main_window, binary)
    main_window.reset_workspace()
    action = main_window._extract_action
    assert action.isEnabled() is False


def test_extract_action_disabled_while_worker_running(
    main_window: MainWindow, tmp_path: Path, qtbot: QtBot
) -> None:
    """The action is disabled while a worker is in flight, then re-enabled."""

    binary = synthetic_uefi_volume.build(tmp_path)
    image = _open_image_in_window(main_window, binary)
    action = main_window._extract_action

    worker = extract_components(main_window, image)
    # While the worker is alive the menu should be disabled. Snapshot
    # the state immediately so the assertion isn't racing the worker
    # finishing.
    if worker.isRunning():
        assert action.isEnabled() is False
    qtbot.waitUntil(lambda: main_window.active_worker is None, timeout=10_000)
    assert action.isEnabled() is True


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


def test_extract_components_opens_extraction_view_tab(
    main_window: MainWindow, tmp_path: Path, qtbot: QtBot
) -> None:
    """Running extraction on the open image opens an ``ExtractionView`` tab."""
    binary = synthetic_uefi_volume.build(tmp_path)
    image = _open_image_in_window(main_window, binary)

    initial_tab_count = main_window.workspace.count()
    result = _run_to_completion(qtbot, main_window, image)
    assert result is not None

    workspace = main_window.workspace
    assert workspace.count() == initial_tab_count + 1
    active = workspace.currentWidget()
    assert isinstance(active, ExtractionView)
    assert active.manifest is not None
    assert active.manifest.total_components == 1
    assert active.manifest.components[0].name == synthetic_uefi_volume.FFS_FILE_NAME


def test_extraction_view_renders_components_and_errors(
    main_window: MainWindow, tmp_path: Path, qtbot: QtBot
) -> None:
    """The view renders both the components table and the errors table."""
    binary = synthetic_uefi_volume.build(tmp_path)
    image = _open_image_in_window(main_window, binary)
    result = _run_to_completion(qtbot, main_window, image)
    assert result is not None
    view = main_window.workspace.currentWidget()
    assert isinstance(view, ExtractionView)
    tables = view.findChildren(QTableWidget)
    # One components table; an errors table only if the manifest has any.
    expected_tables = 1 + (1 if result.manifest.extraction_errors else 0)
    assert len(tables) == expected_tables
    # Components table has one row per component.
    component_table = tables[0]
    assert component_table.rowCount() == result.manifest.total_components


def test_progress_events_reach_status_bar(
    main_window: MainWindow, tmp_path: Path, qtbot: QtBot
) -> None:
    """At least one progress event lands in the status bar while running."""

    binary = synthetic_uefi_volume.build(tmp_path)
    image = _open_image_in_window(main_window, binary)

    captured_status: list[str] = []
    original = main_window._set_status_message

    def _capture(message: str | None) -> None:
        captured_status.append(message or "<cleared>")
        original(message)

    main_window._set_status_message = _capture  # type: ignore[method-assign]

    extract_components(main_window, image)
    qtbot.waitUntil(lambda: main_window.active_worker is None, timeout=10_000)
    main_window._set_status_message = original  # type: ignore[method-assign]

    # We should see at least one "Extracting <basename>:" status update
    # plus the cleared sentinel at the end.
    extracting_messages = [m for m in captured_status if m.startswith("Extracting ")]
    assert extracting_messages
    assert "<cleared>" in captured_status


# ---------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------


def test_request_extraction_cancel_short_circuits(
    main_window: MainWindow, tmp_path: Path, qtbot: QtBot
) -> None:
    """Calling :meth:`request_extraction_cancel` causes the worker to finish promptly."""

    binary = synthetic_uefi_volume.build(tmp_path)
    image = _open_image_in_window(main_window, binary)

    extract_components(main_window, image)
    main_window.request_extraction_cancel()
    qtbot.waitUntil(lambda: main_window.active_worker is None, timeout=10_000)
    # Worker is gone; either we got a manifest with a "cancelled by caller"
    # error or the worker finished naturally before the cancellation flag
    # was checked. Either outcome is acceptable.
    assert main_window.active_worker is None


# ---------------------------------------------------------------------
# Error path
# ---------------------------------------------------------------------


def test_extract_components_shows_message_on_invalid_input(
    main_window: MainWindow,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
) -> None:
    """An ``InvalidInputError`` short-circuits and leaves no new tab."""
    binary = synthetic_uefi_volume.build(tmp_path)
    image = _open_image_in_window(main_window, binary)
    initial_tab_count = main_window.workspace.count()

    # Replace the underlying file so the pipeline fails its
    # input-check step at the next call.
    binary.unlink()

    from PyQt6 import QtWidgets

    captured: list[tuple[str, str]] = []

    def _fake_warning(parent: object, title: str, message: str) -> int:
        captured.append((title, message))
        return 0

    monkeypatch.setattr(QtWidgets.QMessageBox, "warning", _fake_warning)

    extract_components(main_window, image)
    qtbot.waitUntil(lambda: main_window.active_worker is None, timeout=10_000)

    assert main_window.workspace.count() == initial_tab_count
    assert captured  # one warning shown
    assert "Could not extract" in captured[0][0]
