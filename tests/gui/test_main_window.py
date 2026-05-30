"""Tests for the Loki desktop GUI scaffold.

Exercises the structural contracts called out in the build plan:
- ``MainWindow`` constructs with menu bar + central splitter
- File-open action constructs a real ``FirmwareImage`` and opens a tab
- Demo-data action populates all four navigation groups
- Workspace tabs are closable via the standard tab-bar API
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from PyQt6.QtWidgets import QMainWindow, QSplitter, QTabBar
from pytestqt.qtbot import QtBot

from loki.gui.actions.open_firmware import open_firmware_from_path
from loki.gui.demo import build_demo_workspace
from loki.gui.main_window import MainWindow


@pytest.fixture()
def main_window(qtbot: QtBot) -> MainWindow:
    """Construct a fresh ``MainWindow`` and register it for cleanup."""
    window = MainWindow()
    qtbot.addWidget(window)
    return window


# ---------------------------------------------------------------------
# Step 9 — required tests
# ---------------------------------------------------------------------


def test_main_window_constructs(main_window: MainWindow) -> None:
    """Window has a menu bar with the three required top-level menus and a splitter."""
    assert isinstance(main_window, QMainWindow)
    menu_bar = main_window.menuBar()
    assert menu_bar is not None
    action_titles = [a.text() for a in menu_bar.actions()]
    assert "&File" in action_titles
    assert "&View" in action_titles
    assert "&Help" in action_titles

    central = main_window.centralWidget()
    assert isinstance(central, QSplitter)
    assert central.count() == 2  # navigation pane + workspace

    status = main_window.statusBar()
    assert status is not None  # status bar wired up


def test_open_firmware_constructs_model(main_window: MainWindow, tmp_path: Path) -> None:
    """A fake binary on disk produces a valid ``FirmwareImage`` and opens a tab."""
    fake = tmp_path / "fake-firmware.rom"
    payload = b"LOKI-DEMO-FIRMWARE\x00" * 8192
    fake.write_bytes(payload)
    expected_hash = hashlib.sha256(payload).hexdigest()

    image = open_firmware_from_path(main_window, fake)

    assert image is not None
    assert image.file_path == str(fake)
    assert image.file_hash == expected_hash
    assert image.file_size == len(payload)
    assert image.image_id is not None  # uuid5-generated

    workspace = main_window.workspace
    assert workspace.count() == 1
    assert workspace.has_tab(f"image:{image.image_id}")


def test_demo_data_populates_workspace(main_window: MainWindow) -> None:
    """``Load Demo Data`` should fill all four navigation groups appropriately."""
    from loki.gui.actions import load_demo_data

    demo = load_demo_data(main_window)

    nav = main_window.navigation
    images_group = nav.topLevelItem(0)
    baselines_group = nav.topLevelItem(1)
    reports_group = nav.topLevelItem(2)
    fleet_group = nav.topLevelItem(3)
    assert images_group is not None
    assert baselines_group is not None
    assert reports_group is not None
    assert fleet_group is not None

    # 2 images, 1 baseline, 1 report, fleet still placeholder.
    assert images_group.childCount() == len(demo.images) == 2
    assert baselines_group.childCount() == 1
    assert reports_group.childCount() == 1
    assert fleet_group.childCount() == 1  # placeholder still present
    placeholder = fleet_group.child(0)
    assert placeholder is not None
    assert placeholder.text(0) == "No fleet data loaded yet"

    # Every navigation entry under Images, Baselines, Reports is labeled "(demo)".
    for group_item in (images_group, baselines_group, reports_group):
        for idx in range(group_item.childCount()):
            child = group_item.child(idx)
            assert child is not None
            assert child.text(0).endswith("(demo)"), child.text(0)

    # 4 workspace tabs total: 2 images + 1 baseline + 1 report.
    assert main_window.workspace.count() == 4


def test_workspace_tabs_closable(main_window: MainWindow) -> None:
    """Closing a tab via the tab bar removes it from the workspace and key map."""
    workspace = main_window.workspace
    assert workspace.tabsClosable() is True

    demo = build_demo_workspace()
    main_window.add_firmware_image(demo.images[0], demo=True)
    image_key = f"image:{demo.images[0].image_id}"

    assert workspace.count() == 1
    assert workspace.has_tab(image_key)

    # Simulate the user clicking the close button by emitting the same signal.
    tab_bar = workspace.tabBar()
    assert isinstance(tab_bar, QTabBar)
    workspace.tabCloseRequested.emit(0)

    assert workspace.count() == 0
    assert workspace.has_tab(image_key) is False


# ---------------------------------------------------------------------
# Bonus: a couple of small structural assertions worth pinning
# ---------------------------------------------------------------------


def test_navigation_double_click_focuses_existing_tab(main_window: MainWindow) -> None:
    """Double-clicking a navigation entry focuses (not duplicates) its tab."""
    from loki.gui.actions import load_demo_data

    load_demo_data(main_window)
    workspace = main_window.workspace
    initial_tab_count = workspace.count()
    nav = main_window.navigation
    images_group = nav.topLevelItem(0)
    assert images_group is not None
    second_image_item = images_group.child(1)
    assert second_image_item is not None

    workspace.setCurrentIndex(0)  # focus a different tab

    nav._on_item_double_clicked(second_image_item, 0)

    # No new tab should have been created — just focus shift.
    assert workspace.count() == initial_tab_count


def test_reset_workspace_clears_navigation_and_tabs(main_window: MainWindow) -> None:
    """``View → Reset Workspace`` returns the window to a clean slate."""
    from loki.gui.actions import load_demo_data

    load_demo_data(main_window)
    assert main_window.workspace.count() > 0

    main_window.reset_workspace()

    assert main_window.workspace.count() == 0
    nav = main_window.navigation
    for idx in range(4):
        group = nav.topLevelItem(idx)
        assert group is not None
        # Every group should be back to its single placeholder row.
        assert group.childCount() == 1
        placeholder = group.child(0)
        assert placeholder is not None
        assert placeholder.text(0).startswith("No ")
