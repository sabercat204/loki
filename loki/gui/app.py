"""QApplication entry point for the Loki desktop app."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import cast

from PyQt6.QtWidgets import QApplication

from loki.baseline import BaselineStore, BaselineStoreError
from loki.gui.main_window import MainWindow
from loki.models import BaselineConfig

__all__ = ["build_application", "run"]


_LOGGER = logging.getLogger("loki.gui.baselines")
_DEFAULT_BASELINE_STORAGE_PATH = Path.home() / ".local" / "share" / "loki" / "baselines"


def _build_default_baseline_store() -> BaselineStore | None:
    """Construct a :class:`BaselineStore` rooted at the default user path.

    Returns ``None`` if the default Storage_Directory can't be
    created (e.g. read-only home dir, sandboxed environment); the
    GUI still works, but the Baselines navigation group stays
    placeholder. R7.1 says the store is constructed from the
    "active LokiConfig" in the future; v1 hard-codes the path
    pending the config-loading spec (deferred decision §1).
    """

    config = BaselineConfig(
        storage_path=str(_DEFAULT_BASELINE_STORAGE_PATH),
        auto_match=False,
    )
    try:
        return BaselineStore(config)
    except BaselineStoreError as exc:
        _LOGGER.warning(
            "could not construct baseline store at %s: %s",
            _DEFAULT_BASELINE_STORAGE_PATH,
            exc,
        )
        return None


def build_application(argv: list[str] | None = None) -> tuple[QApplication, MainWindow]:
    """Return a ready-to-show ``(QApplication, MainWindow)`` pair.

    Reuses an existing ``QApplication`` if one is already running (e.g.
    under ``pytest-qt``'s ``qapp`` fixture). Constructs a default
    :class:`BaselineStore` rooted at
    ``~/.local/share/loki/baselines`` so the Baselines navigation
    group surfaces real persisted baselines on startup.
    """

    args = argv if argv is not None else sys.argv
    existing = QApplication.instance()
    if existing is None:
        app = QApplication(args)
    else:
        app = cast(QApplication, existing)
    app.setApplicationName("Loki")
    app.setApplicationDisplayName("Loki")
    app.setOrganizationName("LOKI")
    app.setOrganizationDomain("loki.invalid")
    store = _build_default_baseline_store()
    window = MainWindow(baseline_store=store)
    return app, window


def run(argv: list[str] | None = None) -> int:
    """Launch the desktop app and block until the window is closed.

    Returns the Qt event-loop exit code.
    """

    app, window = build_application(argv)
    window.show()
    return app.exec()
