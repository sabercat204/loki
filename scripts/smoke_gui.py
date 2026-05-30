"""One-shot smoke check for the Loki GUI without a real event loop.

Not part of the test suite — this is a manual verification helper. Run::

    QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from loki.baseline import BaselineStore
from loki.gui.actions import load_demo_data
from loki.gui.main_window import MainWindow
from loki.models import BaselineConfig


def main() -> None:
    # Build everything against a fresh tmp baseline directory so the
    # smoke script never touches the user's real baseline storage.
    with tempfile.TemporaryDirectory(prefix="loki-smoke-baselines-") as tmp:
        tmp_path = Path(tmp)
        store = BaselineStore(BaselineConfig(storage_path=str(tmp_path), auto_match=False))

        existing = QApplication.instance()
        if existing is None:
            app = QApplication(["loki-gui-smoke"])
        else:
            # QApplication.instance() is typed as QCoreApplication | None,
            # but the GUI smoke script always runs against the QApplication
            # subclass — narrow the type so mypy --strict accepts the reuse.
            assert isinstance(existing, QApplication)
            app = existing
        app.setApplicationName("Loki")
        window = MainWindow(baseline_store=store)
        window.show()
        app.processEvents()
        demo = load_demo_data(window)
        app.processEvents()
        assert window.workspace.count() == 4, window.workspace.count()
        nav = window.navigation
        counts: list[tuple[str, int]] = []
        for idx in range(4):
            item = nav.topLevelItem(idx)
            assert item is not None
            counts.append((item.text(0), item.childCount()))
        print("nav counts:", counts)
        print("demo summary:", demo.baseline_comparison.summary)
        print("severity dist:", demo.image_report.summary.findings_by_severity)
        window.reset_workspace()
        app.processEvents()
        assert window.workspace.count() == 0
        print("reset clean: ok")
        window.close()
        app.processEvents()


if __name__ == "__main__":
    main()
