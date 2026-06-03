"""Smoke test for ``python -m loki`` (the Briefcase entry point).

Briefcase's bundled launcher invokes the application as ``python -m loki``
on every platform. Without ``loki/__main__.py`` this fails with the
``No module named loki.__main__`` error that shipped briefly in the
v1.0.0 macOS / Windows / Linux artifacts. This test pins the contract
so a future refactor cannot drop ``__main__.py`` without breaking the
packaged builds.
"""

from __future__ import annotations

import importlib
import importlib.util
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest


def test_main_module_is_importable() -> None:
    """``loki.__main__`` exists and exposes a ``main`` callable."""
    module = importlib.import_module("loki.__main__")
    assert callable(module.main), "loki.__main__ must expose a ``main`` function"


def test_python_dash_m_loki_resolves() -> None:
    """``python -m loki`` resolves the package's ``__main__`` entry point.

    We don't actually start the Qt event loop here — we just confirm
    that the module is discoverable via importlib (which is exactly
    what ``python -m loki`` looks up). The real launch is exercised
    by the offscreen smoke harness at ``scripts/smoke_gui.py`` and by
    the in-process tests under ``tests/gui/test_main_window.py``.
    """
    spec = importlib.util.find_spec("loki.__main__")
    assert spec is not None, (
        "loki.__main__ must resolve via importlib so ``python -m loki`` works "
        "from the Briefcase-packaged bundle launcher."
    )


@pytest.fixture()
def patched_run() -> Iterator[MagicMock]:
    """Patch loki.gui.app.run so test runs without spawning a Qt window."""
    with patch("loki.gui.app.run", return_value=0) as patched:
        yield patched


def test_main_delegates_to_gui_app_run(patched_run: MagicMock) -> None:
    """``loki.__main__.main()`` returns the value of ``loki.gui.app.run()``."""
    from loki.__main__ import main

    exit_code = main()
    assert exit_code == 0
    patched_run.assert_called_once()
