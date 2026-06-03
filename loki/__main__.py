"""Package entry point — ``python -m loki``.

This module exists for two reasons:

1. **Briefcase**. The macOS / Windows / Linux app bundles built by
   Briefcase invoke the application as ``python -m loki`` rather than
   importing a specific submodule. Without this file, the bundled
   launcher fails with ``No module named loki.__main__``. Briefcase's
   ``[tool.briefcase.app.loki].startup_module = "loki.gui"`` setting
   is honoured by some platform backends but not all, so we provide a
   canonical ``__main__`` and don't rely on the setting.
2. **Convention**. Python users expect ``python -m loki`` to do
   *something*, and the most useful thing for a GUI-shipping package
   to do is launch the GUI.

Behavior: identical to ``loki gui`` (the CLI subcommand). The CLI
remains the canonical entry point for non-GUI workflows; this module
is a shortcut for the GUI specifically.
"""

from __future__ import annotations

import sys


def main() -> int:
    """Launch the desktop GUI; return the Qt event-loop exit code."""
    # Imported lazily so ``python -c "import loki"`` doesn't pay the
    # PyQt6 import cost (consistent with the lazy-import discipline in
    # ``loki/cli.py``).
    from loki.gui.app import run

    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
