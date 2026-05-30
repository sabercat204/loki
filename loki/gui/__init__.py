"""loki.gui — PyQt6 desktop application for the LOKI firmware analysis platform.

Scope B scaffold: main window, navigation pane, tabbed workspace, file-open
flow that constructs ``FirmwareImage`` from a real binary, and a Load Demo
Data action that populates synthetic model instances so UI/UX work can
iterate without a real extraction pipeline.

Entry point::

    from loki.gui.app import run
    run()

or via the CLI::

    loki gui
"""

from loki.gui.app import run

__all__ = ["main", "run"]


def main() -> None:
    """Briefcase entry point."""
    import sys

    sys.exit(run())
