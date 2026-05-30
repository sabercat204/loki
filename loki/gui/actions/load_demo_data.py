"""View → Load Demo Data action.

Synthesizes a coherent set of valid model instances and pushes them into
the running window. Every entry is labeled "(demo)" so it can't be
confused with output from a real extraction pipeline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from loki.gui.demo import build_demo_workspace
from loki.gui.demo.synthetic import DemoWorkspace

if TYPE_CHECKING:
    from loki.gui.main_window import MainWindow

__all__ = ["load_demo_data"]


def load_demo_data(window: MainWindow) -> DemoWorkspace:
    """Build a synthetic workspace and load it into ``window``.

    Returns the :class:`DemoWorkspace` so tests / callers can inspect
    what was loaded.
    """

    demo = build_demo_workspace()
    for image in demo.images:
        window.add_firmware_image(image, demo=True)
    baseline = demo.baseline_registry.baselines[0]
    window.add_baseline(baseline, comparison=demo.baseline_comparison, demo=True)
    window.add_image_report(demo.image_report, demo=True)
    return demo
