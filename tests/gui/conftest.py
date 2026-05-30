"""Per-package conftest for GUI tests.

Forces the offscreen Qt platform plugin so tests run headless on CI and
on local machines without a display server. Also disables Hypothesis's
deadline for any Qt-touching tests since QApplication startup latency
varies wildly.
"""

from __future__ import annotations

import os

# Set before pytest-qt or QApplication is imported anywhere.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
