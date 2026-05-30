"""Menu / toolbar actions that mutate the workspace."""

from loki.gui.actions.extract_components import extract_components
from loki.gui.actions.load_demo_data import load_demo_data
from loki.gui.actions.open_baseline import open_baseline, open_baseline_from_path
from loki.gui.actions.open_firmware import open_firmware
from loki.gui.actions.save_baseline import save_baseline

__all__ = [
    "extract_components",
    "load_demo_data",
    "open_baseline",
    "open_baseline_from_path",
    "open_firmware",
    "save_baseline",
]
