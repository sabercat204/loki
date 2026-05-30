"""Action: extract components from the currently selected firmware image.

Wires :func:`loki.extraction.extract_firmware` into the GUI through a
:class:`~loki.gui.extraction_worker.ExtractionWorker`. The worker
runs on a ``QThread`` so a multi-hundred-megabyte firmware binary
doesn't freeze the UI for the duration of the extraction.

Two entry points:

- :func:`extract_components` — fire-and-forget. Spawns the worker,
  attaches the standard set of slots on ``window``, and returns the
  worker so callers can reference it (e.g. for cancellation tests).
- :func:`extract_components_blocking` — synchronous helper that runs
  the same flow but blocks the calling thread until the worker
  finishes. Used by tests that want deterministic output without
  driving the Qt event loop manually.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QEventLoop

from loki.extraction import ExtractionResult
from loki.gui.extraction_worker import ExtractionWorker
from loki.models import ExtractionConfig, FirmwareImage

if TYPE_CHECKING:
    from loki.gui.main_window import MainWindow

__all__ = [
    "DEFAULT_EXTRACTION_CONFIG",
    "extract_components",
    "extract_components_blocking",
]


#: GUI-default :class:`ExtractionConfig`. Uses no on-disk output dir
#: (so raw component bytes don't leak across runs) and the same
#: per-component / max-size knobs the CLI defaults to.
DEFAULT_EXTRACTION_CONFIG: ExtractionConfig = ExtractionConfig(
    default_output_dir="",
    max_component_size=50_000_000,
    timeout_per_component=60,
)


def extract_components(
    window: MainWindow,
    image: FirmwareImage,
    *,
    config: ExtractionConfig | None = None,
) -> ExtractionWorker:
    """Spawn a background extraction worker for ``image``.

    Returns the :class:`ExtractionWorker` so callers (and tests) can
    reference it. The worker is owned by ``window`` and deletes
    itself when the run completes; callers don't need to hold a
    strong reference.

    The window is responsible for connecting slots to the worker's
    signals — see :meth:`MainWindow.start_extraction`.
    """

    cfg = config or DEFAULT_EXTRACTION_CONFIG
    return window.start_extraction(image, Path(image.file_path), cfg)


def extract_components_blocking(
    window: MainWindow,
    image: FirmwareImage,
    *,
    config: ExtractionConfig | None = None,
) -> ExtractionResult | None:
    """Run :func:`extract_components` and block until the worker finishes.

    Returns the :class:`ExtractionResult` on success, or ``None`` when
    the pipeline raised an error (the worker's ``errored`` signal
    surfaces the typed exception via the window's standard message
    box; this helper just lets tests drive the flow without
    interacting with the Qt event loop themselves).
    """

    worker = extract_components(window, image, config=config)
    if not worker.isRunning():
        return None
    loop = QEventLoop()
    worker.finished.connect(loop.quit)
    if worker.isRunning():
        loop.exec()
    return window.last_extraction_result_for(image)
