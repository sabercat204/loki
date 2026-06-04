"""``QThread`` worker that runs ``extract_firmware`` off the UI thread.

Surfaces progress events and the final result through Qt signals so
the main window can stay responsive while a multi-hundred-megabyte
firmware binary is being hashed and parsed.

Threading model:

- One worker per extraction. The main window owns the worker and
  deletes it when the run completes.
- Cancellation is request/response via :meth:`request_cancellation`,
  which the worker checks between components (R9.4). The cancellation
  primitive is a :class:`threading.Event`, matching
  :class:`~loki.gui.baseline_load_worker.BaselineLoadWorker` and
  :class:`~loki.gui.analysis_worker.AnalysisWorker` (D3).
- Errors are *captured*, not raised. The worker emits the error
  shape via :pyattr:`errored` so the UI can show a ``QMessageBox``
  on the main thread; the worker thread itself always exits cleanly.
"""

from __future__ import annotations

import threading
from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from loki.extraction import (
    ExtractionPipelineError,
    InvalidInputError,
    ManifestConstructionError,
    ProgressEvent,
    extract_firmware,
)
from loki.models import ExtractionConfig

__all__ = ["ExtractionWorker"]


class ExtractionWorker(QThread):
    """``QThread`` wrapper around :func:`loki.extraction.extract_firmware`.

    Signals:
        progress_event: Emitted from the worker thread for every
            :class:`ProgressEvent`. Qt's queued connection mechanism
            marshals these to the receiving slot's thread (typically
            the main thread).
        finished_with_result: Emitted with the
            :class:`ExtractionResult` when extraction completes
            successfully.
        errored: Emitted with the typed exception (one of
            :class:`InvalidInputError`,
            :class:`ManifestConstructionError`, or generic
            :class:`ExtractionPipelineError`) when the pipeline fails
            its pre- or post-conditions.
    """

    progress_event = pyqtSignal(object)
    finished_with_result = pyqtSignal(object)
    errored = pyqtSignal(object)

    def __init__(
        self,
        path: Path,
        config: ExtractionConfig,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._path = path
        self._config = config
        # ``threading.Event`` is the right primitive: setting it from
        # the GUI thread (via :meth:`request_cancellation`) and reading
        # it from the worker thread (via the ``cancel`` callback) is
        # atomic without an explicit lock, and the same pattern is used
        # by :class:`BaselineLoadWorker` and :class:`AnalysisWorker`.
        self._cancel_event = threading.Event()

    # ------------------------------------------------------------------
    # Public control surface
    # ------------------------------------------------------------------

    def request_cancellation(self) -> None:
        """Ask the worker to stop at the next component boundary (R9.4).

        Idempotent. Once set, the cancel flag stays set for the rest
        of the worker's lifetime; future invocations are no-ops.
        """
        self._cancel_event.set()

    @property
    def cancelled(self) -> bool:
        """Return whether :meth:`request_cancellation` has been called."""
        return self._cancel_event.is_set()

    # ------------------------------------------------------------------
    # QThread.run
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Worker entry point. Runs on the worker thread."""

        def _on_progress(event: ProgressEvent) -> None:
            self.progress_event.emit(event)

        try:
            result = extract_firmware(
                self._path,
                self._config,
                progress=_on_progress,
                cancel=self._cancel_event.is_set,
            )
        except (
            InvalidInputError,
            ManifestConstructionError,
            ExtractionPipelineError,
        ) as exc:
            self.errored.emit(exc)
            return

        self.finished_with_result.emit(result)
