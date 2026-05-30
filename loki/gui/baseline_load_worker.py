"""``QThread`` worker that runs ``BaselineStore.load`` off the UI thread.

The on-disk corpus a baseline-curation user accumulates can grow
past the threshold where the synchronous load (~12s for 128
baselines, ~117s for 1024) freezes the window noticeably. This
worker mirrors the :class:`~loki.gui.extraction_worker.ExtractionWorker`
shape so the UI stays responsive during that load.

Threading model:

- One worker per ``MainWindow`` lifecycle. Spawned during
  ``__init__`` (if the caller opted into background loading) and
  joined in ``closeEvent``.
- Per-file progress events flow through the optional
  ``progress`` callback contracted in baseline-persistence
  R2.8. The worker re-emits each event on the
  :pyattr:`progress` Qt signal so the UI updates the status bar
  on the main thread.
- Cooperative cancellation through the optional ``cancel``
  callback contracted in baseline-persistence R2.9. The worker
  reads a thread-safe flag set by :meth:`request_cancel`; the
  load returns the partial :class:`LoadResult` accumulated so
  far when the flag flips.
- Errors are *captured*, not raised. The worker emits the
  exception via :pyattr:`errored` so the UI can show a
  ``QMessageBox`` on the main thread; the worker thread itself
  always exits cleanly.
"""

from __future__ import annotations

import threading

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from loki.baseline import (
    BaselineStore,
    BaselineStoreError,
    LoadProgressEvent,
)

__all__ = ["BaselineLoadWorker"]


class BaselineLoadWorker(QThread):
    """``QThread`` wrapper around :meth:`BaselineStore.load`.

    Signals:
        finished_with_result: Emitted with the
            :class:`~loki.baseline.LoadResult` when the load
            completes successfully (including when the load
            stopped early via :meth:`request_cancel`).
        errored: Emitted with the typed exception (a
            :class:`BaselineStoreError` subclass) when the load
            fails its pre-conditions.
        progress: Emitted with each
            :class:`~loki.baseline.LoadProgressEvent` produced by
            the underlying ``BaselineStore.load`` per
            baseline-persistence R2.8. Connected to the
            :class:`~loki.gui.main_window.MainWindow`'s status bar
            so per-file progress shows up without blocking the UI.
    """

    finished_with_result = pyqtSignal(object)
    errored = pyqtSignal(object)
    progress = pyqtSignal(object)

    def __init__(
        self,
        store: BaselineStore,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        # ``threading.Event`` is the right primitive here: setting
        # it from the GUI thread (via :meth:`request_cancel`) and
        # reading it from the worker thread (via the cancel
        # callback) is atomic without an explicit lock.
        self._cancel_event = threading.Event()

    @property
    def store(self) -> BaselineStore:
        """Return the store this worker loads from."""
        return self._store

    def request_cancel(self) -> None:
        """Signal the worker to stop after the current Baseline_File.

        Idempotent. Once called, the cancel flag stays set for the
        rest of the worker's lifetime; future invocations are
        no-ops. The GUI surface that calls this should also disable
        whatever button or menu item triggered it so the user
        doesn't double-click.
        """

        self._cancel_event.set()

    def is_cancel_requested(self) -> bool:
        """Return whether :meth:`request_cancel` has been called."""

        return self._cancel_event.is_set()

    # ------------------------------------------------------------------
    # QThread.run
    # ------------------------------------------------------------------

    def _emit_progress(self, event: LoadProgressEvent) -> None:
        """Re-emit a per-file progress event on the worker's Qt signal."""

        self.progress.emit(event)

    def run(self) -> None:
        """Worker entry point. Runs on the worker thread."""
        try:
            result = self._store.load(
                progress=self._emit_progress,
                cancel=self._cancel_event.is_set,
            )
        except BaselineStoreError as exc:
            self.errored.emit(exc)
            return

        self.finished_with_result.emit(result)
