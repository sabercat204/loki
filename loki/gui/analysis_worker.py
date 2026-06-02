"""``QThread`` worker that runs classification + analysis off the UI thread.

Mirrors the contract established by
:class:`~loki.gui.extraction_worker.ExtractionWorker` and
:class:`~loki.gui.baseline_load_worker.BaselineLoadWorker` so the three
worker types can be handled uniformly by the main window:

- Cooperative cancellation through a :class:`threading.Event` set from
  the GUI thread (via :meth:`request_cancel`) and polled from the
  worker thread via the ``cancel`` callback contracts on
  :func:`loki.classification.classify_components` and
  :func:`loki.analysis.analyze_image`.
- Typed-exception propagation: failure modes that escape the underlying
  pipelines are emitted on :pyattr:`errored` as instances of
  :class:`AnalysisError`, :class:`ClassificationPipelineError`, or
  :class:`BaselineStoreError` (all share the contract that ``str(exc)``
  produces an operator-facing message). Untyped exceptions still
  surface — they are wrapped in :class:`RuntimeError` and emitted so
  the worker thread always exits cleanly without stack-tracing into
  ``sys.excepthook``.
"""

from __future__ import annotations

import threading
from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from loki.analysis.errors import AnalysisError
from loki.baseline.errors import BaselineStoreError
from loki.classification.errors import ClassificationPipelineError
from loki.models import (
    BaselineConfig,
    ClassificationConfig,
    ExtractionManifest,
)

__all__ = ["AnalysisWorker"]


class AnalysisWorker(QThread):
    """Run classify + analyze on a background thread.

    Signals:
        finished_with_report: Emitted with the
            :class:`~loki.models.ImageAnalysisReport` on success
            (including when the run stops early via
            :meth:`request_cancel` and the analysis pipeline returns a
            partial report per its R16.6 cancellation-as-return-path
            contract).
        errored: Emitted with the typed exception that aborted the
            run. Always one of the three pipeline-error roots
            (:class:`AnalysisError`, :class:`ClassificationPipelineError`,
            :class:`BaselineStoreError`) or a
            :class:`RuntimeError` wrapping any other exception.
            Connected to the
            :class:`~loki.gui.main_window.MainWindow` ``QMessageBox``
            handler that dispatches per-type recovery.
    """

    finished_with_report = pyqtSignal(object)
    errored = pyqtSignal(object)

    def __init__(
        self,
        manifest: ExtractionManifest,
        baseline_path: Path,
        rules_path: Path,
        *,
        taxonomy_version: str = "1.0.0",
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._manifest = manifest
        self._baseline_path = baseline_path
        self._rules_path = rules_path
        self._taxonomy_version = taxonomy_version
        # ``threading.Event`` is the right primitive here: setting it
        # from the GUI thread and reading it from the worker thread is
        # atomic without an explicit lock. Mirrors
        # :class:`BaselineLoadWorker`.
        self._cancel_event = threading.Event()

    def request_cancel(self) -> None:
        """Signal the worker to stop after the current component.

        Idempotent. Once set, the cancel flag stays set for the rest
        of the worker's lifetime; future invocations are no-ops. The
        underlying classification + analysis pipelines poll the
        ``cancel`` callback between components and return the partial
        result accumulated so far when the flag flips
        (R16.6 in analysis; mirrored in classification).
        """
        self._cancel_event.set()

    def is_cancel_requested(self) -> bool:
        """Return whether :meth:`request_cancel` has been called."""
        return self._cancel_event.is_set()

    def run(self) -> None:
        """Worker entry point. Runs on the worker thread."""
        try:
            from loki.analysis import analyze_image
            from loki.baseline import BaselineStore
            from loki.classification import classify_components
            from loki.models.config import AnalysisConfig
            from loki.models.enums import SeverityLevel
        except ImportError as exc:  # pragma: no cover — dev-only safety net
            self.errored.emit(RuntimeError(f"analysis pipeline import failed: {exc}"))
            return

        try:
            store = BaselineStore(
                BaselineConfig(storage_path=str(self._baseline_path), auto_match=True)
            )
            load_result = store.load(cancel=self._cancel_event.is_set)

            config = ClassificationConfig(
                taxonomy_version=self._taxonomy_version,
                confidence_threshold=0.6,
                rules_path=str(self._rules_path),
            )
            classification_result = classify_components(
                self._manifest.components,
                config,
                cancel=self._cancel_event.is_set,
            )

            analysis_config = AnalysisConfig(
                severity_weights={
                    "type": 0.25,
                    "vendor": 0.25,
                    "security_posture": 0.30,
                    "mutability": 0.20,
                },
                default_severity_threshold=SeverityLevel.MEDIUM,
            )
            report = analyze_image(
                target_records=classification_result.records,
                registry=load_result.registry,
                target_image=self._manifest.source_image,
                config=analysis_config,
                cancel=self._cancel_event.is_set,
            )
            self.finished_with_report.emit(report)
        except (AnalysisError, ClassificationPipelineError, BaselineStoreError) as exc:
            self.errored.emit(exc)
        except Exception as exc:
            # Wrap any non-typed exception in RuntimeError so the
            # ``errored`` signal payload remains an Exception instance
            # the UI handler can dispatch on.
            self.errored.emit(RuntimeError(f"{type(exc).__name__}: {exc}"))
