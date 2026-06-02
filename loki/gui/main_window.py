"""Top-level ``QMainWindow`` for the Loki desktop app.

Wires the navigation pane, tabbed workspace, menu bar, and status bar.
Public methods (``add_firmware_image``, ``add_baseline``,
``add_image_report``) are how the action handlers and tests push state
into the UI without going through menus.
"""

from __future__ import annotations

import importlib.metadata
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QByteArray, QSettings, Qt
from PyQt6.QtGui import QAction, QCloseEvent
from PyQt6.QtWidgets import (
    QLabel,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStatusBar,
    QWidget,
)

from loki.baseline import BaselineStore, BaselineStoreError
from loki.gui.actions import (
    load_demo_data,
    open_baseline,
    open_firmware,
    save_baseline,
)
from loki.gui.actions.extract_components import extract_components
from loki.gui.baseline_load_worker import BaselineLoadWorker
from loki.gui.extraction_worker import ExtractionWorker
from loki.gui.navigation import NavigationGroup, NavigationPane
from loki.gui.views import (
    AnalysisView,
    BaselineView,
    ExtractionView,
    FirmwareImageView,
    FleetAnalysisView,
    ImageAnalysisReportView,
)
from loki.gui.workspace import Workspace
from loki.models import (
    BaselineComparison,
    BaselineRecord,
    ExtractionConfig,
    ExtractionManifest,
    FirmwareImage,
    ImageAnalysisReport,
)

if TYPE_CHECKING:
    from loki.extraction import (
        ExtractionPipelineError,
        ExtractionResult,
        ProgressEvent,
    )

__all__ = ["MainWindow"]


_WINDOW_TITLE = "Loki — Firmware Analysis"
_DEFAULT_SIZE = (1280, 800)

_LOGGER = logging.getLogger("loki.gui.baselines")


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        baseline_store: BaselineStore | None = None,
        background_load: bool = True,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(_WINDOW_TITLE)

        # Track which models are loaded so the status bar stays accurate.
        self._image_count = 0
        self._classification_version: str | None = None
        self._last_extraction: datetime | None = None
        self._image_views: dict[str, FirmwareImageView] = {}
        self._baseline_views: dict[str, BaselineView] = {}
        self._baseline_records: dict[str, BaselineRecord] = {}
        self._report_views: dict[str, ImageAnalysisReportView] = {}
        self._extraction_views: dict[str, ExtractionView] = {}
        # Map from image_id -> FirmwareImage so the extraction action can
        # look up the currently-active image without round-tripping through
        # the view layer.
        self._images_by_key: dict[str, FirmwareImage] = {}
        # Background-extraction state.
        self._active_worker: ExtractionWorker | None = None
        self._active_worker_image: FirmwareImage | None = None
        self._last_results: dict[str, ExtractionResult] = {}

        # Baseline persistence (R7). Optional injection lets tests
        # point at a tmp_path-rooted store while production uses a
        # default location under ~/.local/share/loki/baselines.
        self._baseline_store = baseline_store
        self._background_load = background_load
        self._baseline_load_worker: BaselineLoadWorker | None = None

        self._navigation = NavigationPane(self)
        self._workspace = Workspace(self)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(self._navigation)
        splitter.addWidget(self._workspace)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([260, 1020])
        self.setCentralWidget(splitter)
        self._splitter = splitter

        self._build_menu_bar()
        self._build_status_bar()

        self._navigation.item_activated.connect(self._on_navigation_activated)
        self._workspace.currentChanged.connect(self._on_workspace_tab_changed)

        self._restore_geometry()

        # Pre-register the extractors so the worker thread doesn't
        # pay the registration cost on its first run. Idempotent;
        # ``extract_firmware`` calls the same helper internally.
        from loki.extraction.extractors import register as _register_extractors

        _register_extractors()

        # Run the baseline Discovery_Scan now that the menu/status bar
        # are wired up — R7.1, R7.2, R7.3.
        self._populate_baselines_from_store()

        # The save-baseline action is enabled only when a BaselineView
        # is the active workspace tab; re-evaluate now that the
        # workspace is built and the menu exists.
        self._refresh_save_baseline_action_enabled()

    # ------------------------------------------------------------------
    # Public API used by actions and tests
    # ------------------------------------------------------------------

    def add_firmware_image(self, image: FirmwareImage, *, demo: bool = False) -> None:
        """Add an image to the navigation pane and open a view tab for it."""
        key = self._image_key(image)
        label = self._image_label(image, demo=demo)
        self._navigation.add_entry(NavigationGroup.IMAGES, key, label)
        view = FirmwareImageView(image, parent=self._workspace)
        self._image_views[key] = view
        self._images_by_key[key] = image
        self._workspace.open_tab(key, label, view)
        self._image_count += 1
        if image.extraction_timestamp is not None:
            self._last_extraction = image.extraction_timestamp
        self._refresh_extract_action_enabled()
        self._refresh_status_bar()

    def add_baseline(
        self,
        baseline: BaselineRecord,
        *,
        comparison: BaselineComparison | None = None,
        demo: bool = False,
    ) -> None:
        """Add a baseline to the navigation pane and open a view tab for it.

        R7.8: navigation entry label is
        ``{vendor} {model} {firmware_version}`` for real-loaded
        baselines. Demo baselines retain the ``(demo)`` suffix per
        R7.9.
        """
        key = f"baseline:{baseline.baseline_id}"
        suffix = " (demo)" if demo else ""
        # R7.8: canonical label.
        label = f"{baseline.vendor} {baseline.model} {baseline.firmware_version}{suffix}"
        self._navigation.add_entry(NavigationGroup.BASELINES, key, label)
        view = BaselineView(baseline, comparison=comparison, parent=self._workspace)
        self._baseline_views[key] = view
        self._baseline_records[key] = baseline
        self._workspace.open_tab(key, label, view)
        if baseline.component_manifest:
            self._classification_version = baseline.component_manifest[0].classification_version
        self._refresh_status_bar()
        self._refresh_save_baseline_action_enabled()

    def add_image_report(self, report: ImageAnalysisReport, *, demo: bool = False) -> None:
        """Add an analysis report to the navigation pane and open a view tab for it."""
        key = f"report:{report.report_id}"
        suffix = " (demo)" if demo else ""
        label = (
            f"Report — {report.image_metadata.model or report.image_id} "
            f"[{report.posture_rating.value}]{suffix}"
        )
        self._navigation.add_entry(NavigationGroup.REPORTS, key, label)
        view = ImageAnalysisReportView(report, parent=self._workspace)
        self._report_views[key] = view
        self._workspace.open_tab(key, label, view)
        self._refresh_status_bar()

    def add_extraction_result(self, image: FirmwareImage, result: ExtractionResult) -> None:
        """Open an :class:`ExtractionView` tab for ``result`` against ``image``."""
        manifest = result.manifest
        key = self._extraction_key(image, manifest)
        label = (
            f"Extraction — {self._image_basename(image)} ({manifest.total_components} components)"
        )
        view = ExtractionView(manifest, parent=self._workspace)
        self._extraction_views[key] = view
        self._workspace.open_tab(key, label, view)
        self._last_extraction = manifest.extraction_timestamp
        image_key = self._image_key(image)
        self._last_results[image_key] = result
        self._refresh_analyze_action_enabled()
        self._refresh_status_bar()

    def start_extraction(
        self,
        image: FirmwareImage,
        path: Path,
        config: ExtractionConfig,
    ) -> ExtractionWorker:
        """Spawn an :class:`ExtractionWorker` for ``image`` and wire its signals.

        Refuses to spawn a second worker if one is already active —
        the action wiring uses :meth:`_refresh_extract_action_enabled`
        to guard the menu, but this is the belt-and-braces check.
        Returns the existing worker in that case.
        """

        if self._active_worker is not None:
            return self._active_worker

        worker = ExtractionWorker(path, config, parent=self)
        worker.progress_event.connect(self._on_progress_event)
        worker.finished_with_result.connect(self._on_extraction_finished)
        worker.errored.connect(self._on_extraction_errored)
        worker.finished.connect(self._on_worker_finished)
        self._active_worker = worker
        self._active_worker_image = image
        self._refresh_extract_action_enabled()
        self._set_status_message(f"Extracting {self._image_basename(image)}…")
        worker.start()
        return worker

    def request_extraction_cancel(self) -> None:
        """Request cancellation of the active extraction worker, if any."""
        if self._active_worker is not None:
            self._active_worker.request_cancellation()

    def last_extraction_result_for(self, image: FirmwareImage) -> ExtractionResult | None:
        """Return the most recent extraction result for ``image``, if any."""
        return self._last_results.get(self._image_key(image))

    @property
    def active_worker(self) -> ExtractionWorker | None:
        """Return the active background extraction worker, if any.

        Exposed for tests; production code shouldn't poke at it
        directly because the worker is owned by the window and tied
        to a single in-flight extraction.
        """
        return self._active_worker

    def reset_workspace(self) -> None:
        """Close every tab and clear navigation entries.

        Bound to ``View → Reset Workspace``. Useful for restarting after
        loading demo data without restarting the whole app. If a
        background extraction is currently running it is requested to
        cancel; the worker still runs to completion on its own thread
        but its result is discarded.
        """
        if self._active_worker is not None:
            self._active_worker.request_cancellation()
        self._workspace.reset()
        self._navigation.reset()
        self._image_views.clear()
        self._baseline_views.clear()
        self._baseline_records.clear()
        self._report_views.clear()
        self._extraction_views.clear()
        self._images_by_key.clear()
        self._last_results.clear()
        self._image_count = 0
        self._classification_version = None
        self._last_extraction = None
        self._refresh_extract_action_enabled()
        self._refresh_analyze_action_enabled()
        self._refresh_save_baseline_action_enabled()
        self._refresh_status_bar()

    @property
    def navigation(self) -> NavigationPane:
        return self._navigation

    @property
    def workspace(self) -> Workspace:
        return self._workspace

    # ------------------------------------------------------------------
    # Menu / status bar / persistence
    # ------------------------------------------------------------------

    def _build_menu_bar(self) -> None:
        menu_bar = self.menuBar()
        if menu_bar is None:  # pragma: no cover - PyQt always returns a bar
            return

        file_menu = menu_bar.addMenu("&File")
        if file_menu is not None:
            open_action = QAction("&Open Firmware Image…", self)
            open_action.setShortcut("Ctrl+O")
            open_action.triggered.connect(self._on_open_firmware)
            file_menu.addAction(open_action)
            file_menu.addSeparator()
            quit_action = QAction("&Quit", self)
            quit_action.setShortcut("Ctrl+Q")
            quit_action.triggered.connect(self.close)
            file_menu.addAction(quit_action)
            self._file_menu = file_menu

        view_menu = menu_bar.addMenu("&View")
        if view_menu is not None:
            demo_action = QAction("Load &Demo Data", self)
            demo_action.triggered.connect(self._on_load_demo_data)
            view_menu.addAction(demo_action)
            extract_action = QAction("&Extract Firmware Components…", self)
            extract_action.setShortcut("Ctrl+E")
            extract_action.triggered.connect(self._on_extract_components)
            extract_action.setEnabled(False)
            view_menu.addAction(extract_action)
            self._extract_action = extract_action
            analyze_action = QAction("Run &Analysis…", self)
            analyze_action.setShortcut("Ctrl+A")
            analyze_action.triggered.connect(self._on_run_analysis)
            analyze_action.setEnabled(False)
            view_menu.addAction(analyze_action)
            self._analyze_action = analyze_action
            load_fleet_action = QAction("Load &Fleet Report…", self)
            load_fleet_action.triggered.connect(self._on_load_fleet_report)
            view_menu.addAction(load_fleet_action)
            view_menu.addSeparator()
            open_baseline_action = QAction("&Open Baseline Registry…", self)
            open_baseline_action.triggered.connect(self._on_open_baseline)
            view_menu.addAction(open_baseline_action)
            self._open_baseline_action = open_baseline_action
            save_baseline_action = QAction("&Save Baseline…", self)
            save_baseline_action.triggered.connect(self._on_save_baseline)
            save_baseline_action.setEnabled(False)
            view_menu.addAction(save_baseline_action)
            self._save_baseline_action = save_baseline_action
            cancel_baseline_load_action = QAction("&Cancel Baseline Load", self)
            cancel_baseline_load_action.triggered.connect(self._on_cancel_baseline_load)
            cancel_baseline_load_action.setEnabled(False)
            view_menu.addAction(cancel_baseline_load_action)
            self._cancel_baseline_load_action = cancel_baseline_load_action
            view_menu.addSeparator()
            reset_action = QAction("&Reset Workspace", self)
            reset_action.triggered.connect(self.reset_workspace)
            view_menu.addAction(reset_action)
            self._view_menu = view_menu

        help_menu = menu_bar.addMenu("&Help")
        if help_menu is not None:
            about_action = QAction("&About Loki", self)
            about_action.triggered.connect(self._on_about)
            help_menu.addAction(about_action)
            self._help_menu = help_menu

    def _build_status_bar(self) -> None:
        bar = QStatusBar(self)
        self.setStatusBar(bar)
        self._status_label = QLabel("ready")
        self._status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        bar.addWidget(self._status_label, 1)
        self._transient_status: str | None = None
        self._refresh_status_bar()

    def _refresh_status_bar(self) -> None:
        if self._transient_status is not None:
            self._status_label.setText(self._transient_status)
            return
        last_extraction = self._last_extraction.isoformat() if self._last_extraction else "—"
        classification_version = self._classification_version or "—"
        self._status_label.setText(
            f"images: {self._image_count}  "
            f"last extraction: {last_extraction}  "
            f"classification version: {classification_version}"
        )

    def _set_status_message(self, message: str | None) -> None:
        """Set or clear a transient status-bar override for in-flight state."""
        self._transient_status = message
        self._refresh_status_bar()

    def _restore_geometry(self) -> None:
        settings = QSettings("LOKI", "Desktop")
        geometry = settings.value("main_window/geometry")
        if isinstance(geometry, QByteArray) and not geometry.isEmpty():
            self.restoreGeometry(geometry)
        else:
            self.resize(*_DEFAULT_SIZE)
        state = settings.value("main_window/state")
        if isinstance(state, QByteArray) and not state.isEmpty():
            self.restoreState(state)
        splitter_state = settings.value("main_window/splitter")
        if isinstance(splitter_state, QByteArray) and not splitter_state.isEmpty():
            self._splitter.restoreState(splitter_state)

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802 - Qt signature
        # Cancel any in-flight extraction so it doesn't keep the
        # process alive after the window closes. ``QThread.wait()``
        # joins the worker; the worker's cancellation hook ensures it
        # returns promptly at the next component boundary.
        if self._active_worker is not None:
            self._active_worker.request_cancellation()
            self._active_worker.wait(5_000)
        # Cancel + join any in-flight baseline-load worker. R7.11
        # contracts a cancellation affordance for slow loads;
        # closeEvent reuses it so the window can shut down promptly
        # without waiting for a 1024-baseline scan to finish.
        if self._baseline_load_worker is not None:
            self._baseline_load_worker.request_cancel()
            self._baseline_load_worker.wait(30_000)
        # Cancel + join any in-flight analysis worker. The
        # classification + analysis pipelines poll the cancellation
        # token between components and return partial reports
        # promptly, so closeEvent doesn't need a long wait budget.
        analysis_worker = getattr(self, "_analysis_worker", None)
        if analysis_worker is not None and analysis_worker.isRunning():
            analysis_worker.request_cancel()
            analysis_worker.wait(5_000)
        settings = QSettings("LOKI", "Desktop")
        settings.setValue("main_window/geometry", self.saveGeometry())
        settings.setValue("main_window/state", self.saveState())
        settings.setValue("main_window/splitter", self._splitter.saveState())
        super().closeEvent(a0)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_open_firmware(self) -> None:
        open_firmware(self)

    def _on_load_demo_data(self) -> None:
        load_demo_data(self)

    def _on_open_baseline(self) -> None:
        open_baseline(self)

    def _on_save_baseline(self) -> None:
        record = self._currently_selected_baseline()
        if record is None:
            QMessageBox.information(
                self,
                "Save Baseline",
                "Select a baseline tab in the workspace before saving.",
            )
            return
        save_baseline(self, record)

    def _on_extract_components(self) -> None:
        image = self._currently_selected_image()
        if image is None:
            QMessageBox.information(
                self,
                "Extract Firmware Components",
                "Open a firmware image first via File → Open Firmware Image.",
            )
            return
        extract_components(self, image)

    def _on_run_analysis(self) -> None:
        """Run the analysis pipeline against the current image's extraction."""
        from PyQt6.QtWidgets import QFileDialog

        from loki.gui.analysis_worker import AnalysisWorker

        image = self._currently_selected_image()
        if image is None:
            QMessageBox.information(
                self,
                "Run Analysis",
                "Open a firmware image first via File → Open Firmware Image.",
            )
            return

        image_key = self._image_key(image)
        result = self._last_results.get(image_key)
        if result is None:
            QMessageBox.information(
                self,
                "Run Analysis",
                "Extract components first via View → Extract Firmware Components.",
            )
            return

        baseline_path = QFileDialog.getExistingDirectory(
            self,
            "Select Baseline Directory",
            "",
        )
        if not baseline_path:
            return

        rules_path = QFileDialog.getExistingDirectory(
            self,
            "Select Rules Directory",
            "",
        )
        if not rules_path:
            return

        from pathlib import Path

        self._analyze_action.setEnabled(False)
        self._set_status_message("Running analysis…")
        worker = AnalysisWorker(
            result.manifest,
            Path(baseline_path),
            Path(rules_path),
            parent=self,
        )
        worker.finished_with_report.connect(self._on_analysis_finished)
        worker.errored.connect(self._on_analysis_errored)
        worker.finished.connect(lambda: self._set_status_message(None))
        worker.finished.connect(lambda: self._refresh_analyze_action_enabled())
        self._analysis_worker = worker
        worker.start()

    def _on_analysis_finished(self, report: object) -> None:
        """Handle successful analysis completion."""
        from loki.models import ImageAnalysisReport

        assert isinstance(report, ImageAnalysisReport)
        key = f"analysis:{report.report_id}"
        label = f"Analysis — {report.posture_rating.value} ({len(report.findings)} findings)"
        view = AnalysisView(report, parent=self._workspace)
        self._workspace.open_tab(key, label, view)
        self._navigation.add_entry(NavigationGroup.REPORTS, key, label)
        self._set_status_message(None)

    def _on_analysis_errored(self, exc: object) -> None:
        """Handle analysis failure.

        ``exc`` is one of the typed pipeline-error roots
        (``AnalysisError``, ``ClassificationPipelineError``,
        ``BaselineStoreError``) per the
        :class:`~loki.gui.analysis_worker.AnalysisWorker` contract,
        or a :class:`RuntimeError` wrapping any other exception.
        ``str(exc)`` is the operator-facing message in every case.
        """
        message = f"{type(exc).__name__}: {exc}"
        QMessageBox.warning(self, "Analysis Error", f"Analysis failed:\n{message}")
        self._set_status_message(None)

    def _refresh_analyze_action_enabled(self) -> None:
        """Toggle the View -> Run Analysis menu action's enabled state."""
        action = getattr(self, "_analyze_action", None)
        if action is None:
            return
        has_results = bool(self._last_results)
        action.setEnabled(has_results)

    def _on_load_fleet_report(self) -> None:
        """Open a FleetAnalysisReport JSON file and display it."""
        from PyQt6.QtWidgets import QFileDialog

        from loki.models.reports import FleetAnalysisReport

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Fleet Analysis Report",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if not path:
            return

        from pathlib import Path

        try:
            text = Path(path).read_text(encoding="utf-8")
            report = FleetAnalysisReport.model_validate_json(text)
        except Exception as exc:
            QMessageBox.warning(
                self,
                "Load Fleet Report",
                f"Failed to load fleet report:\n{exc}",
            )
            return

        key = f"fleet:{report.report_id}"
        label = f"Fleet — {report.fleet_id} ({report.image_count} images)"
        view = FleetAnalysisView(report, parent=self._workspace)
        self._workspace.open_tab(key, label, view)
        self._navigation.add_entry(NavigationGroup.REPORTS, key, label)

    def _on_about(self) -> None:
        try:
            version = importlib.metadata.version("loki")
        except importlib.metadata.PackageNotFoundError:  # pragma: no cover - dev install
            version = "unknown"
        QMessageBox.about(
            self,
            "About Loki",
            (
                f"<b>Loki</b> {version}<br>"
                "Firmware analysis platform.<br><br>"
                "<i>This GUI is scope-B scaffolding. The extraction, "
                "classification, and analysis pipelines are not yet implemented; "
                "use <b>View → Load Demo Data</b> to preview the workflow.</i>"
            ),
        )

    def _on_navigation_activated(self, group: str, key: str, label: str) -> None:
        view = self._lookup_view(group, key)
        if view is None:
            return
        self._workspace.open_tab(key, label, view)

    def _lookup_view(self, group: str, key: str) -> QWidget | None:
        if group == NavigationGroup.IMAGES:
            return self._image_views.get(key)
        if group == NavigationGroup.BASELINES:
            return self._baseline_views.get(key)
        if group == NavigationGroup.REPORTS:
            return self._report_views.get(key)
        return None

    # ------------------------------------------------------------------
    # Selection / extraction helpers
    # ------------------------------------------------------------------

    def _currently_selected_image(self) -> FirmwareImage | None:
        """Return the firmware image associated with the active workspace tab.

        Falls back to the last-added image if the active tab isn't a
        :class:`FirmwareImageView` — that's the typical case when the
        user double-clicks Extract right after opening a binary.
        """

        active = self._workspace.currentWidget()
        if isinstance(active, FirmwareImageView):
            return active.image
        # Fallback: pick any open image. Stable order = insertion order
        # so the most recently added image wins.
        if not self._images_by_key:
            return None
        last_key = next(reversed(self._images_by_key))
        return self._images_by_key[last_key]

    def _refresh_extract_action_enabled(self) -> None:
        """Toggle the View -> Extract Firmware Components menu action's enabled state.

        Disabled when no firmware image is loaded *or* when a
        background extraction is currently running. Re-enabled once
        the worker finishes.
        """
        action = getattr(self, "_extract_action", None)
        if action is None:
            return
        has_image = bool(self._images_by_key)
        idle = self._active_worker is None
        action.setEnabled(has_image and idle)

    # ------------------------------------------------------------------
    # Baseline integration helpers (R7)
    # ------------------------------------------------------------------

    @property
    def baseline_store(self) -> BaselineStore | None:
        """Return the active :class:`BaselineStore`, if any.

        Used by the open-baseline / save-baseline actions to access
        the store without going through the menu wiring. Tests can
        inject a different store via the constructor.
        """
        return self._baseline_store

    def _currently_selected_baseline(self) -> BaselineRecord | None:
        """Return the :class:`BaselineRecord` for the active workspace tab.

        Returns ``None`` when the active tab isn't a
        :class:`BaselineView` — Save Baseline is enabled only in
        that case (R7.5), so this should never return ``None`` from
        a click on the menu action, but the defensive branch keeps
        the signature honest.
        """
        active = self._workspace.currentWidget()
        if not isinstance(active, BaselineView):
            return None
        return active.baseline

    def _refresh_save_baseline_action_enabled(self) -> None:
        """R7.5: Save Baseline is enabled only when a BaselineView is active."""
        action = getattr(self, "_save_baseline_action", None)
        if action is None:
            return
        active = self._workspace.currentWidget()
        action.setEnabled(isinstance(active, BaselineView))

    def _refresh_cancel_baseline_load_action_enabled(self) -> None:
        """R7.11: Cancel Baseline Load is enabled only while a worker is running."""
        action = getattr(self, "_cancel_baseline_load_action", None)
        if action is None:
            return
        worker = self._baseline_load_worker
        action.setEnabled(worker is not None and not worker.is_cancel_requested())

    def _on_cancel_baseline_load(self) -> None:
        """R7.11: ask the running :class:`BaselineLoadWorker` to stop.

        Sets the worker's cancel flag, immediately disables the menu
        action so a frustrated user doesn't double-click, and updates
        the status bar so the partial-result outcome is visible. The
        worker's ``finished`` signal will eventually fire and reset
        the action through
        :meth:`_refresh_cancel_baseline_load_action_enabled`.
        """
        worker = self._baseline_load_worker
        if worker is None:
            return
        worker.request_cancel()
        self._refresh_cancel_baseline_load_action_enabled()
        self._set_status_message("Cancelling baseline load…")
        _LOGGER.info("baseline load cancellation requested by user")

    def _on_workspace_tab_changed(self, _index: int) -> None:
        """Re-evaluate the Save Baseline action when the active tab changes."""
        self._refresh_save_baseline_action_enabled()

    def _populate_baselines_from_store(self) -> None:
        """Run the baseline Discovery_Scan and seed the navigation pane.

        R7.1: load every Baseline_File from the Storage_Directory.
        R7.2: show "Loading baselines from {path}…" in the status bar
        for the duration of the load.
        R7.3: surface a non-blocking notification listing the
        quarantine count and log per-file reasons under
        ``loki.gui.baselines``.

        Dispatches to a background :class:`BaselineLoadWorker` when
        the constructor's ``background_load`` flag is ``True`` (the
        production default), or to a synchronous in-line load
        otherwise. The background path keeps the UI responsive on
        large Storage_Directories where the load duration approaches
        the R9.1 budget.
        """

        store = self._baseline_store
        if store is None:
            return

        self._set_status_message(f"Loading baselines from {store.storage_path}…")
        if self._background_load:
            self._spawn_baseline_load_worker(store)
        else:
            self._load_baselines_synchronous(store)

    def _spawn_baseline_load_worker(self, store: BaselineStore) -> None:
        """Construct + start a :class:`BaselineLoadWorker` for ``store``."""
        worker = BaselineLoadWorker(store, parent=self)
        worker.finished_with_result.connect(self._on_baseline_load_finished)
        worker.errored.connect(self._on_baseline_load_errored)
        worker.progress.connect(self._on_baseline_load_progress)
        worker.finished.connect(self._on_baseline_load_worker_finished)
        self._baseline_load_worker = worker
        self._refresh_cancel_baseline_load_action_enabled()
        worker.start()

    def _on_baseline_load_progress(self, event: object) -> None:
        """Update the status bar with per-file progress (R7.10)."""
        from loki.baseline import LoadProgressEvent

        if not isinstance(event, LoadProgressEvent):
            return
        self._set_status_message(
            f"Loading baselines… {event.index}/{event.total} ({event.path.name})"
        )

    def _load_baselines_synchronous(self, store: BaselineStore) -> None:
        """Run :meth:`BaselineStore.load` on the calling thread."""
        try:
            result = store.load()
        except BaselineStoreError as exc:
            self._handle_baseline_load_error(store, exc)
            return
        self._apply_baseline_load_result(store, result)
        self._set_status_message(None)

    def _on_baseline_load_finished(self, result: object) -> None:
        """Handle the worker's success path on the main thread."""
        # ``result`` is a :class:`LoadResult`; signal types are object
        # for Qt's queued-connection serializer.
        from loki.baseline import LoadResult

        store = self._baseline_store
        if store is None or not isinstance(result, LoadResult):
            return
        self._apply_baseline_load_result(store, result)
        self._set_status_message(None)

    def _on_baseline_load_errored(self, exc: object) -> None:
        """Handle the worker's error path on the main thread."""
        store = self._baseline_store
        if store is None or not isinstance(exc, BaselineStoreError):
            return
        self._handle_baseline_load_error(store, exc)
        self._set_status_message(None)

    def _on_baseline_load_worker_finished(self) -> None:
        """Reset worker state once ``QThread.finished`` fires."""
        worker = self._baseline_load_worker
        self._baseline_load_worker = None
        if worker is not None:
            worker.deleteLater()
        self._refresh_cancel_baseline_load_action_enabled()

    def _apply_baseline_load_result(
        self,
        store: BaselineStore,
        result: object,
    ) -> None:
        """Iterate ``result.registry`` and surface the quarantine count.

        Common to both the sync and async load paths.
        """
        # Late import keeps the LoadResult type local to where we need
        # the runtime check; the import doesn't trigger any side-effects
        # because ``loki.baseline`` is already loaded.
        from loki.baseline import LoadResult

        if not isinstance(result, LoadResult):  # pragma: no cover - defensive
            return

        for record in result.registry.baselines:
            self.add_baseline(record)

        if len(result.quarantine) > 0:
            # R7.3: surface the count + log per-file reasons.
            for entry in result.quarantine:
                _LOGGER.warning(
                    "baseline quarantine path=%s reason=%s",
                    entry.path,
                    entry.reason,
                )
            QMessageBox.information(
                self,
                "Baselines loaded with warnings",
                (
                    f"{len(result.quarantine)} baseline file(s) could not be loaded "
                    f"from {store.storage_path} and were quarantined. "
                    "See the loki.gui.baselines logger for per-file reasons."
                ),
            )

    def _handle_baseline_load_error(
        self,
        store: BaselineStore,
        exc: BaselineStoreError,
    ) -> None:
        """Render a typed load error as a warning dialog + log line."""
        QMessageBox.warning(
            self,
            "Could not load baselines",
            f"{store.storage_path}\n\n{exc}",
        )
        _LOGGER.warning(
            "baseline store load failed path=%s error=%s",
            store.storage_path,
            exc,
        )

    # ------------------------------------------------------------------
    # Worker signal handlers (run on the main thread via Qt queueing)
    # ------------------------------------------------------------------

    def _on_progress_event(self, event: ProgressEvent) -> None:
        """Reflect a :class:`ProgressEvent` into the status bar."""
        if self._active_worker_image is None:
            return
        basename = self._image_basename(self._active_worker_image)
        self._set_status_message(
            f"Extracting {basename}: {event.phase} "
            f"({event.component_index}/{event.components_estimated}) "
            f"{event.message}"
        )

    def _on_extraction_finished(self, result: ExtractionResult) -> None:
        """Handle the worker's success path: open an ``ExtractionView`` tab."""
        if self._active_worker_image is not None:
            self.add_extraction_result(self._active_worker_image, result)

    def _on_extraction_errored(self, exc: ExtractionPipelineError) -> None:
        """Handle the worker's error path: show a typed warning dialog."""
        from loki.extraction import (
            InvalidInputError,
            ManifestConstructionError,
        )

        if isinstance(exc, InvalidInputError):
            QMessageBox.warning(
                self,
                "Could not extract firmware components",
                f"{exc.path}\n\n{exc.message}",
            )
        elif isinstance(exc, ManifestConstructionError):
            QMessageBox.warning(
                self,
                "Manifest construction failed",
                exc.message,
            )
        else:
            QMessageBox.warning(
                self,
                "Extraction pipeline error",
                str(exc),
            )

    def _on_worker_finished(self) -> None:
        """Reset worker state once ``QThread.finished`` fires."""
        worker = self._active_worker
        self._active_worker = None
        self._active_worker_image = None
        self._set_status_message(None)
        self._refresh_extract_action_enabled()
        self._refresh_status_bar()
        if worker is not None:
            worker.deleteLater()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _image_key(image: FirmwareImage) -> str:
        return f"image:{image.image_id}"

    @staticmethod
    def _extraction_key(image: FirmwareImage, manifest: ExtractionManifest) -> str:
        return f"extraction:{image.image_id}:{manifest.extraction_timestamp.isoformat()}"

    @staticmethod
    def _image_basename(image: FirmwareImage) -> str:
        if image.file_path:
            return image.file_path.rsplit("/", 1)[-1]
        return image.file_hash[:12]  # pragma: no cover - file_path is required

    @staticmethod
    def _image_label(image: FirmwareImage, *, demo: bool) -> str:
        suffix = " (demo)" if demo else ""
        # Show file basename for compactness; fall back to first 12 chars of hash.
        if image.file_path:
            base = image.file_path.rsplit("/", 1)[-1]
        else:  # pragma: no cover - file_path is required
            base = image.file_hash[:12]
        return f"{base}{suffix}"
