"""Background worker for running classification + analysis pipeline."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from loki.models import (
    BaselineConfig,
    ClassificationConfig,
    ExtractionManifest,
)

__all__ = ["AnalysisWorker"]


class AnalysisWorker(QThread):
    """Run classify + analyze on a background thread.

    Emits ``finished_with_report`` on success, ``errored`` on failure.
    """

    finished_with_report = pyqtSignal(object)
    errored = pyqtSignal(str)

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

    def run(self) -> None:
        try:
            from loki.analysis import analyze_image
            from loki.baseline import BaselineStore
            from loki.classification import classify_components
            from loki.models.config import AnalysisConfig
            from loki.models.enums import SeverityLevel

            store = BaselineStore(
                BaselineConfig(storage_path=str(self._baseline_path), auto_match=True)
            )
            load_result = store.load()

            config = ClassificationConfig(
                taxonomy_version=self._taxonomy_version,
                confidence_threshold=0.6,
                rules_path=str(self._rules_path),
            )
            classification_result = classify_components(self._manifest.components, config)

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
            )
            self.finished_with_report.emit(report)
        except Exception as exc:
            self.errored.emit(f"{type(exc).__name__}: {exc}")
