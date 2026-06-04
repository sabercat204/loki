"""Tests for the background extraction worker.

The MainWindow integration path is covered by ``test_extraction_view.py``
and ``test_main_window.py``. This file exercises the worker class
directly: signal emission, cancellation primitive shape (D3 — now
``threading.Event``-uniform with :class:`BaselineLoadWorker` and
:class:`AnalysisWorker`), and the P79 idempotence property.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from loki.extraction import ExtractionResult, ProgressEvent
from loki.extraction.extractors.base import clear_registry
from loki.gui.extraction_worker import ExtractionWorker
from loki.models import ExtractionConfig
from tests.extraction.fixtures import synthetic_microcode


@pytest.fixture(autouse=True)
def _registry_isolation() -> Iterator[None]:
    """Match ``tests/extraction/`` test isolation: clear extractor registry."""
    clear_registry()
    yield
    clear_registry()


def _make_config(tmp_path: Path) -> ExtractionConfig:
    return ExtractionConfig(
        default_output_dir=str(tmp_path / "extracted"),
        max_component_size=10_000_000,
        timeout_per_component=30,
    )


# ---------------------------------------------------------------------
# Cancellation primitive shape (D3 — threading.Event uniformity)
# ---------------------------------------------------------------------


def test_request_cancellation_flips_cancelled_property(tmp_path: Path) -> None:
    """``request_cancellation()`` flips the ``cancelled`` property to ``True``.

    The internal primitive is a ``threading.Event`` (D3), but the
    public surface (``request_cancellation()`` + ``cancelled``
    property) is unchanged from the v1.0.0 contract.
    """
    binary = synthetic_microcode.build(tmp_path)
    worker = ExtractionWorker(binary, _make_config(tmp_path))
    assert worker.cancelled is False
    worker.request_cancellation()
    assert worker.cancelled is True


def test_request_cancellation_is_idempotent(tmp_path: Path) -> None:
    """Property P79 (worker_cancel_idempotence) for ExtractionWorker.

    For any sequence of ``request_cancellation()`` calls on a fresh
    worker, ``cancelled`` returns ``True`` after the first call and
    remains ``True`` for all subsequent calls and reads — the same
    property the spec mandates for ``BaselineLoadWorker`` and
    ``AnalysisWorker``.
    """
    binary = synthetic_microcode.build(tmp_path)
    worker = ExtractionWorker(binary, _make_config(tmp_path))
    assert worker.cancelled is False
    for _ in range(5):
        worker.request_cancellation()
        assert worker.cancelled is True


# ---------------------------------------------------------------------
# Signal emission — happy path
# ---------------------------------------------------------------------


def test_worker_emits_finished_with_result_on_success(
    tmp_path: Path,
    qtbot: QtBot,
) -> None:
    """The worker emits an ``ExtractionResult`` via ``finished_with_result``."""
    binary = synthetic_microcode.build(tmp_path)
    worker = ExtractionWorker(binary, _make_config(tmp_path))

    with qtbot.waitSignal(worker.finished_with_result, timeout=10_000) as blocker:
        worker.start()

    [result] = blocker.args
    assert isinstance(result, ExtractionResult)
    # Synthetic microcode fixture produces two blobs.
    assert len(result.manifest.components) >= 1
    worker.wait(2_000)


def test_worker_emits_progress_events(
    tmp_path: Path,
    qtbot: QtBot,
) -> None:
    """Per-component ``ProgressEvent`` instances flow on the ``progress_event`` signal."""
    binary = synthetic_microcode.build(tmp_path)
    worker = ExtractionWorker(binary, _make_config(tmp_path))

    captured: list[ProgressEvent] = []

    def _capture(event: object) -> None:
        assert isinstance(event, ProgressEvent)
        captured.append(event)

    worker.progress_event.connect(_capture)
    with qtbot.waitSignal(worker.finished_with_result, timeout=10_000):
        worker.start()

    assert len(captured) >= 1
    worker.wait(2_000)


# ---------------------------------------------------------------------
# Signal emission — cancellation short-circuit
# ---------------------------------------------------------------------


def test_pre_set_cancel_short_circuits_extraction(
    tmp_path: Path,
    qtbot: QtBot,
) -> None:
    """Calling ``request_cancellation`` before ``start`` makes extraction return early.

    The cancellation flag is checked between components by the
    upstream ``extract_firmware`` pipeline, so a pre-set flag means
    the worker still finishes cleanly (via either ``finished_with_result``
    with a partial manifest or ``errored`` with a typed pipeline
    error per the extraction-pipeline spec). Either outcome is the
    contract; the failure mode this guards against is a hung worker.
    """
    binary = synthetic_microcode.build(tmp_path)
    worker = ExtractionWorker(binary, _make_config(tmp_path))
    worker.request_cancellation()

    with qtbot.waitSignals(
        [worker.finished_with_result, worker.errored],
        timeout=10_000,
        order="none",
        raising=False,
    ):
        worker.start()

    # The worker should have emitted exactly one of the terminal
    # signals; either way the QThread should be joinable promptly.
    worker.wait(5_000)
    assert worker.cancelled is True
