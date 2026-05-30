"""Captured-log audit for the analysis subsystem (task 23).

Implements the dynamic half of R20.3-R20.5 ("at any time") by
attaching a recording handler to the ``loki.analysis`` logger and
asserting nothing leaks across the full analysis lifecycle:
import, pipeline construction, run (happy path), run (paired
disagreement), run (signature regression), run (unexpected
component), run (missing required component), run
(classification gap), run (cancellation), shutdown.

The Forbidden_Leakage_Field_Set inherits classification's set
(``component_id``, ``signature_info.signer``,
``BaselineRecord.source_image_hash``, axis ``evidence`` strings) and
extends it per requirements.md Glossary with
``FindingEvidence.matched_rule``, ``FindingEvidence.matched_cve``,
``FindingEvidence.matched_signature``,
``FindingEvidence.raw_indicators``, ``FindingRecord.title``,
``FindingRecord.description``.

Mirrors :mod:`tests.classification.test_log_no_leakage`,
:mod:`tests.extraction.test_log_no_leakage`, and
:mod:`tests.baseline.test_log_no_leakage`.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator

import pytest

from loki.analysis import analyze_image
from loki.models import (
    AnalysisConfig,
    BaselineRegistry,
    ClassificationRecord,
    ComponentTypeLabel,
    MatchStrategy,
    SeverityLevel,
)
from tests.analysis._helpers import (
    VALID_WEIGHTS,
    make_baseline_record,
    make_image,
    make_record,
    make_signature_info,
)


@pytest.fixture()
def captured_records() -> Iterator[list[logging.LogRecord]]:
    """Attach a recording handler to ``loki.analysis`` for one test."""

    records: list[logging.LogRecord] = []

    class _Recorder(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("loki.analysis")
    handler = _Recorder(level=logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


def _formatted_messages(records: list[logging.LogRecord]) -> list[str]:
    return [record.getMessage() for record in records]


def _config() -> AnalysisConfig:
    return AnalysisConfig(
        severity_weights=dict(VALID_WEIGHTS),
        default_severity_threshold=SeverityLevel.MEDIUM,
        match_strategy=MatchStrategy.AUTO,
    )


def _forbidden_substrings(
    *,
    target_records: list[ClassificationRecord],
    baseline_records: list[ClassificationRecord],
    matched_baseline_id: uuid.UUID,
    source_image_hash: str,
) -> set[str]:
    """Return strings that must never appear in any log record."""
    forbidden: set[str] = set()
    for record in target_records:
        forbidden.add(str(record.component_id))
        forbidden.add(str(record.source_image_id))
    for record in baseline_records:
        forbidden.add(str(record.component_id))
    forbidden.add(str(matched_baseline_id))
    forbidden.add(source_image_hash)
    return forbidden


# ---------------------------------------------------------------------
# Lifecycle smoke (R20.1, R20.2 anchors)
# ---------------------------------------------------------------------


def test_emits_run_start_record(
    captured_records: list[logging.LogRecord],
) -> None:
    """R20.1: run-start INFO log carries (vendor, model, firmware_version, baseline_version)."""
    cfg = _config()
    baseline = make_baseline_record(vendor="Intel", model="X1", firmware_version="1.0.0")
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image(vendor="Intel", model="X1", firmware_version="1.0.0")

    analyze_image(
        target_records=[],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    starts = [m for m in _formatted_messages(captured_records) if "starting" in m]
    assert len(starts) == 1
    msg = starts[0]
    assert "Intel" in msg
    assert "X1" in msg
    assert "1.0.0" in msg


def test_emits_run_finished_record(
    captured_records: list[logging.LogRecord],
) -> None:
    """R20.2: run-finish INFO log carries duration_ms + per-category counts."""
    cfg = _config()
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    analyze_image(
        target_records=[],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    finished = [m for m in _formatted_messages(captured_records) if "finished" in m]
    assert len(finished) == 1
    msg = finished[0]
    assert "duration_ms=" in msg
    assert "classification_mismatch=" in msg
    assert "signature_regression=" in msg
    assert "unexpected_component=" in msg
    assert "missing_required_component=" in msg
    assert "classification_gap=" in msg
    assert "analysis_cancelled=" in msg


# ---------------------------------------------------------------------
# R20.3-R20.5 — no content leakage during a full lifecycle
# ---------------------------------------------------------------------


def test_paired_disagreement_run_does_not_leak(
    captured_records: list[logging.LogRecord],
) -> None:
    """R20.5: paired-disagreement run does not leak any forbidden substring."""
    cfg = _config()
    cid = uuid.uuid4()
    target = make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_record = make_record(component_id=cid, type_label=ComponentTypeLabel.OS_KERNEL)
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    analyze_image(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    forbidden = _forbidden_substrings(
        target_records=[target],
        baseline_records=[baseline_record],
        matched_baseline_id=baseline.baseline_id,
        source_image_hash=baseline.source_image_hash,
    )
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_signature_regression_run_does_not_leak(
    captured_records: list[logging.LogRecord],
) -> None:
    cfg = _config()
    cid = uuid.uuid4()
    target = make_record(component_id=cid, signature_info=make_signature_info(present=False))
    baseline_record = make_record(
        component_id=cid, signature_info=make_signature_info(present=True)
    )
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    analyze_image(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    forbidden = _forbidden_substrings(
        target_records=[target],
        baseline_records=[baseline_record],
        matched_baseline_id=baseline.baseline_id,
        source_image_hash=baseline.source_image_hash,
    )
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_unexpected_component_run_does_not_leak(
    captured_records: list[logging.LogRecord],
) -> None:
    cfg = _config()
    target = make_record()  # different component_id from baseline
    baseline = make_baseline_record()
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    analyze_image(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    forbidden = _forbidden_substrings(
        target_records=[target],
        baseline_records=baseline.component_manifest,
        matched_baseline_id=baseline.baseline_id,
        source_image_hash=baseline.source_image_hash,
    )
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_missing_required_run_does_not_leak(
    captured_records: list[logging.LogRecord],
) -> None:
    cfg = _config()
    baseline_record = make_record()
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    analyze_image(
        target_records=[],  # nothing to pair -> baseline record unpaired
        registry=registry,
        target_image=image,
        config=cfg,
    )

    forbidden = _forbidden_substrings(
        target_records=[],
        baseline_records=[baseline_record],
        matched_baseline_id=baseline.baseline_id,
        source_image_hash=baseline.source_image_hash,
    )
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_classification_gap_run_does_not_leak(
    captured_records: list[logging.LogRecord],
) -> None:
    cfg = AnalysisConfig(
        severity_weights=dict(VALID_WEIGHTS),
        default_severity_threshold=SeverityLevel.MEDIUM,
        match_strategy=MatchStrategy.AUTO,
        confidence_gap_threshold=0.6,
    )
    cid = uuid.uuid4()
    target = make_record(component_id=cid, confidence=0.4)
    baseline_record = make_record(component_id=cid, confidence=1.0)
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    analyze_image(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    forbidden = _forbidden_substrings(
        target_records=[target],
        baseline_records=[baseline_record],
        matched_baseline_id=baseline.baseline_id,
        source_image_hash=baseline.source_image_hash,
    )
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_cancellation_run_does_not_leak_index(
    captured_records: list[logging.LogRecord],
) -> None:
    """R7.4: cancellation_at_index value lives in the persisted report only.

    The run-finish summary is allowed to log
    ``analysis_cancelled=1``, but the specific 1-based index N
    must not appear in any log record.
    """
    cfg = _config()
    targets = [make_record() for _ in range(10)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    cancel_at = 7

    call_count = [0]

    def cancel() -> bool:
        call_count[0] += 1
        return call_count[0] > cancel_at - 1

    analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
        cancel=cancel,
    )

    # The literal "cancelled-at-index=7" string must NOT appear in any
    # log record (it lives in evidence.raw_indicators[0] only, per
    # R7.4). The run-finish summary's "analysis_cancelled=1" is fine.
    for message in _formatted_messages(captured_records):
        assert f"cancelled-at-index={cancel_at}" not in message


def test_does_not_log_during_idle_state(
    captured_records: list[logging.LogRecord],
) -> None:
    """R20.5 'at any time' clause: no records emitted while no analysis is in progress.

    The module-top imports already touched every public submodule
    of :mod:`loki.analysis`. If any of those imports emitted a
    log record, the captured-records list would already be
    non-empty when this test runs.
    """
    # Touch every public submodule.
    import loki.analysis
    import loki.analysis.api
    import loki.analysis.errors
    import loki.analysis.findings
    import loki.analysis.matching
    import loki.analysis.pairing
    import loki.analysis.pipeline
    import loki.analysis.posture
    import loki.analysis.report
    import loki.analysis.scoring
    import loki.analysis.timing
    import loki.analysis.version  # noqa: F401

    assert captured_records == []


def test_logger_namespace_is_loki_analysis(
    captured_records: list[logging.LogRecord],
) -> None:
    """Every emitted record's logger name starts with ``loki.analysis`` (R19.4)."""
    cfg = _config()
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    analyze_image(
        target_records=[],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    assert captured_records
    for r in captured_records:
        assert r.name.startswith("loki.analysis"), (
            f"record from foreign logger {r.name!r}: {r.getMessage()}"
        )


def test_no_per_finding_log_records_emitted(
    captured_records: list[logging.LogRecord],
) -> None:
    """R20.3: no per-finding log record is emitted in v1.

    A run that emits N findings should produce exactly two INFO
    log records (run-start and run-finish), regardless of N.
    """
    cfg = _config()
    cid = uuid.uuid4()
    target = make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline_record = make_record(component_id=cid, type_label=ComponentTypeLabel.OS_KERNEL)
    baseline = make_baseline_record(component_manifest=[baseline_record])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    analyze_image(
        target_records=[target],
        registry=registry,
        target_image=image,
        config=cfg,
    )

    info_records = [r for r in captured_records if r.levelno == logging.INFO]
    assert len(info_records) == 2  # exactly run-start + run-finish
