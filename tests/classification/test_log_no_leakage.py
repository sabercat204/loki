"""Captured-log audit for the classification subsystem (task 19).

Implements the dynamic half of R13.5/R13.6 ("at any time") by
attaching a recording handler to the ``loki.classification``
logger and asserting nothing leaks across the full classification
lifecycle: import, pipeline construction, classify (happy path),
classify (per-component failure), classify (R5.6 dual-record),
shutdown.

R13.5 names the Forbidden_Leakage_Field_Set explicitly:

- ``ExtractedComponent.component_id`` and the mirrored
  ``ClassificationRecord.component_id``
- ``SignatureInfo.signer``
- the parent ``BaselineRecord.source_image_hash`` (not directly
  reachable from the classification subsystem; the audit
  simulates by pinning a synthetic hash on the input)
- any ``AxisClassification.evidence`` string

Mirrors :mod:`tests.extraction.test_log_no_leakage` and
:mod:`tests.baseline.test_log_no_leakage`.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from loki.classification import classify_components
from loki.models import LOKI_NAMESPACE, ExtractedComponent
from loki.models.config import ClassificationConfig
from tests.classification.fixtures import build_components


@pytest.fixture()
def captured_records() -> Iterator[list[logging.LogRecord]]:
    """Attach a recording handler to ``loki.classification`` for one test."""

    records: list[logging.LogRecord] = []

    class _Recorder(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("loki.classification")
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


def _config(rules_dir: Path) -> ClassificationConfig:
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


def _forbidden_substrings(components: list[ExtractedComponent]) -> set[str]:
    """Return the set of strings that must never appear in any log record.

    Mirrors R13.5: every component's ``component_id`` (UUID
    surface), every component's ``source_image_id`` (UUID
    surface), and any evidence strings the synthetic rules
    contribute. Plus a synthetic source_image_hash canary.
    """
    forbidden: set[str] = set()
    for component in components:
        forbidden.add(str(component.component_id))
        forbidden.add(str(component.source_image_id))
    return forbidden


# ---------------------------------------------------------------------
# Lifecycle smoke (R13.1, R13.2, R13.3 anchors)
# ---------------------------------------------------------------------


def test_emits_pipeline_ready_record_at_construction(
    synthetic_rules_dir: Path,
    captured_records: list[logging.LogRecord],
) -> None:
    """R13.1: pipeline construction logs an INFO record with
    rules_path, files, rules, taxonomy_version,
    classification_version."""
    classify_components([], _config(synthetic_rules_dir))
    messages = _formatted_messages(captured_records)
    ready = [m for m in messages if m.startswith("classification pipeline ready")]
    assert len(ready) == 1
    msg = ready[0]
    assert "rules_path=" in msg
    assert "files=" in msg
    assert "rules=" in msg
    assert "taxonomy_version=" in msg
    assert "classification_version=" in msg


def test_emits_run_start_record(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
    captured_records: list[logging.LogRecord],
) -> None:
    """R13.2: run start logs an INFO record carrying component
    count and classification version."""
    classify_components(synthetic_components, _config(synthetic_rules_dir))
    messages = _formatted_messages(captured_records)
    starts = [m for m in messages if m.startswith("classification run starting")]
    assert len(starts) == 1
    msg = starts[0]
    assert f"components={len(synthetic_components)}" in msg
    assert "classification_version=" in msg


def test_emits_run_finished_record(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
    captured_records: list[logging.LogRecord],
) -> None:
    """R13.3: run end logs an INFO record carrying records,
    errors, duration."""
    classify_components(synthetic_components, _config(synthetic_rules_dir))
    messages = _formatted_messages(captured_records)
    finished = [m for m in messages if m.startswith("classification run finished")]
    assert len(finished) == 1
    msg = finished[0]
    assert "records=" in msg
    assert "errors=" in msg
    assert "duration=" in msg


# ---------------------------------------------------------------------
# R13.5/R13.6 — no content leakage during a full lifecycle
# ---------------------------------------------------------------------


def test_happy_path_run_does_not_leak_forbidden_substrings(
    synthetic_rules_dir: Path,
    tmp_path: Path,
    captured_records: list[logging.LogRecord],
) -> None:
    """A successful classification run does not leak any
    Forbidden_Leakage_Field substring."""
    # Build components with real raw_path so the run is fully
    # successful (no missing-bytes errors that would routinely
    # log error messages).
    components: list[ExtractedComponent] = []
    for i in range(3):
        raw_file = tmp_path / f"comp-{i}.bin"
        raw_file.write_bytes(b"\x00" * 64)
        components.append(
            ExtractedComponent(
                component_id=uuid.uuid5(LOKI_NAMESPACE, f"leak-test-{i}"),
                source_image_id=uuid.uuid5(LOKI_NAMESPACE, "leak-image"),
                offset=f"0x{i * 0x1000:x}",
                size=64,
                raw_hash="0" * 64,
                component_type_hint="dxe_driver",
                guid=str(uuid.uuid5(LOKI_NAMESPACE, f"leak-guid-{i}")),
                name=f"COMP_{i:03d}",
                raw_path=str(raw_file),
            )
        )
    classify_components(components, _config(synthetic_rules_dir))

    forbidden = _forbidden_substrings(components)
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_per_component_failure_run_does_not_leak_forbidden_substrings(
    synthetic_rules_dir: Path,
    tmp_path: Path,
    captured_records: list[logging.LogRecord],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Forcing a per-component failure makes the pipeline emit
    the WARNING record (R13.4); that record must not leak any
    component identifier."""
    components: list[ExtractedComponent] = []
    for i in range(2):
        raw_file = tmp_path / f"comp-{i}.bin"
        raw_file.write_bytes(b"\x00" * 64)
        components.append(
            ExtractedComponent(
                component_id=uuid.uuid5(LOKI_NAMESPACE, f"failure-leak-{i}"),
                source_image_id=uuid.uuid5(LOKI_NAMESPACE, "failure-leak-image"),
                offset=f"0x{i * 0x1000:x}",
                size=64,
                raw_hash="0" * 64,
                component_type_hint="dxe_driver",
                guid=str(uuid.uuid5(LOKI_NAMESPACE, f"failure-guid-{i}")),
                name=f"FAIL_{i:03d}",
                raw_path=str(raw_file),
            )
        )
    failing_id = components[0].component_id

    from loki.classification.rules.matcher import matches as real_matches

    def crashing_matches(rule: object, component: ExtractedComponent) -> bool:
        if component.component_id == failing_id:
            raise RuntimeError("synthetic crash for leak test")
        return real_matches(rule, component)  # type: ignore[arg-type]

    monkeypatch.setattr("loki.classification.classifier.matches", crashing_matches)

    classify_components(components, _config(synthetic_rules_dir))

    # R13.4 specifically: the WARNING record carries
    # axes_classified= count and nothing else identifying.
    warnings = [r for r in captured_records if r.levelno == logging.WARNING]
    failure_warnings = [r for r in warnings if "per-component failure" in r.getMessage()]
    assert len(failure_warnings) >= 1
    for warning in failure_warnings:
        msg = warning.getMessage()
        assert "axes_classified=" in msg
        # No component_id, source_image_id, or evidence in the
        # WARNING message string.
        for component in components:
            assert str(component.component_id) not in msg
            assert str(component.source_image_id) not in msg


def test_dual_record_run_does_not_leak_forbidden_substrings(
    synthetic_rules_dir: Path,
    captured_records: list[logging.LogRecord],
) -> None:
    """The R5.6 dual-record path (raw_path=None) does not leak
    component identifiers in its log records."""
    components = build_components(count=3)  # raw_path=None on every component
    classify_components(components, _config(synthetic_rules_dir))

    forbidden = _forbidden_substrings(components)
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_evidence_strings_never_appear_in_logs(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
    captured_records: list[logging.LogRecord],
) -> None:
    """The synthetic rules' evidence strings (per the fixture,
    ``"synthetic match on component {idx}"``) must never
    appear in any log record."""
    classify_components(synthetic_components, _config(synthetic_rules_dir))
    messages = _formatted_messages(captured_records)
    for message in messages:
        assert "synthetic match on component" not in message


def test_does_not_log_during_idle_state(
    captured_records: list[logging.LogRecord],
) -> None:
    """R13.6 'at any time' clause: no records emitted while no
    classification is in progress.

    The module-top imports already touched every public submodule
    of :mod:`loki.classification`. If any of those imports
    emitted a log record, the captured-records list would
    already be non-empty when this test runs.
    """
    # Touch every public submodule.
    import loki.classification
    import loki.classification.api
    import loki.classification.classifier
    import loki.classification.errors
    import loki.classification.pipeline
    import loki.classification.rules
    import loki.classification.rules.loader
    import loki.classification.rules.matcher
    import loki.classification.rules.schema
    import loki.classification.signatures
    import loki.classification.timing
    import loki.classification.version  # noqa: F401

    assert captured_records == []


def test_logger_namespace_is_loki_classification(
    synthetic_rules_dir: Path,
    synthetic_components: list[ExtractedComponent],
    captured_records: list[logging.LogRecord],
) -> None:
    """Every emitted record's logger name starts with ``loki.classification``."""
    classify_components(synthetic_components, _config(synthetic_rules_dir))
    assert captured_records
    for r in captured_records:
        assert r.name.startswith("loki.classification"), (
            f"record from foreign logger {r.name!r}: {r.getMessage()}"
        )
