"""Per-component error tests for the classification pipeline.

Covers Requirement 9 in detail: rule-evaluation crash, record
validation failure, rule-load errors raising rather than
landing in ``errors``, errors-empty contract on full success,
mixed records-and-errors interleaving, and UTC timestamps on
emitted ``ClassificationError`` instances.

Wave 5's ``test_pipeline.py`` covers the happy path; this
file covers the failure modes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from loki.classification import classify_components
from loki.classification.errors import (
    ClassificationConfigError,
    ClassificationRuleError,
)
from loki.classification.pipeline import ClassificationPipeline
from loki.models import LOKI_NAMESPACE, ExtractedComponent
from loki.models.config import ClassificationConfig


def _config(rules_dir: Path) -> ClassificationConfig:
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


def _make_component_with_raw_file(
    *,
    tmp_path: Path,
    index: int = 0,
    guid: str | None = None,
) -> ExtractedComponent:
    """Make a component with a real raw_path so signature detection
    runs without surfacing a missing-bytes error. The synthetic-
    components fixture has raw_path=None which would otherwise
    trigger R5.6 dual-record on every component."""
    raw_file = tmp_path / f"component-{index}.bin"
    raw_file.write_bytes(b"\x00" * 64)
    return ExtractedComponent(
        component_id=uuid.uuid5(LOKI_NAMESPACE, f"err-test-component-{index}"),
        source_image_id=uuid.uuid5(LOKI_NAMESPACE, "err-test-image"),
        offset=f"0x{(index * 0x1000):x}",
        size=64,
        raw_hash="0" * 64,
        component_type_hint="dxe_driver",
        guid=guid or str(uuid.uuid5(LOKI_NAMESPACE, f"err-comp-guid-{index}")),
        name=f"COMP_{index:03d}",
        raw_path=str(raw_file),
    )


# ---------------------------------------------------------------------------
# Rule-evaluation crash (R9.3)
# ---------------------------------------------------------------------------


def test_rule_evaluation_crash_records_typed_error_and_continues(
    synthetic_rules_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``matches`` raises during axis evaluation for one
    component, the pipeline records a ``ClassificationError``
    with the documented message shape and continues with the
    remaining components."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(3)]
    target_component_id = components[1].component_id

    # Monkeypatch matches to raise on the second component only.
    from loki.classification.rules.matcher import matches as real_matches

    def crashing_matches(rule: object, component: ExtractedComponent) -> bool:
        if component.component_id == target_component_id:
            raise RuntimeError("synthetic crash for testing")
        return real_matches(rule, component)  # type: ignore[arg-type]

    monkeypatch.setattr("loki.classification.classifier.matches", crashing_matches)

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config)

    # The crashed component produces no record; the other two do.
    assert len(result.records) == 2
    record_ids = {r.component_id for r in result.records}
    assert target_component_id not in record_ids

    # Exactly one ClassificationError was recorded for the crashed
    # component, with the documented message shape.
    crash_errors = [
        e
        for e in result.errors
        if e.component_id == target_component_id and "rule evaluation crashed" in e.error_message
    ]
    assert len(crash_errors) == 1
    assert "RuntimeError" in crash_errors[0].error_message


def test_rule_evaluation_crash_does_not_raise_out_of_entry_point(
    synthetic_rules_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R9.3: per-component failures NEVER raise out of
    ``classify_components`` — they are recorded inside
    ``result.errors``."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=0)]

    def always_crashing_matches(*args: object, **kwargs: object) -> bool:
        raise ValueError("always crashes")

    monkeypatch.setattr("loki.classification.classifier.matches", always_crashing_matches)

    config = _config(synthetic_rules_dir)
    # The call must not raise.
    result = classify_components(components, config)
    assert len(result.records) == 0
    assert len(result.errors) == 1
    assert "ValueError" in result.errors[0].error_message


# ---------------------------------------------------------------------------
# Record-construction validation failure (R9.3)
# ---------------------------------------------------------------------------


def test_record_validation_failure_records_typed_error(
    synthetic_rules_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the constructed ``ClassificationRecord`` fails
    Pydantic validation, the pipeline records a
    ``ClassificationError`` with the ``"record validation
    failed"`` message and continues.

    Approach: monkeypatch ``ClassificationRecord`` in the
    pipeline module so its constructor raises
    ``pydantic.ValidationError`` for one specific component.
    The pipeline catches this and routes through the R9.3
    failure path.
    """
    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=0)]
    target_id = components[0].component_id

    import loki.classification.pipeline
    from loki.models.classification import ClassificationRecord as RealRecord

    def poisoned_record_constructor(**kwargs: Any) -> RealRecord:
        if kwargs.get("component_id") == target_id:
            # Build a real ValidationError by passing an invalid
            # extraction_offset (which fails the model's field
            # validator).
            return RealRecord(**{**kwargs, "extraction_offset": "not_a_valid_hex_offset"})
        return RealRecord(**kwargs)

    monkeypatch.setattr(
        loki.classification.pipeline,
        "ClassificationRecord",
        poisoned_record_constructor,
    )

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config)

    assert len(result.records) == 0
    assert len(result.errors) >= 1
    validation_errors = [e for e in result.errors if "record validation failed" in e.error_message]
    assert len(validation_errors) == 1
    assert validation_errors[0].component_id == target_id


# ---------------------------------------------------------------------------
# Rule-load errors raise rather than landing in errors (R9.2)
# ---------------------------------------------------------------------------


def test_rule_load_failure_raises_typed_exception(
    tmp_path: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R9.2: rule-load failures are whole-run failures and
    SHALL raise as ``ClassificationConfigError``, not land in
    ``ClassificationResult.errors``."""

    bogus_rules = tmp_path / "no-such-dir"
    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(bogus_rules),
    )
    with pytest.raises(ClassificationConfigError):
        classify_components(synthetic_components, config)


def test_per_rule_validation_failure_raises_typed_exception(
    tmp_path: Path,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """A per-rule validation error in a rule file raises
    ``ClassificationRuleError`` rather than landing in
    ``result.errors``."""

    rules_dir = tmp_path / "bad-rules"
    rules_dir.mkdir()
    bad_rule_yaml = """\
taxonomy_version: "1.0.0"
rules:
  - rule_id: "Invalid.Uppercase.RuleId"
    axis: type
    matcher:
      guid: "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
    effect:
      label: UEFI_DRIVER
      confidence: 0.5
      method: RULE
"""
    (rules_dir / "bad.yaml").write_text(bad_rule_yaml)

    config = _config(rules_dir)
    with pytest.raises(ClassificationRuleError):
        classify_components(synthetic_components, config)


# ---------------------------------------------------------------------------
# Errors empty on full success (R9.5)
# ---------------------------------------------------------------------------


def test_errors_list_is_empty_when_all_components_classify_successfully(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """R9.5: when every component classifies successfully and
    none triggers the R5.6 dual-record path, ``errors`` is
    empty."""
    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(3)]
    config = _config(synthetic_rules_dir)
    result = classify_components(components, config)
    assert len(result.records) == 3
    assert result.errors == []


# ---------------------------------------------------------------------------
# Mixed records and errors interleave (R9.3)
# ---------------------------------------------------------------------------


def test_records_and_errors_interleave_when_some_components_fail(
    synthetic_rules_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One bad component does not hide the rest: when component
    indices 0 and 2 succeed and index 1 fails, the result has
    two records (for 0 and 2) and one error (for 1)."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(3)]
    failing_id = components[1].component_id

    from loki.classification.rules.matcher import matches as real_matches

    def selectively_crashing_matches(rule: object, component: ExtractedComponent) -> bool:
        if component.component_id == failing_id:
            raise RuntimeError("only this component fails")
        return real_matches(rule, component)  # type: ignore[arg-type]

    monkeypatch.setattr("loki.classification.classifier.matches", selectively_crashing_matches)

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config)

    assert len(result.records) == 2
    record_ids = [r.component_id for r in result.records]
    assert components[0].component_id in record_ids
    assert components[2].component_id in record_ids
    assert failing_id not in record_ids

    failure_errors = [e for e in result.errors if e.component_id == failing_id]
    assert len(failure_errors) == 1


# ---------------------------------------------------------------------------
# UTC timestamps (R9.4)
# ---------------------------------------------------------------------------


def test_classification_error_timestamp_is_utc(
    synthetic_rules_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R9.4: every emitted ``ClassificationError.timestamp``
    is in UTC."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=0)]

    def crashing_matches(*args: object, **kwargs: object) -> bool:
        raise RuntimeError("test crash")

    monkeypatch.setattr("loki.classification.classifier.matches", crashing_matches)

    before = datetime.now(tz=UTC)
    config = _config(synthetic_rules_dir)
    result = classify_components(components, config)
    after = datetime.now(tz=UTC)

    assert len(result.errors) == 1
    error_ts = result.errors[0].timestamp
    assert error_ts.tzinfo is not None
    assert error_ts.utcoffset() == datetime.now(tz=UTC).utcoffset()
    # Timestamp falls within the run window.
    assert before <= error_ts <= after


def test_cancellation_error_timestamp_is_utc(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """The cancellation error path also produces a UTC timestamp."""
    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=0)]

    def always_cancel() -> bool:
        return True

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config, cancel=always_cancel)

    cancellation_errors = [e for e in result.errors if e.component_id is None]
    assert len(cancellation_errors) == 1
    error_ts = cancellation_errors[0].timestamp
    assert error_ts.tzinfo is not None


# ---------------------------------------------------------------------------
# Pipeline construction errors (R9.1, R9.2)
# ---------------------------------------------------------------------------


def test_pipeline_construction_propagates_loader_errors(
    tmp_path: Path,
) -> None:
    """``ClassificationPipeline(config)`` propagates the
    loader's typed errors. R9.1: the entry point raises only
    subclasses of ``ClassificationPipelineError``."""

    bogus = tmp_path / "missing"
    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(bogus),
    )
    with pytest.raises(ClassificationConfigError):
        ClassificationPipeline(config)
