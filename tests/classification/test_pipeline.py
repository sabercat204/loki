"""Tests for the internal ``ClassificationPipeline``.

Covers the happy-path classify flow per Task 12: synthetic
components + synthetic rules produce records in input order,
with deterministic axis selections, and the model layer's
auto-computed ``composite_confidence`` and ``needs_review``
fields populate correctly.

Per-component error paths (Task 14), the R5.6 dual-record
contract (Task 15), inner-component handling (Task 16), and
the progress + cancellation callbacks (Task 17) get their own
focused test files in Wave 6.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loki.classification.pipeline import ClassificationPipeline
from loki.classification.version import CLASSIFICATION_VERSION
from loki.models import ExtractedComponent
from loki.models.classification import ClassificationRecord
from loki.models.config import ClassificationConfig


@pytest.fixture
def pipeline_config(synthetic_rules_dir: Path) -> ClassificationConfig:
    """Build a ClassificationConfig pointing at the synthetic rules."""
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(synthetic_rules_dir),
    )


def test_pipeline_construction_loads_rules(
    pipeline_config: ClassificationConfig,
) -> None:
    """Pipeline construction loads the Rule_Set from disk."""
    pipeline = ClassificationPipeline(pipeline_config)
    # Implementation detail: the pipeline holds the rules. We
    # don't poke at private state in tests, but classifying any
    # input proves the rules loaded.
    result = pipeline.classify([])
    assert result.records == []
    assert result.errors == []


def test_classify_produces_one_record_per_component(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """Happy path: every input component produces one record.

    Note: the synthetic components have ``raw_path=None``, so
    every component also produces a missing-bytes
    ``ClassificationError`` per the R5.6 dual-record contract.
    See :func:`test_classify_with_dual_record_for_missing_raw_path`
    for explicit dual-record coverage.
    """
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    assert len(result.records) == len(synthetic_components)
    # R5.6 dual-record: one missing-bytes error per component.
    assert len(result.errors) == len(synthetic_components)
    for error in result.errors:
        assert "raw_path missing" in error.error_message


def test_classify_preserves_input_order(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R8.3 / R10.5: records emitted in input order."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    component_ids = [c.component_id for c in synthetic_components]
    record_ids = [r.component_id for r in result.records]
    assert record_ids == component_ids


def test_classify_records_have_validated_pydantic_shapes(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """Property 33: every emitted record passes Pydantic strict
    validation. Re-validating via model_dump → model_validate
    proves the records survive the round-trip without
    losing fields."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    for record in result.records:
        assert isinstance(record, ClassificationRecord)
        # Re-validate by round-tripping through JSON.
        round_tripped = ClassificationRecord.model_validate_json(record.model_dump_json())
        assert round_tripped == record


def test_classify_records_carry_run_started_timestamp(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R1.6 + R8.1: every record carries the same run-start
    timestamp (so two records in the same run share the same
    ``timestamp`` field)."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    timestamps = {r.timestamp for r in result.records}
    assert len(timestamps) == 1


def test_classify_records_carry_classification_version(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R1.5: every record carries the pipeline's semver."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    for record in result.records:
        assert record.classification_version == CLASSIFICATION_VERSION


def test_classify_records_preserve_component_ids(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R10.2: ``ClassificationRecord.component_id`` equals the
    input component's ``component_id``; same for
    ``source_image_id`` and ``extraction_offset``."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    for component, record in zip(synthetic_components, result.records, strict=True):
        assert record.component_id == component.component_id
        assert record.source_image_id == component.source_image_id
        assert record.extraction_offset == component.offset


def test_classify_axis_selections_are_deterministic(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R8.1 / R8.2: two runs on the same input + same rules
    produce the same axis classifications (modulo timestamp)."""
    pipeline = ClassificationPipeline(pipeline_config)
    first = pipeline.classify(synthetic_components)
    second = pipeline.classify(synthetic_components)
    assert len(first.records) == len(second.records)
    for r1, r2 in zip(first.records, second.records, strict=True):
        assert r1.type_axis == r2.type_axis
        assert r1.vendor_axis == r2.vendor_axis
        assert r1.security_axis == r2.security_axis
        assert r1.mutability_axis == r2.mutability_axis
        assert r1.composite_confidence == r2.composite_confidence
        assert r1.needs_review == r2.needs_review


def test_classify_records_have_composite_confidence_from_model_layer(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R4.9: the model layer auto-computes
    ``composite_confidence = min(...)`` and
    ``needs_review = composite_confidence < 0.60``. The pipeline
    relies on this and never overrides it."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    for record in result.records:
        expected = min(
            record.type_axis.confidence,
            record.vendor_axis.confidence,
            record.security_axis.confidence,
            record.mutability_axis.confidence,
        )
        assert record.composite_confidence == expected
        assert record.needs_review == (expected < 0.60)


def test_classify_records_have_signature_info_with_v1_defaults(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R5.2-R5.4: ``verified=False``, ``signer=None``,
    ``cert_expiry=None`` for every emitted record in v1.
    Synthetic components have ``raw_path=None``, so
    ``present`` is also False."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    for record in result.records:
        assert record.signature_info is not None
        assert record.signature_info.verified is False
        assert record.signature_info.signer is None
        assert record.signature_info.cert_expiry is None
        # Synthetic components have raw_path=None -> present is False.
        assert record.signature_info.present is False


def test_classify_records_have_empty_cve_matches(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R6.1: ``cve_matches`` is the empty list ``[]`` in v1."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    for record in result.records:
        assert record.cve_matches == []


def test_classify_records_have_empty_overrides_and_suspicion_triggers(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R10.3 / R10.4: ``overrides`` and ``suspicion_triggers``
    are empty lists in v1."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    for record in result.records:
        assert record.overrides == []
        assert record.suspicion_triggers == []


def test_classify_with_dual_record_for_missing_raw_path(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """R5.6: synthetic components have raw_path=None, so each
    component produces both a record (with all four axes
    classified) AND a missing-bytes ClassificationError. This
    is the dual-record contract.

    With the default 4-component fixture, that's 4 records and
    4 errors, and every error references one of the input
    component_ids."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    assert len(result.records) == len(synthetic_components)
    assert len(result.errors) == len(synthetic_components)
    error_component_ids = {e.component_id for e in result.errors}
    component_ids = {c.component_id for c in synthetic_components}
    assert error_component_ids == component_ids
    for error in result.errors:
        assert "raw_path missing" in error.error_message


def test_classify_records_dump_to_json_losslessly(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """Property 37: every emitted ClassificationRecord round-trips
    through JSON without data loss."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    for record in result.records:
        payload = record.model_dump_json()
        restored = ClassificationRecord.model_validate_json(payload)
        assert restored.model_dump() == record.model_dump()


def test_classify_records_axis_classifications_link_to_known_rule_ids(
    pipeline_config: ClassificationConfig,
    synthetic_components: list[ExtractedComponent],
) -> None:
    """When a rule fires, the resulting AxisClassification carries
    the winning rule's ``rule_id``. The synthetic-rules fixture
    seeds rules whose matchers fire on the synthetic components,
    so at least some axes should carry non-None rule_ids."""
    pipeline = ClassificationPipeline(pipeline_config)
    result = pipeline.classify(synthetic_components)
    rule_ids: set[str | None] = set()
    for record in result.records:
        rule_ids.add(record.type_axis.rule_id)
        rule_ids.add(record.vendor_axis.rule_id)
        rule_ids.add(record.security_axis.rule_id)
        rule_ids.add(record.mutability_axis.rule_id)
    # At least one axis fired across the 4 components.
    non_none_rule_ids = {r for r in rule_ids if r is not None}
    assert len(non_none_rule_ids) > 0
    # All non-None rule_ids should be from the synthetic fixture.
    for rule_id in non_none_rule_ids:
        assert rule_id.startswith("synthetic.")
