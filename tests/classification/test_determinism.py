"""Hypothesis property-based tests for classification determinism.

Covers Properties 35-38 (R8.1, R8.2, R8.3, R8.6, R8.7):

- Property 35: two runs on the same input + same Rule_Set
  produce equal records under ``model_dump(mode="json")`` after
  stripping ``timestamp``.
- Property 36: input order is preserved in the ``records`` list
  (subsequence by ``component_id``).
- Property 37: every emitted ``ClassificationRecord`` round-trips
  through ``model_validate_json(model_dump_json())`` losslessly.
- Property 38: re-classification is idempotent (same input
  twice produces equal records modulo timestamp).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.classification import ClassificationResult, classify_components
from loki.models import ExtractedComponent
from loki.models.classification import ClassificationRecord
from loki.models.config import ClassificationConfig
from tests.classification.fixtures import build_components, build_rule_files

# Hypothesis settings for full-pipeline properties: each example
# writes rule files to disk and runs classification, so we keep
# ``max_examples`` modest per the project convention (the
# baseline-persistence layer uses 25 for the same reason).
_FULL_PIPELINE_SETTINGS = settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    deadline=None,
)

# Strategy: small component counts to keep each example fast.
_component_count = st.integers(min_value=0, max_value=8)
_include_inner = st.booleans()


def _strip_timestamp(record_dump: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the record dump with ``timestamp`` removed."""
    return {k: v for k, v in record_dump.items() if k != "timestamp"}


def _config_for(rules_dir: Path) -> ClassificationConfig:
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


# ---------------------------------------------------------------------
# Property 35: same input + same Rule_Set → equal records modulo timestamp
# ---------------------------------------------------------------------


@given(count=_component_count, include_inner=_include_inner)
@_FULL_PIPELINE_SETTINGS
def test_property_35_two_runs_produce_equal_records(
    tmp_path_factory: Any,
    count: int,
    include_inner: bool,
) -> None:
    """R8.1: two classify_components runs on the same input
    produce records equal under model_dump(mode='json') after
    stripping timestamp."""
    tmp_path: Path = tmp_path_factory.mktemp("p35")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir)
    components = build_components(count=count, include_inner=include_inner)

    config = _config_for(rules_dir)
    first = classify_components(components, config)
    second = classify_components(components, config)

    first_dumps = [_strip_timestamp(r.model_dump(mode="json")) for r in first.records]
    second_dumps = [_strip_timestamp(r.model_dump(mode="json")) for r in second.records]
    assert first_dumps == second_dumps


# ---------------------------------------------------------------------
# Property 36: input order preservation
# ---------------------------------------------------------------------


@given(count=_component_count, include_inner=_include_inner)
@_FULL_PIPELINE_SETTINGS
def test_property_36_records_preserve_input_order(
    tmp_path_factory: Any,
    count: int,
    include_inner: bool,
) -> None:
    """R8.3 + R10.5: the ``records`` list, restricted to the
    components that produced records, is a prefix-subsequence
    of the input by ``component_id``."""
    tmp_path: Path = tmp_path_factory.mktemp("p36")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir)
    components = build_components(count=count, include_inner=include_inner)

    config = _config_for(rules_dir)
    result = classify_components(components, config)

    record_ids = [r.component_id for r in result.records]
    component_ids = [c.component_id for c in components]
    # Records' component_ids must form an in-order subsequence
    # of the input components' ids.
    iter_components = iter(component_ids)
    for record_id in record_ids:
        # Advance through component_ids until we find this record_id.
        while True:
            try:
                candidate = next(iter_components)
            except StopIteration:
                raise AssertionError(f"record id {record_id} not found in input order") from None
            if candidate == record_id:
                break


# ---------------------------------------------------------------------
# Property 37: JSON round-trip
# ---------------------------------------------------------------------


@given(count=_component_count, include_inner=_include_inner)
@_FULL_PIPELINE_SETTINGS
def test_property_37_records_round_trip_through_json(
    tmp_path_factory: Any,
    count: int,
    include_inner: bool,
) -> None:
    """R8.6: every emitted ClassificationRecord round-trips
    through model_validate_json(model_dump_json())."""
    tmp_path: Path = tmp_path_factory.mktemp("p37")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir)
    components = build_components(count=count, include_inner=include_inner)

    config = _config_for(rules_dir)
    result = classify_components(components, config)

    for record in result.records:
        payload = record.model_dump_json()
        restored = ClassificationRecord.model_validate_json(payload)
        assert restored.model_dump(mode="json") == record.model_dump(mode="json")


# ---------------------------------------------------------------------
# Property 38: idempotence
# ---------------------------------------------------------------------


@given(count=_component_count)
@_FULL_PIPELINE_SETTINGS
def test_property_38_reclassification_is_idempotent(
    tmp_path_factory: Any,
    count: int,
) -> None:
    """R8.7: re-running classification on the same input
    produces equal records modulo timestamp.

    This is structurally similar to Property 35 but emphasizes
    that calling the entry point repeatedly does not accumulate
    state in the rule set or matcher.
    """
    tmp_path: Path = tmp_path_factory.mktemp("p38")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir)
    components = build_components(count=count)

    config = _config_for(rules_dir)
    runs: list[ClassificationResult] = [classify_components(components, config) for _ in range(3)]

    first = [_strip_timestamp(r.model_dump(mode="json")) for r in runs[0].records]
    for subsequent_run in runs[1:]:
        subsequent = [_strip_timestamp(r.model_dump(mode="json")) for r in subsequent_run.records]
        assert subsequent == first


# ---------------------------------------------------------------------
# Errors are also deterministic (R8.1 second clause covers errors)
# ---------------------------------------------------------------------


@given(count=_component_count)
@_FULL_PIPELINE_SETTINGS
def test_errors_are_deterministic_across_runs(
    tmp_path_factory: Any,
    count: int,
) -> None:
    """The errors list has the same shape across two runs of the
    same input (modulo timestamp). Synthetic components have
    raw_path=None so every run produces the dual-record errors;
    this property pins that the errors are stable across runs."""
    tmp_path: Path = tmp_path_factory.mktemp("perr")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir)
    components: list[ExtractedComponent] = build_components(count=count)

    config = _config_for(rules_dir)
    first = classify_components(components, config)
    second = classify_components(components, config)

    first_ids = [e.component_id for e in first.errors]
    second_ids = [e.component_id for e in second.errors]
    first_msgs = [e.error_message for e in first.errors]
    second_msgs = [e.error_message for e in second.errors]

    assert first_ids == second_ids
    assert first_msgs == second_msgs
