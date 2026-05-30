"""Hypothesis property test for ClassificationRecord re-validation.

Covers Property 33 (R10.1): every emitted
``ClassificationRecord`` round-trips through
``ClassificationRecord.model_validate(record.model_dump(mode="json"))``
without losing fields. This pins the model layer's strict
validators on the records the pipeline produces.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.classification import classify_components
from loki.models.classification import ClassificationRecord
from loki.models.config import ClassificationConfig
from tests.classification.fixtures import build_components, build_rule_files

_FULL_PIPELINE_SETTINGS = settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    deadline=None,
)

_component_count = st.integers(min_value=0, max_value=8)


def _config_for(rules_dir: Path) -> ClassificationConfig:
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


@given(count=_component_count)
@_FULL_PIPELINE_SETTINGS
def test_property_33_records_pass_pydantic_revalidation(
    tmp_path_factory: Any,
    count: int,
) -> None:
    """R10.1: every emitted record passes
    ``ClassificationRecord.model_validate_json(record.model_dump_json())``
    without raising and without losing fields.

    Note: we round-trip via JSON rather than a Python dict
    because ``ClassificationRecord`` uses ``strict=True`` and
    rejects string values where its fields are typed as enums
    (e.g. ``method: ClassificationMethod``). The JSON path
    handles enum coercion correctly.
    """
    tmp_path: Path = tmp_path_factory.mktemp("p33")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir)
    components = build_components(count=count)

    result = classify_components(components, _config_for(rules_dir))

    for record in result.records:
        payload = record.model_dump_json()
        re_validated = ClassificationRecord.model_validate_json(payload)
        assert re_validated.model_dump(mode="json") == record.model_dump(mode="json")


@given(count=_component_count)
@_FULL_PIPELINE_SETTINGS
def test_property_33_records_round_trip_python_dict(
    tmp_path_factory: Any,
    count: int,
) -> None:
    """Stricter complement: round-trip via Python dict
    (``model_dump()`` returns enum / UUID / datetime instances;
    ``model_validate(...)`` accepts them under strict mode)."""
    tmp_path: Path = tmp_path_factory.mktemp("p33b")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir)
    components = build_components(count=count)

    result = classify_components(components, _config_for(rules_dir))

    for record in result.records:
        # Strict re-validation requires the native dump (not the
        # JSON-mode dump) so enums / UUIDs / datetimes pass through
        # unchanged.
        re_validated = ClassificationRecord.model_validate(record.model_dump())
        assert re_validated.model_dump() == record.model_dump()
