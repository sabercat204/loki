"""Tests for the classification exception hierarchy and error model.

Covers Requirements 9.1, 9.3, 9.4: typed exception hierarchy
rooted at ``ClassificationPipelineError``; per-component
``ClassificationError`` Pydantic model with non-empty message
validation and UTC timestamp.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from loki.classification import (
    ClassificationConfigError,
    ClassificationError,
    ClassificationPipelineError,
    ClassificationRuleError,
)

# ---------------------------------------------------------------------------
# Hierarchy + construction
# ---------------------------------------------------------------------------


def test_classification_pipeline_error_is_subclass_of_exception() -> None:
    assert issubclass(ClassificationPipelineError, Exception)


def test_classification_config_error_subclasses_pipeline_error() -> None:
    assert issubclass(ClassificationConfigError, ClassificationPipelineError)


def test_classification_rule_error_subclasses_pipeline_error() -> None:
    assert issubclass(ClassificationRuleError, ClassificationPipelineError)


def test_classification_config_error_carries_path_and_message() -> None:
    path = Path("/no/such/dir")
    err = ClassificationConfigError(path, "rules directory does not exist")
    assert err.path == path
    assert err.message == "rules directory does not exist"
    assert "rules directory does not exist" in str(err)
    assert str(path) in str(err)


def test_classification_config_error_accepts_str_path() -> None:
    err = ClassificationConfigError("/some/string/path", "boom")
    assert err.path == Path("/some/string/path")


def test_classification_rule_error_carries_path_rule_id_message() -> None:
    rule_path = Path("/rules/file.yaml")
    err = ClassificationRuleError(
        rule_path,
        "intel.management-engine.firmware",
        "rule_id charset violation",
    )
    assert err.path == rule_path
    assert err.rule_id == "intel.management-engine.firmware"
    assert err.message == "rule_id charset violation"
    rendered = str(err)
    assert "rule_id charset violation" in rendered
    assert "intel.management-engine.firmware" in rendered
    # ``str(Path)`` uses native path separators; assert the platform-native
    # rendering rather than a hard-coded POSIX literal.
    assert str(rule_path) in rendered


def test_classification_rule_error_accepts_none_rule_id() -> None:
    """When the rule_id itself is unparseable, rule_id is None and the rendered
    string should not mention rule_id at all."""
    err = ClassificationRuleError(
        Path("/rules/file.yaml"),
        None,
        "rule entry missing rule_id",
    )
    assert err.rule_id is None
    rendered = str(err)
    assert "rule entry missing rule_id" in rendered
    assert "rule_id=" not in rendered


# ---------------------------------------------------------------------------
# ClassificationError Pydantic model
# ---------------------------------------------------------------------------


def test_classification_error_constructs_with_documented_fields() -> None:
    cid = uuid.uuid4()
    ts = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    err = ClassificationError(
        component_id=cid,
        error_message="rule evaluation crashed: KeyError",
        timestamp=ts,
    )
    assert err.component_id == cid
    assert err.error_message == "rule evaluation crashed: KeyError"
    assert err.timestamp == ts


def test_classification_error_accepts_none_component_id_for_whole_run_failures() -> None:
    """R1.9 cancellation records component_id=None."""
    err = ClassificationError(
        component_id=None,
        error_message="classification cancelled by caller",
        timestamp=datetime.now(tz=UTC),
    )
    assert err.component_id is None


def test_classification_error_rejects_empty_message() -> None:
    with pytest.raises(ValidationError):
        ClassificationError(
            component_id=None,
            error_message="",
            timestamp=datetime.now(tz=UTC),
        )


def test_classification_error_rejects_whitespace_only_message() -> None:
    with pytest.raises(ValidationError):
        ClassificationError(
            component_id=None,
            error_message="   \t\n  ",
            timestamp=datetime.now(tz=UTC),
        )


def test_classification_error_round_trips_through_json() -> None:
    """The Pydantic model should round-trip without data loss."""
    cid = uuid.uuid4()
    ts = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    original = ClassificationError(
        component_id=cid,
        error_message="record validation failed: extraction_offset must match ^0x...",
        timestamp=ts,
    )
    payload = original.model_dump_json()
    restored = ClassificationError.model_validate_json(payload)
    assert restored == original
