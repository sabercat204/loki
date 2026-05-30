"""Cancellation token tests for the classification pipeline.

Covers Requirement 1.9: a cancel token returning ``True`` between
components stops the loop, records a cancellation
``ClassificationError(component_id=None, error_message=
"classification cancelled by caller")``, and returns the
partial ``ClassificationResult`` accumulated so far. Wave 5's
``test_api_contract.py`` covered the basics; this file pins
the precise partial-result invariants.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from loki.classification import classify_components
from loki.models import LOKI_NAMESPACE, ExtractedComponent
from loki.models.config import ClassificationConfig


def _config(rules_dir: Path) -> ClassificationConfig:
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


def _make_component_with_raw_file(*, tmp_path: Path, index: int) -> ExtractedComponent:
    raw_file = tmp_path / f"comp-{index}.bin"
    raw_file.write_bytes(b"\x00" * 64)
    return ExtractedComponent(
        component_id=uuid.uuid5(LOKI_NAMESPACE, f"cancel-test-{index}"),
        source_image_id=uuid.uuid5(LOKI_NAMESPACE, "cancel-image"),
        offset=f"0x{index * 0x1000:x}",
        size=64,
        raw_hash="0" * 64,
        component_type_hint="dxe_driver",
        guid=str(uuid.uuid5(LOKI_NAMESPACE, f"cancel-guid-{index}")),
        name=f"COMP_{index:03d}",
        raw_path=str(raw_file),
    )


# ---------------------------------------------------------------------------
# Cancel after exactly N components
# ---------------------------------------------------------------------------


def test_cancel_after_three_yields_exactly_three_records(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """A cancel token that returns False for the first three
    checks and True on the fourth yields exactly 3 records
    (for the three components that completed before
    cancellation) plus 1 cancellation error."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(10)]
    check_count = [0]

    def cancel_after_three() -> bool:
        check_count[0] += 1
        return check_count[0] > 3

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config, cancel=cancel_after_three)

    assert len(result.records) == 3
    cancellation_errors = [e for e in result.errors if e.component_id is None]
    assert len(cancellation_errors) == 1
    assert cancellation_errors[0].error_message == "classification cancelled by caller"


def test_cancelled_records_are_first_n_in_input_order(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """The records emitted before cancellation are the FIRST
    N components in input order — not arbitrary components."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(10)]
    check_count = [0]

    def cancel_after_two() -> bool:
        check_count[0] += 1
        return check_count[0] > 2

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config, cancel=cancel_after_two)

    record_ids = [r.component_id for r in result.records]
    expected_first_two = [components[0].component_id, components[1].component_id]
    assert record_ids == expected_first_two


# ---------------------------------------------------------------------------
# Always-cancel and never-cancel boundary cases
# ---------------------------------------------------------------------------


def test_always_cancel_yields_empty_records(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """A cancel token returning True on the very first check
    yields zero records and one cancellation error."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(5)]

    def always_cancel() -> bool:
        return True

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config, cancel=always_cancel)

    assert result.records == []
    cancellation_errors = [e for e in result.errors if e.component_id is None]
    assert len(cancellation_errors) == 1


def test_never_cancel_classifies_full_input(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """A cancel token that always returns False is
    indistinguishable from no token at all."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(5)]

    def never_cancel() -> bool:
        return False

    config = _config(synthetic_rules_dir)
    with_token = classify_components(components, config, cancel=never_cancel)
    without_token = classify_components(components, config)

    assert len(with_token.records) == len(without_token.records)
    assert len(with_token.records) == 5
    # Errors should match too (both classify the full input
    # successfully when components have readable raw_paths).
    assert len(with_token.errors) == len(without_token.errors)


def test_omitting_cancel_token_works_normally(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """Omitting the cancel token (the default) does not
    short-circuit; every component is classified."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(5)]
    config = _config(synthetic_rules_dir)
    result = classify_components(components, config)
    assert len(result.records) == 5
    assert result.errors == []


# ---------------------------------------------------------------------------
# Cancellation error properties
# ---------------------------------------------------------------------------


def test_cancellation_error_has_none_component_id(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """R1.9: the cancellation error carries
    ``component_id=None`` (it's a whole-run signal, not tied
    to any specific component)."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=0)]

    def always_cancel() -> bool:
        return True

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config, cancel=always_cancel)

    cancellation_errors = [e for e in result.errors if e.component_id is None]
    assert len(cancellation_errors) == 1
    assert cancellation_errors[0].component_id is None


def test_cancellation_error_message_is_documented(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """R1.9: the cancellation error's message is exactly
    ``"classification cancelled by caller"``. Downstream
    consumers can match on this string to distinguish the
    cancellation case from other whole-run-failure shapes."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=0)]

    def always_cancel() -> bool:
        return True

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config, cancel=always_cancel)

    cancellation_errors = [e for e in result.errors if e.component_id is None]
    assert len(cancellation_errors) == 1
    assert cancellation_errors[0].error_message == "classification cancelled by caller"


def test_cancellation_does_not_emit_records_for_skipped_components(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """The components that come AFTER the cancellation point
    do not appear in the records list."""

    components = [_make_component_with_raw_file(tmp_path=tmp_path, index=i) for i in range(5)]
    check_count = [0]

    def cancel_after_two() -> bool:
        check_count[0] += 1
        return check_count[0] > 2

    config = _config(synthetic_rules_dir)
    result = classify_components(components, config, cancel=cancel_after_two)

    record_ids = {r.component_id for r in result.records}
    skipped_ids = {components[i].component_id for i in range(2, 5)}
    # No skipped component appears in the records.
    assert not record_ids & skipped_ids


# ---------------------------------------------------------------------------
# Cancellation interacts cleanly with empty input
# ---------------------------------------------------------------------------


def test_cancel_with_empty_input_produces_empty_result(
    synthetic_rules_dir: Path,
) -> None:
    """An empty component sequence with a cancel token never
    triggers cancellation (the cancel token is checked at the
    top of the per-component loop, which never executes for
    empty input)."""

    def always_cancel() -> bool:
        return True

    config = _config(synthetic_rules_dir)
    result = classify_components([], config, cancel=always_cancel)
    assert result.records == []
    assert result.errors == []
