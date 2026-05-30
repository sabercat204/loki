"""R5.6 dual-record contract tests.

Verifies Property 42: when a component's bytes are unreadable,
the pipeline emits both a ``ClassificationRecord`` (with
``signature_info.present=False`` and all four axes classified)
AND a ``ClassificationError`` for the same ``component_id``.
This is the only contracted v1 case where a single component
appears in both ``records`` and ``errors`` lists.

Wave 5's ``test_pipeline.py`` covered the ``raw_path=None``
variant; this file expands to the file-unreadable variant
and pins the precise dual-record invariants.
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


def _component(
    *,
    index: int = 0,
    raw_path: str | None = None,
) -> ExtractedComponent:
    """Build a component whose raw_path drives the dual-record case."""
    return ExtractedComponent(
        component_id=uuid.uuid5(LOKI_NAMESPACE, f"dual-record-test-{index}"),
        source_image_id=uuid.uuid5(LOKI_NAMESPACE, "dual-record-image"),
        offset=f"0x{(index * 0x1000):x}",
        size=64,
        raw_hash="0" * 64,
        component_type_hint="dxe_driver",
        guid=str(uuid.uuid5(LOKI_NAMESPACE, f"dual-record-guid-{index}")),
        name=f"COMP_{index:03d}",
        raw_path=raw_path,
    )


# ---------------------------------------------------------------------------
# raw_path = None variant
# ---------------------------------------------------------------------------


def test_raw_path_none_emits_record_and_error_for_same_component(
    synthetic_rules_dir: Path,
) -> None:
    """When raw_path is None, the component appears in BOTH
    records and errors with the same component_id."""

    component = _component(raw_path=None)
    config = _config(synthetic_rules_dir)
    result = classify_components([component], config)

    # Exactly one record + one error.
    assert len(result.records) == 1
    assert len(result.errors) == 1

    record = result.records[0]
    error = result.errors[0]

    # Both reference the same component_id.
    assert record.component_id == component.component_id
    assert error.component_id == component.component_id


def test_raw_path_none_record_has_signature_info_present_false(
    synthetic_rules_dir: Path,
) -> None:
    """The emitted record carries ``signature_info.present=False``
    (the bytes weren't readable, so no signature was detected)."""
    component = _component(raw_path=None)
    config = _config(synthetic_rules_dir)
    result = classify_components([component], config)

    assert len(result.records) == 1
    record = result.records[0]
    assert record.signature_info is not None
    assert record.signature_info.present is False


def test_raw_path_none_record_has_all_four_axes_classified(
    synthetic_rules_dir: Path,
) -> None:
    """The dual-record case does not suppress any of the four
    axes — they all classify per Requirements 3 and 4 (often
    landing in the UNKNOWN fallback)."""
    component = _component(raw_path=None)
    config = _config(synthetic_rules_dir)
    result = classify_components([component], config)

    assert len(result.records) == 1
    record = result.records[0]
    assert record.type_axis is not None
    assert record.vendor_axis is not None
    assert record.security_axis is not None
    assert record.mutability_axis is not None


def test_raw_path_none_error_message_identifies_missing_bytes(
    synthetic_rules_dir: Path,
) -> None:
    """The error message identifies the missing-bytes condition
    so callers can distinguish it from other failure modes."""
    component = _component(raw_path=None)
    config = _config(synthetic_rules_dir)
    result = classify_components([component], config)

    assert len(result.errors) == 1
    error = result.errors[0]
    assert "raw_path missing" in error.error_message


# ---------------------------------------------------------------------------
# raw_path points at a missing file variant
# ---------------------------------------------------------------------------


def test_missing_file_emits_record_and_error_for_same_component(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """When raw_path points at a non-existent file, the dual-
    record contract still holds."""

    nonexistent = tmp_path / "no-such-file.bin"
    component = _component(raw_path=str(nonexistent))
    config = _config(synthetic_rules_dir)
    result = classify_components([component], config)

    assert len(result.records) == 1
    assert len(result.errors) == 1
    assert result.records[0].component_id == component.component_id
    assert result.errors[0].component_id == component.component_id


def test_missing_file_record_has_signature_info_present_false(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    nonexistent = tmp_path / "no-such-file.bin"
    component = _component(raw_path=str(nonexistent))
    config = _config(synthetic_rules_dir)
    result = classify_components([component], config)

    assert len(result.records) == 1
    record = result.records[0]
    assert record.signature_info is not None
    assert record.signature_info.present is False


def test_missing_file_error_message_identifies_unreadable(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """The file-unreadable variant of the error message is
    distinct from the raw_path-missing variant so callers can
    differentiate the two."""
    nonexistent = tmp_path / "no-such-file.bin"
    component = _component(raw_path=str(nonexistent))
    config = _config(synthetic_rules_dir)
    result = classify_components([component], config)

    assert len(result.errors) == 1
    error = result.errors[0]
    assert "file unreadable" in error.error_message


# ---------------------------------------------------------------------------
# Property 42: dual-record contract holds across the input sequence
# ---------------------------------------------------------------------------


def test_dual_record_contract_holds_across_multiple_components(
    synthetic_rules_dir: Path,
) -> None:
    """When N components all hit the missing-bytes path, the
    result has N records and N errors. Component IDs match
    pairwise."""

    components = [_component(index=i, raw_path=None) for i in range(5)]
    config = _config(synthetic_rules_dir)
    result = classify_components(components, config)

    assert len(result.records) == 5
    assert len(result.errors) == 5

    # Each component_id appears exactly once in records and once
    # in errors.
    record_ids = {r.component_id for r in result.records}
    error_ids = {e.component_id for e in result.errors}
    expected_ids = {c.component_id for c in components}
    assert record_ids == expected_ids
    assert error_ids == expected_ids


def test_dual_record_does_not_apply_when_bytes_are_readable(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """The dual-record contract is specific to the missing-bytes
    case. When raw_path points at a readable file, the
    component appears only in ``records`` (R9.5: errors empty)."""

    raw_file = tmp_path / "real-file.bin"
    raw_file.write_bytes(b"\x00" * 64)
    component = _component(raw_path=str(raw_file))
    config = _config(synthetic_rules_dir)
    result = classify_components([component], config)

    assert len(result.records) == 1
    assert result.errors == []


def test_dual_record_can_mix_with_normal_records(
    synthetic_rules_dir: Path,
    tmp_path: Path,
) -> None:
    """A run with one missing-bytes component and one
    normal-bytes component produces 2 records (one per
    component) and 1 error (only for the missing-bytes one)."""

    raw_file = tmp_path / "readable.bin"
    raw_file.write_bytes(b"\x00" * 64)
    readable_component = _component(index=0, raw_path=str(raw_file))
    missing_component = _component(index=1, raw_path=None)

    config = _config(synthetic_rules_dir)
    result = classify_components([readable_component, missing_component], config)

    assert len(result.records) == 2
    assert len(result.errors) == 1
    assert result.errors[0].component_id == missing_component.component_id
