"""Tests for ``loki.analysis.pairing``.

Covers task 9 acceptance: duplicate component_id detection on both
sides; baseline_index construction keyed on component_id; pair_records
yields tuples in target input order with None for unpaired records;
unpaired_baselines returns ascending-component_id-sorted records.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

import pytest

from loki.analysis import AnalysisInputError
from loki.analysis.pairing import (
    build_baseline_index,
    check_pairing_preconditions,
    pair_records,
    unpaired_baselines,
)
from loki.models import (
    AxisClassification,
    ClassificationMethod,
    ClassificationRecord,
    ComponentTypeLabel,
    MutabilityLabel,
    SecurityPostureLabel,
    VendorLabel,
)

# --- Test fixture helpers ---


def _axis(label: str, *, confidence: float = 1.0) -> AxisClassification:
    return AxisClassification(
        label=label,
        confidence=confidence,
        method=ClassificationMethod.RULE,
    )


def _make_record(*, component_id: uuid.UUID | None = None) -> ClassificationRecord:
    return ClassificationRecord(
        component_id=component_id or uuid.uuid4(),
        source_image_id=uuid.uuid4(),
        extraction_offset="0x00",
        timestamp=datetime.now(UTC),
        type_axis=_axis(ComponentTypeLabel.UEFI_DRIVER),
        vendor_axis=_axis(VendorLabel.INTEL),
        security_axis=_axis(SecurityPostureLabel.SECURE),
        mutability_axis=_axis(MutabilityLabel.READONLY),
        classification_version="1.0.0",
    )


# --- check_pairing_preconditions ---


def test_unique_ids_on_both_sides_accepts() -> None:
    targets = [_make_record() for _ in range(3)]
    baselines = [_make_record() for _ in range(3)]
    check_pairing_preconditions(targets, baselines, uuid.uuid4())  # no raise


def test_target_side_duplicate_raises_with_offending_id() -> None:
    dup_id = uuid.uuid4()
    targets = [
        _make_record(component_id=dup_id),
        _make_record(),
        _make_record(component_id=dup_id),
    ]
    baselines = [_make_record() for _ in range(2)]
    bid = uuid.uuid4()
    with pytest.raises(AnalysisInputError) as excinfo:
        check_pairing_preconditions(targets, baselines, bid)
    assert excinfo.value.side == "target"
    assert dup_id in excinfo.value.duplicates
    assert excinfo.value.baseline_id is None
    assert "target_records" in str(excinfo.value)


def test_baseline_side_duplicate_raises_with_baseline_id() -> None:
    dup_id = uuid.uuid4()
    targets = [_make_record() for _ in range(2)]
    baselines = [
        _make_record(component_id=dup_id),
        _make_record(),
        _make_record(component_id=dup_id),
    ]
    bid = uuid.uuid4()
    with pytest.raises(AnalysisInputError) as excinfo:
        check_pairing_preconditions(targets, baselines, bid)
    assert excinfo.value.side == "baseline"
    assert dup_id in excinfo.value.duplicates
    assert excinfo.value.baseline_id == bid


def test_target_duplicates_surface_before_baseline_duplicates() -> None:
    """Duplicate-on-both-sides: target side wins (the simpler error)."""
    target_dup = uuid.uuid4()
    baseline_dup = uuid.uuid4()
    targets = [
        _make_record(component_id=target_dup),
        _make_record(component_id=target_dup),
    ]
    baselines = [
        _make_record(component_id=baseline_dup),
        _make_record(component_id=baseline_dup),
    ]
    with pytest.raises(AnalysisInputError) as excinfo:
        check_pairing_preconditions(targets, baselines, uuid.uuid4())
    assert excinfo.value.side == "target"


def test_multiple_duplicates_on_target_side_all_reported() -> None:
    dup_a = uuid.uuid4()
    dup_b = uuid.uuid4()
    targets = [
        _make_record(component_id=dup_a),
        _make_record(component_id=dup_b),
        _make_record(component_id=dup_a),
        _make_record(component_id=dup_b),
        _make_record(),
    ]
    baselines = [_make_record() for _ in range(2)]
    with pytest.raises(AnalysisInputError) as excinfo:
        check_pairing_preconditions(targets, baselines, uuid.uuid4())
    assert dup_a in excinfo.value.duplicates
    assert dup_b in excinfo.value.duplicates
    assert len(excinfo.value.duplicates) == 2  # each id reported once


def test_empty_inputs_accept() -> None:
    """No records on either side is a valid input combination (R1.3)."""
    check_pairing_preconditions([], [], uuid.uuid4())  # no raise


# --- build_baseline_index ---


def test_build_baseline_index_keys_on_component_id() -> None:
    records = [_make_record() for _ in range(3)]
    index = build_baseline_index(records)
    assert set(index.keys()) == {r.component_id for r in records}
    for record in records:
        assert index[record.component_id] is record


def test_build_baseline_index_empty_input() -> None:
    assert build_baseline_index([]) == {}


# --- pair_records ---


def test_pair_records_preserves_target_input_order() -> None:
    """R3.4: per-target findings appear in target input order."""
    target_a = _make_record()
    target_b = _make_record()
    target_c = _make_record()
    targets = [target_a, target_b, target_c]
    baseline_b = _make_record(component_id=target_b.component_id)
    index = build_baseline_index([baseline_b])
    pairs = list(pair_records(targets, index))
    assert len(pairs) == 3
    assert pairs[0][0] is target_a  # target order preserved
    assert pairs[1][0] is target_b
    assert pairs[2][0] is target_c
    # Pairing: a unpaired, b paired, c unpaired.
    assert pairs[0][1] is None
    assert pairs[1][1] is baseline_b
    assert pairs[2][1] is None


def test_pair_records_paired_match_returns_baseline() -> None:
    target = _make_record()
    baseline = _make_record(component_id=target.component_id)
    index = build_baseline_index([baseline])
    pairs = list(pair_records([target], index))
    assert len(pairs) == 1
    assert pairs[0][0] is target
    assert pairs[0][1] is baseline


def test_pair_records_unpaired_target_returns_none() -> None:
    target = _make_record()
    other_baseline = _make_record()  # different component_id
    index = build_baseline_index([other_baseline])
    pairs = list(pair_records([target], index))
    assert pairs[0][1] is None


def test_pair_records_empty_targets_emits_nothing() -> None:
    baseline = _make_record()
    index = build_baseline_index([baseline])
    pairs = list(pair_records([], index))
    assert pairs == []


# --- unpaired_baselines ---


def test_unpaired_baselines_sorts_by_ascending_component_id() -> None:
    """R3.4: missing_required_component findings ordered by ascending component_id."""
    # Build records, then sort the expected order.
    records = [_make_record() for _ in range(5)]
    index = build_baseline_index(records)
    consumed: set[uuid.UUID] = set()  # nothing consumed
    unpaired = unpaired_baselines(index, consumed)
    expected_order = sorted(records, key=lambda r: r.component_id)
    assert [r.component_id for r in unpaired] == [r.component_id for r in expected_order]


def test_unpaired_baselines_filters_consumed_ids() -> None:
    records = [_make_record() for _ in range(5)]
    index = build_baseline_index(records)
    consumed = {records[1].component_id, records[3].component_id}
    unpaired = unpaired_baselines(index, consumed)
    assert {r.component_id for r in unpaired} == {
        records[0].component_id,
        records[2].component_id,
        records[4].component_id,
    }


def test_unpaired_baselines_all_consumed_returns_empty() -> None:
    records = [_make_record() for _ in range(3)]
    index = build_baseline_index(records)
    consumed = {r.component_id for r in records}
    assert unpaired_baselines(index, consumed) == []


def test_unpaired_baselines_empty_index_returns_empty() -> None:
    assert unpaired_baselines({}, set()) == []


# --- End-to-end smoke ---


def test_full_pairing_flow_smoke() -> None:
    """Smoke: build index, iterate, track consumed, surface unpaired."""
    paired_id = uuid.uuid4()
    target_only_id = uuid.uuid4()
    baseline_only_id = uuid.uuid4()

    targets = [
        _make_record(component_id=paired_id),
        _make_record(component_id=target_only_id),
    ]
    baseline_manifest = [
        _make_record(component_id=paired_id),
        _make_record(component_id=baseline_only_id),
    ]

    bid = uuid.uuid4()
    check_pairing_preconditions(targets, baseline_manifest, bid)
    index = build_baseline_index(baseline_manifest)

    consumed: set[uuid.UUID] = set()
    pair_results: list[tuple[uuid.UUID, bool]] = []
    for target, baseline in pair_records(targets, index):
        pair_results.append((target.component_id, baseline is not None))
        if baseline is not None:
            consumed.add(target.component_id)

    assert pair_results == [(paired_id, True), (target_only_id, False)]

    unpaired = unpaired_baselines(index, consumed)
    assert len(unpaired) == 1
    assert unpaired[0].component_id == baseline_only_id


def test_pair_records_linear_time_smoke() -> None:
    """Smoke (not strict): 1024+1024 pairing completes in well under a second."""
    pair_count = 1024
    targets = [_make_record() for _ in range(pair_count)]
    baselines = [_make_record(component_id=t.component_id) for t in targets]
    index = build_baseline_index(baselines)
    start = time.monotonic()
    consumed: set[uuid.UUID] = set()
    for target, baseline in pair_records(targets, index):
        if baseline is not None:
            consumed.add(target.component_id)
    elapsed = time.monotonic() - start
    assert len(consumed) == pair_count
    # Pairing 1024+1024 records should be tiny; 1.0s is a generous ceiling.
    assert elapsed < 1.0
