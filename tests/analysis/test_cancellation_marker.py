"""Tests for ``make_cancellation_marker``.

Covers task 10 acceptance: the constructed Cancellation_Marker carries
the documented field invariants per R7.1-R7.7; deterministic finding_id
across two cancellations of the same baseline at the same index;
Pydantic round-trip via JSON; the marker constructs without Pydantic
validation errors.
"""

from __future__ import annotations

import uuid

from loki.analysis.findings import (
    ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID,
    derive_finding_id,
    make_cancellation_marker,
)
from loki.models import FindingRecord, SeverityLevel


def test_category_is_analysis_cancelled() -> None:
    marker = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=1)
    assert marker.category == "analysis_cancelled"


def test_severity_is_info() -> None:
    """R7.3: the marker is diagnostic, not a threat indicator."""
    marker = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=1)
    assert marker.severity is SeverityLevel.INFO


def test_component_id_is_sentinel() -> None:
    """R7.2: marker carries the deterministic sentinel UUID."""
    marker = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=1)
    assert marker.component_id == ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID


def test_title_is_fixed_non_leaking() -> None:
    """R7.5: title is a fixed, non-leaking string."""
    marker = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=42)
    assert marker.title == "analysis cancelled"


def test_description_is_fixed_non_leaking() -> None:
    """R7.5: description is a fixed, non-leaking string."""
    marker = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=42)
    assert marker.description == ("cooperative cancellation observed; partial findings returned")


def test_raw_indicators_carries_index_only() -> None:
    """R7.4: evidence.raw_indicators[0] is "cancelled-at-index=N"."""
    marker = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=42)
    assert marker.evidence.raw_indicators == ["cancelled-at-index=42"]


def test_raw_indicators_index_varies_with_input() -> None:
    a = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=1)
    b = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=99)
    assert a.evidence.raw_indicators == ["cancelled-at-index=1"]
    assert b.evidence.raw_indicators == ["cancelled-at-index=99"]


def test_evidence_classification_record_is_none() -> None:
    """The Cancellation_Marker has no associated ClassificationRecord."""
    marker = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=1)
    assert marker.evidence.classification_record is None


def test_evidence_other_fields_default() -> None:
    """matched_rule / matched_cve / matched_signature / deviation_score all None."""
    marker = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=1)
    assert marker.evidence.matched_rule is None
    assert marker.evidence.matched_cve is None
    assert marker.evidence.matched_signature is None
    assert marker.evidence.deviation_score is None


def test_recommended_action_is_empty_string() -> None:
    """v1 leaves recommended_actions list empty per R17.3 — per-finding string is empty."""
    marker = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=1)
    assert marker.recommended_action == ""


# --- Deterministic finding_id ---


def test_deterministic_finding_id_across_two_calls_same_baseline() -> None:
    """R7.7: same baseline + same index produces the same finding_id."""
    bid = uuid.uuid4()
    a = make_cancellation_marker(baseline_id=bid, cancelled_at_index=5)
    b = make_cancellation_marker(baseline_id=bid, cancelled_at_index=5)
    assert a.finding_id == b.finding_id


def test_finding_id_independent_of_index() -> None:
    """R7.7: two cancellations of the same baseline at *different* indices share finding_id."""
    bid = uuid.uuid4()
    a = make_cancellation_marker(baseline_id=bid, cancelled_at_index=5)
    b = make_cancellation_marker(baseline_id=bid, cancelled_at_index=99)
    # finding_id is a function of (baseline_id, "analysis_cancelled", sentinel)
    # only — index lives in evidence.raw_indicators, not in the tuple.
    assert a.finding_id == b.finding_id
    # The two markers differ only in evidence.raw_indicators.
    assert a.evidence.raw_indicators != b.evidence.raw_indicators


def test_finding_id_distinct_per_baseline() -> None:
    a = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=1)
    b = make_cancellation_marker(baseline_id=uuid.uuid4(), cancelled_at_index=1)
    assert a.finding_id != b.finding_id


def test_finding_id_matches_derive_finding_id_formula() -> None:
    """The marker's finding_id is exactly derive_finding_id(...)."""
    bid = uuid.uuid4()
    marker = make_cancellation_marker(baseline_id=bid, cancelled_at_index=7)
    expected = derive_finding_id(
        baseline_id=bid,
        finding_category="analysis_cancelled",
        target_component_id=ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID,
    )
    assert marker.finding_id == expected


# --- Pydantic round-trip ---


def test_pydantic_round_trip() -> None:
    bid = uuid.uuid4()
    original = make_cancellation_marker(baseline_id=bid, cancelled_at_index=10)
    restored = FindingRecord.model_validate_json(original.model_dump_json())
    assert restored.finding_id == original.finding_id
    assert restored.component_id == original.component_id
    assert restored.severity is SeverityLevel.INFO
    assert restored.category == "analysis_cancelled"
    assert restored.title == original.title
    assert restored.description == original.description
    assert restored.evidence.raw_indicators == ["cancelled-at-index=10"]
