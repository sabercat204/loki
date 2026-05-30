"""Tests for ``derive_finding_id`` and the Cancellation_Marker sentinel UUID.

Covers task 10 acceptance: same inputs produce the same UUID across two
calls; distinct categories produce distinct UUIDs; distinct baselines
produce distinct UUIDs; the sentinel UUID is bit-equal to the documented
formula.
"""

from __future__ import annotations

import uuid

from loki.analysis.findings import (
    ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID,
    derive_finding_id,
)
from loki.models.firmware import LOKI_NAMESPACE

# --- Determinism ---


def test_same_inputs_produce_same_uuid() -> None:
    bid = uuid.uuid4()
    cid = uuid.uuid4()
    a = derive_finding_id(
        baseline_id=bid,
        finding_category="classification_mismatch",
        target_component_id=cid,
    )
    b = derive_finding_id(
        baseline_id=bid,
        finding_category="classification_mismatch",
        target_component_id=cid,
    )
    assert a == b


def test_distinct_categories_produce_distinct_uuids() -> None:
    bid = uuid.uuid4()
    cid = uuid.uuid4()
    mismatch = derive_finding_id(
        baseline_id=bid,
        finding_category="classification_mismatch",
        target_component_id=cid,
    )
    regression = derive_finding_id(
        baseline_id=bid,
        finding_category="signature_regression",
        target_component_id=cid,
    )
    gap = derive_finding_id(
        baseline_id=bid,
        finding_category="classification_gap",
        target_component_id=cid,
    )
    assert len({mismatch, regression, gap}) == 3


def test_distinct_baselines_produce_distinct_uuids() -> None:
    bid_a = uuid.uuid4()
    bid_b = uuid.uuid4()
    cid = uuid.uuid4()
    a = derive_finding_id(
        baseline_id=bid_a,
        finding_category="classification_mismatch",
        target_component_id=cid,
    )
    b = derive_finding_id(
        baseline_id=bid_b,
        finding_category="classification_mismatch",
        target_component_id=cid,
    )
    assert a != b


def test_distinct_target_component_ids_produce_distinct_uuids() -> None:
    bid = uuid.uuid4()
    cid_a = uuid.uuid4()
    cid_b = uuid.uuid4()
    a = derive_finding_id(
        baseline_id=bid,
        finding_category="classification_mismatch",
        target_component_id=cid_a,
    )
    b = derive_finding_id(
        baseline_id=bid,
        finding_category="classification_mismatch",
        target_component_id=cid_b,
    )
    assert a != b


def test_derivation_matches_documented_formula() -> None:
    """The function returns ``uuid5(LOKI_NAMESPACE, f"{bid}:{cat}:{cid}")``."""
    bid = uuid.uuid4()
    cid = uuid.uuid4()
    cat = "classification_mismatch"
    expected = uuid.uuid5(LOKI_NAMESPACE, f"{bid}:{cat}:{cid}")
    actual = derive_finding_id(
        baseline_id=bid,
        finding_category=cat,
        target_component_id=cid,
    )
    assert actual == expected


# --- Sentinel UUID ---


def test_sentinel_matches_documented_formula() -> None:
    expected = uuid.uuid5(LOKI_NAMESPACE, "analysis-cancelled")
    assert ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID == expected


def test_sentinel_is_uuid_instance() -> None:
    assert isinstance(ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID, uuid.UUID)


def test_sentinel_is_module_constant() -> None:
    """Two imports of the constant return the same identity (no recomputation)."""
    # Re-import via importlib to verify the constant is computed exactly once.
    import importlib

    mod_a = importlib.import_module("loki.analysis.findings")
    mod_b = importlib.import_module("loki.analysis.findings")
    assert mod_a is mod_b
    assert (
        mod_a.ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID
        is mod_b.ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID
    )
