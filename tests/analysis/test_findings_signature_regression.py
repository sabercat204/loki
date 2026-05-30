"""Tests for ``emit_signature_regression`` (R5)."""

from __future__ import annotations

import uuid

import pytest

from loki.analysis.findings import derive_finding_id, emit_signature_regression
from loki.models import SeverityLevel
from tests.analysis._helpers import make_record, make_signature_info

# --- Severity by direction ---


def test_baseline_signed_target_unsigned_is_high() -> None:
    """R5.6: lost-signature regression → HIGH."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=make_signature_info(present=False))
    baseline = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    finding = emit_signature_regression(
        target=target, baseline=baseline, matched_baseline_id=uuid.uuid4()
    )
    assert finding.severity is SeverityLevel.HIGH
    assert finding.evidence.matched_signature == "BASELINE_SIGNED"


def test_target_signed_baseline_unsigned_is_medium() -> None:
    """R5.6: gained-signature regression → MEDIUM."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    baseline = make_record(
        component_id=target_id, signature_info=make_signature_info(present=False)
    )
    finding = emit_signature_regression(
        target=target, baseline=baseline, matched_baseline_id=uuid.uuid4()
    )
    assert finding.severity is SeverityLevel.MEDIUM
    assert finding.evidence.matched_signature == "TARGET_SIGNED"


# --- DeviationScore is None ---


def test_no_deviation_score_embedded() -> None:
    """R9.11: only classification_mismatch findings carry a DeviationScore."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=make_signature_info(present=False))
    baseline = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    finding = emit_signature_regression(
        target=target, baseline=baseline, matched_baseline_id=uuid.uuid4()
    )
    assert finding.evidence.deviation_score is None


# --- Field invariants ---


def test_category_and_component_id() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=make_signature_info(present=False))
    baseline = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    finding = emit_signature_regression(
        target=target, baseline=baseline, matched_baseline_id=uuid.uuid4()
    )
    assert finding.category == "signature_regression"
    assert finding.component_id == target_id


def test_evidence_carries_target_record() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=make_signature_info(present=False))
    baseline = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    finding = emit_signature_regression(
        target=target, baseline=baseline, matched_baseline_id=uuid.uuid4()
    )
    assert finding.evidence.classification_record is target


# --- Determinism ---


def test_finding_id_stable_across_emits() -> None:
    bid = uuid.uuid4()
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=make_signature_info(present=False))
    baseline = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    a = emit_signature_regression(target=target, baseline=baseline, matched_baseline_id=bid)
    b = emit_signature_regression(target=target, baseline=baseline, matched_baseline_id=bid)
    assert a.finding_id == b.finding_id
    assert a.finding_id == derive_finding_id(
        baseline_id=bid,
        finding_category="signature_regression",
        target_component_id=target_id,
    )


# --- Defensive: pre-condition violations ---


def test_target_signature_info_none_raises() -> None:
    """Pipeline asserts non-None signature_info; defensive check in emitter."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=None)
    baseline = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    with pytest.raises(ValueError, match="non-None"):
        emit_signature_regression(
            target=target, baseline=baseline, matched_baseline_id=uuid.uuid4()
        )


def test_baseline_signature_info_none_raises() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    baseline = make_record(component_id=target_id, signature_info=None)
    with pytest.raises(ValueError, match="non-None"):
        emit_signature_regression(
            target=target, baseline=baseline, matched_baseline_id=uuid.uuid4()
        )


def test_both_signed_raises() -> None:
    """Both signed → caller shouldn't have invoked the emitter; defensive."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    baseline = make_record(component_id=target_id, signature_info=make_signature_info(present=True))
    with pytest.raises(ValueError, match="must differ"):
        emit_signature_regression(
            target=target, baseline=baseline, matched_baseline_id=uuid.uuid4()
        )


def test_both_unsigned_raises() -> None:
    """Both unsigned → caller shouldn't have invoked the emitter; defensive."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, signature_info=make_signature_info(present=False))
    baseline = make_record(
        component_id=target_id, signature_info=make_signature_info(present=False)
    )
    with pytest.raises(ValueError, match="must differ"):
        emit_signature_regression(
            target=target, baseline=baseline, matched_baseline_id=uuid.uuid4()
        )
