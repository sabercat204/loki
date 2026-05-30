"""Tests for ``emit_classification_gap`` (R10)."""

from __future__ import annotations

import uuid

from loki.analysis.findings import derive_finding_id, emit_classification_gap
from loki.models import SeverityLevel
from tests.analysis._helpers import make_record


def test_severity_is_flat_low() -> None:
    """R10.6: severity is LOW; gaps are diagnostic, not threats."""
    target = make_record(confidence=0.4)  # below default 0.6 threshold
    finding = emit_classification_gap(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.severity is SeverityLevel.LOW


def test_category_and_component_id() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, confidence=0.4)
    finding = emit_classification_gap(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.category == "classification_gap"
    assert finding.component_id == target_id


def test_evidence_carries_target_record() -> None:
    """R10.5: evidence.classification_record is the target record."""
    target = make_record(confidence=0.4)
    finding = emit_classification_gap(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.evidence.classification_record is target


def test_no_deviation_score_embedded() -> None:
    target = make_record(confidence=0.4)
    finding = emit_classification_gap(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.evidence.deviation_score is None


def test_evidence_other_fields_default() -> None:
    target = make_record(confidence=0.4)
    finding = emit_classification_gap(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.evidence.matched_rule is None
    assert finding.evidence.matched_cve is None
    assert finding.evidence.matched_signature is None
    assert finding.evidence.raw_indicators == []


def test_finding_id_stable_across_emits() -> None:
    bid = uuid.uuid4()
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, confidence=0.4)
    a = emit_classification_gap(target=target, matched_baseline_id=bid)
    b = emit_classification_gap(target=target, matched_baseline_id=bid)
    assert a.finding_id == b.finding_id
    assert a.finding_id == derive_finding_id(
        baseline_id=bid,
        finding_category="classification_gap",
        target_component_id=target_id,
    )


def test_recommended_action_is_empty_string() -> None:
    target = make_record(confidence=0.4)
    finding = emit_classification_gap(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.recommended_action == ""


# --- The emitter is independent of pairing ---


def test_emitter_does_not_consult_baseline() -> None:
    """R10.2: the gap finding fires regardless of pairing.

    The emitter signature confirms this — it takes only the target,
    no baseline. The pipeline orchestrates whether to call this.
    """
    target = make_record(confidence=0.3)
    finding = emit_classification_gap(target=target, matched_baseline_id=uuid.uuid4())
    # Smoke: the finding constructs cleanly with no baseline reference
    # in the evidence.
    assert finding.evidence.classification_record is target
