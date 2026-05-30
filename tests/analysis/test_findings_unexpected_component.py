"""Tests for ``emit_unexpected_component`` (R6)."""

from __future__ import annotations

import uuid

from loki.analysis.findings import derive_finding_id, emit_unexpected_component
from loki.models import SeverityLevel
from tests.analysis._helpers import make_record


def test_severity_is_flat_medium() -> None:
    """R6.5: severity is MEDIUM, independent of input axes."""
    target = make_record()
    finding = emit_unexpected_component(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.severity is SeverityLevel.MEDIUM


def test_category_and_component_id() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id)
    finding = emit_unexpected_component(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.category == "unexpected_component"
    assert finding.component_id == target_id


def test_evidence_carries_target_record() -> None:
    """R6.4: evidence.classification_record is the unpaired Target_Record."""
    target = make_record()
    finding = emit_unexpected_component(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.evidence.classification_record is target


def test_no_deviation_score_embedded() -> None:
    target = make_record()
    finding = emit_unexpected_component(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.evidence.deviation_score is None


def test_evidence_other_fields_default() -> None:
    target = make_record()
    finding = emit_unexpected_component(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.evidence.matched_rule is None
    assert finding.evidence.matched_cve is None
    assert finding.evidence.matched_signature is None
    assert finding.evidence.raw_indicators == []


def test_finding_id_stable_across_emits() -> None:
    bid = uuid.uuid4()
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id)
    a = emit_unexpected_component(target=target, matched_baseline_id=bid)
    b = emit_unexpected_component(target=target, matched_baseline_id=bid)
    assert a.finding_id == b.finding_id
    assert a.finding_id == derive_finding_id(
        baseline_id=bid,
        finding_category="unexpected_component",
        target_component_id=target_id,
    )


def test_recommended_action_is_empty_string() -> None:
    target = make_record()
    finding = emit_unexpected_component(target=target, matched_baseline_id=uuid.uuid4())
    assert finding.recommended_action == ""
