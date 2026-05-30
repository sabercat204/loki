"""Tests for ``emit_missing_required_component`` (R8)."""

from __future__ import annotations

import uuid

from loki.analysis.findings import derive_finding_id, emit_missing_required_component
from loki.models import SeverityLevel
from tests.analysis._helpers import make_record


def test_severity_is_flat_high() -> None:
    """R8.5: severity is HIGH, flat per v1."""
    baseline = make_record()
    finding = emit_missing_required_component(baseline=baseline, matched_baseline_id=uuid.uuid4())
    assert finding.severity is SeverityLevel.HIGH


def test_category_and_component_id_from_baseline() -> None:
    """R8.3: component_id field carries the BASELINE record's component_id."""
    baseline_cid = uuid.uuid4()
    baseline = make_record(component_id=baseline_cid)
    finding = emit_missing_required_component(baseline=baseline, matched_baseline_id=uuid.uuid4())
    assert finding.category == "missing_required_component"
    assert finding.component_id == baseline_cid


def test_evidence_carries_baseline_record() -> None:
    """R8.4: evidence.classification_record is the unpaired baseline record."""
    baseline = make_record()
    finding = emit_missing_required_component(baseline=baseline, matched_baseline_id=uuid.uuid4())
    assert finding.evidence.classification_record is baseline


def test_no_deviation_score_embedded() -> None:
    baseline = make_record()
    finding = emit_missing_required_component(baseline=baseline, matched_baseline_id=uuid.uuid4())
    assert finding.evidence.deviation_score is None


def test_evidence_other_fields_default() -> None:
    baseline = make_record()
    finding = emit_missing_required_component(baseline=baseline, matched_baseline_id=uuid.uuid4())
    assert finding.evidence.matched_rule is None
    assert finding.evidence.matched_cve is None
    assert finding.evidence.matched_signature is None
    assert finding.evidence.raw_indicators == []


def test_finding_id_uses_baseline_component_id() -> None:
    """R15.7: target_component_id arg sourced from baseline.component_id."""
    bid = uuid.uuid4()
    baseline_cid = uuid.uuid4()
    baseline = make_record(component_id=baseline_cid)
    finding = emit_missing_required_component(baseline=baseline, matched_baseline_id=bid)
    expected = derive_finding_id(
        baseline_id=bid,
        finding_category="missing_required_component",
        target_component_id=baseline_cid,
    )
    assert finding.finding_id == expected


def test_finding_id_stable_across_emits() -> None:
    bid = uuid.uuid4()
    baseline = make_record()
    a = emit_missing_required_component(baseline=baseline, matched_baseline_id=bid)
    b = emit_missing_required_component(baseline=baseline, matched_baseline_id=bid)
    assert a.finding_id == b.finding_id


def test_recommended_action_is_empty_string() -> None:
    baseline = make_record()
    finding = emit_missing_required_component(baseline=baseline, matched_baseline_id=uuid.uuid4())
    assert finding.recommended_action == ""
