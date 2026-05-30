"""Tests for ``emit_classification_mismatch`` (R4)."""

from __future__ import annotations

import uuid

from loki.analysis.findings import derive_finding_id, emit_classification_mismatch
from loki.models import (
    ComponentTypeLabel,
    MutabilityLabel,
    SecurityPostureLabel,
    SeverityLevel,
    VendorLabel,
)
from tests.analysis._helpers import VALID_WEIGHTS, make_record, make_signature_info

# --- Single-axis mismatch ---


def test_type_axis_mismatch_only_emits_finding_with_score() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline = make_record(component_id=target_id, type_label=ComponentTypeLabel.OS_KERNEL)
    bid = uuid.uuid4()
    finding = emit_classification_mismatch(
        target=target, baseline=baseline, matched_baseline_id=bid, severity_weights=VALID_WEIGHTS
    )
    assert finding.category == "classification_mismatch"
    assert finding.component_id == target_id
    assert finding.evidence.deviation_score is not None
    # Only type axis disagrees (weight 0.4) at full confidence on both sides.
    # composite_score = 10.0 * 0.4 * 1.0 = 4.0 → MEDIUM.
    assert finding.evidence.deviation_score.composite_score == 4.0
    assert finding.severity is SeverityLevel.MEDIUM


def test_vendor_axis_mismatch_only_emits_lower_severity() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, vendor_label=VendorLabel.INTEL)
    baseline = make_record(component_id=target_id, vendor_label=VendorLabel.AMD)
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    # Only vendor axis disagrees (weight 0.2) at full confidence.
    # composite_score = 10.0 * 0.2 * 1.0 = 2.0 → LOW.
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.composite_score == 2.0
    assert finding.severity is SeverityLevel.LOW


# --- All-axes mismatch ---


def test_all_axes_mismatch_at_full_confidence_is_critical() -> None:
    target_id = uuid.uuid4()
    target = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.UEFI_DRIVER,
        vendor_label=VendorLabel.INTEL,
        security_label=SecurityPostureLabel.SECURE,
        mutability_label=MutabilityLabel.READONLY,
    )
    baseline = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.OS_KERNEL,
        vendor_label=VendorLabel.AMD,
        security_label=SecurityPostureLabel.VULNERABLE,
        mutability_label=MutabilityLabel.MUTABLE,
    )
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.composite_score == 10.0
    assert finding.severity is SeverityLevel.CRITICAL


# --- Defensive: no axes disagree ---


def test_no_axes_disagree_emits_info_severity() -> None:
    """The pipeline shouldn't call this in production, but defensive: composite=0 → INFO."""
    target_id = uuid.uuid4()
    record = make_record(component_id=target_id)
    finding = emit_classification_mismatch(
        target=record,
        baseline=record,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.composite_score == 0.0
    assert finding.severity is SeverityLevel.INFO


# --- DeviationScore embedding ---


def test_deviation_score_carries_security_direction_degraded() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, security_label=SecurityPostureLabel.VULNERABLE)
    baseline = make_record(component_id=target_id, security_label=SecurityPostureLabel.SECURE)
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.security_direction.value == "DEGRADED"


def test_deviation_score_carries_signature_delta_lost() -> None:
    target_id = uuid.uuid4()
    target = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.UEFI_DRIVER,
        signature_info=make_signature_info(present=False),
    )
    baseline = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.OS_KERNEL,
        signature_info=make_signature_info(present=True),
    )
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.signature_delta.value == "LOST"


def test_deviation_score_carries_mutability_change_became_mutable() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, mutability_label=MutabilityLabel.MUTABLE)
    baseline = make_record(component_id=target_id, mutability_label=MutabilityLabel.READONLY)
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.mutability_change.value == "BECAME_MUTABLE"


def test_deviation_score_component_criticality_from_baseline() -> None:
    """R9.7: component_criticality = baseline.composite_confidence."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id)
    baseline = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.OS_KERNEL,
        confidence=0.7,  # drives composite_confidence to 0.7
    )
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.component_criticality == 0.7


def test_deviation_score_cve_introduced_is_false_in_v1() -> None:
    """R9.9: v1 SHALL set cve_introduced = False for every emitted score."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline = make_record(component_id=target_id, type_label=ComponentTypeLabel.OS_KERNEL)
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.cve_introduced is False


def test_priority_rank_placeholder_is_one() -> None:
    """R9.10: emitter sets priority_rank=1 placeholder; pipeline overwrites."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline = make_record(component_id=target_id, type_label=ComponentTypeLabel.OS_KERNEL)
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.deviation_score is not None
    # 1 is the placeholder per the docstring; the pipeline's second pass
    # in Wave 6 will overwrite this with the real rank.
    assert finding.evidence.deviation_score.priority_rank == 1


# --- Determinism ---


def test_finding_id_stable_across_two_emits() -> None:
    """Same inputs → same finding_id (R15.7)."""
    bid = uuid.uuid4()
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline = make_record(component_id=target_id, type_label=ComponentTypeLabel.OS_KERNEL)
    a = emit_classification_mismatch(
        target=target, baseline=baseline, matched_baseline_id=bid, severity_weights=VALID_WEIGHTS
    )
    b = emit_classification_mismatch(
        target=target, baseline=baseline, matched_baseline_id=bid, severity_weights=VALID_WEIGHTS
    )
    assert a.finding_id == b.finding_id


def test_finding_id_matches_derive_finding_id_formula() -> None:
    bid = uuid.uuid4()
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline = make_record(component_id=target_id, type_label=ComponentTypeLabel.OS_KERNEL)
    finding = emit_classification_mismatch(
        target=target, baseline=baseline, matched_baseline_id=bid, severity_weights=VALID_WEIGHTS
    )
    expected = derive_finding_id(
        baseline_id=bid,
        finding_category="classification_mismatch",
        target_component_id=target_id,
    )
    assert finding.finding_id == expected


# --- Severity boundary ---


def test_severity_boundary_at_six_is_high() -> None:
    """R10.7 boundary: composite_score == 6.0 → HIGH."""
    target_id = uuid.uuid4()
    # Construct weights where two axes carry 0.3 + 0.3 = 0.6 of weight,
    # and target+baseline disagree on those two axes only at full
    # confidence: 10 * (0.3 + 0.3) = 6.0 → HIGH.
    weights = {"type": 0.3, "vendor": 0.3, "security_posture": 0.2, "mutability": 0.2}
    target = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.UEFI_DRIVER,
        vendor_label=VendorLabel.INTEL,
    )
    baseline = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.OS_KERNEL,
        vendor_label=VendorLabel.AMD,
    )
    finding = emit_classification_mismatch(
        target=target, baseline=baseline, matched_baseline_id=uuid.uuid4(), severity_weights=weights
    )
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.composite_score == 6.0
    assert finding.severity is SeverityLevel.HIGH


def test_severity_boundary_at_eight_is_critical() -> None:
    """R10.7 boundary: composite_score == 8.0 → CRITICAL (G4-B HARDEN)."""
    target_id = uuid.uuid4()
    # Weights: type 0.4 + vendor 0.4 = 0.8 of weight, disagree on both.
    # 10 * (0.4 + 0.4) = 8.0 → CRITICAL.
    weights = {"type": 0.4, "vendor": 0.4, "security_posture": 0.1, "mutability": 0.1}
    target = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.UEFI_DRIVER,
        vendor_label=VendorLabel.INTEL,
    )
    baseline = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.OS_KERNEL,
        vendor_label=VendorLabel.AMD,
    )
    finding = emit_classification_mismatch(
        target=target, baseline=baseline, matched_baseline_id=uuid.uuid4(), severity_weights=weights
    )
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.composite_score == 8.0
    assert finding.severity is SeverityLevel.CRITICAL


# --- Evidence and recommended_action ---


def test_evidence_classification_record_is_target() -> None:
    """R4.5: evidence.classification_record is the target record itself."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline = make_record(component_id=target_id, type_label=ComponentTypeLabel.OS_KERNEL)
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.classification_record is target


def test_evidence_other_fields_default() -> None:
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline = make_record(component_id=target_id, type_label=ComponentTypeLabel.OS_KERNEL)
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.evidence.matched_rule is None
    assert finding.evidence.matched_cve is None
    assert finding.evidence.matched_signature is None
    assert finding.evidence.raw_indicators == []


def test_recommended_action_is_empty_string() -> None:
    """v1 leaves recommended_actions empty per R17.3."""
    target_id = uuid.uuid4()
    target = make_record(component_id=target_id, type_label=ComponentTypeLabel.UEFI_DRIVER)
    baseline = make_record(component_id=target_id, type_label=ComponentTypeLabel.OS_KERNEL)
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert finding.recommended_action == ""


def test_title_and_description_mention_disagreeing_axes() -> None:
    target_id = uuid.uuid4()
    target = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.UEFI_DRIVER,
        vendor_label=VendorLabel.INTEL,
    )
    baseline = make_record(
        component_id=target_id,
        type_label=ComponentTypeLabel.OS_KERNEL,
        vendor_label=VendorLabel.AMD,
    )
    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline,
        matched_baseline_id=uuid.uuid4(),
        severity_weights=VALID_WEIGHTS,
    )
    assert "type" in finding.title
    assert "vendor" in finding.title
    assert "type" in finding.description
    assert "vendor" in finding.description
