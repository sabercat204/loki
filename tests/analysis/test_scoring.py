"""Tests for ``loki.analysis.scoring``.

Covers task 11 acceptance: each of the six scoring helpers obeys its
documented contract under both example-based assertions and Hypothesis-
generated inputs. The Composite_Score and severity-mapping invariants
are pinned via boundary-value tests because R10.7's mapping uses
``>=`` thresholds (8.0, 6.0, 4.0, 2.0).
"""

from __future__ import annotations

import math

from hypothesis import given
from hypothesis import strategies as st

from loki.analysis.scoring import (
    axis_score,
    base_severity_from_composite,
    composite_score,
    mutability_change,
    security_direction,
    signature_delta,
)
from loki.models import (
    AxisClassification,
    ClassificationMethod,
    ComponentTypeLabel,
    MutabilityChange,
    MutabilityLabel,
    SecurityDirection,
    SecurityPostureLabel,
    SeverityLevel,
    SignatureDelta,
    SignatureInfo,
    VendorLabel,
)


def _axis(label: str, *, confidence: float = 1.0) -> AxisClassification:
    return AxisClassification(
        label=label,
        confidence=confidence,
        method=ClassificationMethod.RULE,
    )


# --- axis_score ---


def test_axis_score_returns_zero_for_agreeing_labels() -> None:
    a = _axis(ComponentTypeLabel.UEFI_DRIVER, confidence=1.0)
    b = _axis(ComponentTypeLabel.UEFI_DRIVER, confidence=1.0)
    assert axis_score(a, b) == 0.0


def test_axis_score_returns_zero_even_at_partial_confidence_when_labels_agree() -> None:
    a = _axis(ComponentTypeLabel.UEFI_DRIVER, confidence=0.4)
    b = _axis(ComponentTypeLabel.UEFI_DRIVER, confidence=0.7)
    assert axis_score(a, b) == 0.0


def test_axis_score_at_full_confidence_disagree_is_one() -> None:
    a = _axis(ComponentTypeLabel.UEFI_DRIVER, confidence=1.0)
    b = _axis(ComponentTypeLabel.OS_KERNEL, confidence=1.0)
    assert axis_score(a, b) == 1.0


def test_axis_score_at_partial_confidence_disagree_is_product() -> None:
    a = _axis(ComponentTypeLabel.UEFI_DRIVER, confidence=0.7)
    b = _axis(ComponentTypeLabel.OS_KERNEL, confidence=0.5)
    assert math.isclose(axis_score(a, b), 0.35)


@given(
    label_a=st.sampled_from([str(x) for x in ComponentTypeLabel]),
    label_b=st.sampled_from([str(x) for x in ComponentTypeLabel]),
    conf_a=st.floats(min_value=0.0, max_value=1.0),
    conf_b=st.floats(min_value=0.0, max_value=1.0),
)
def test_axis_score_property_in_unit_interval(
    label_a: str, label_b: str, conf_a: float, conf_b: float
) -> None:
    """For any inputs, axis_score returns a value in [0.0, 1.0]."""
    score = axis_score(_axis(label_a, confidence=conf_a), _axis(label_b, confidence=conf_b))
    assert 0.0 <= score <= 1.0


# --- composite_score ---


_VALID_WEIGHTS = {
    "type": 0.4,
    "vendor": 0.2,
    "security_posture": 0.3,
    "mutability": 0.1,
}


def test_composite_score_all_zero_axis_scores_is_zero() -> None:
    assert (
        composite_score(
            type_score=0.0,
            vendor_score=0.0,
            security_score=0.0,
            mutability_score=0.0,
            severity_weights=_VALID_WEIGHTS,
        )
        == 0.0
    )


def test_composite_score_all_full_disagree_is_ten() -> None:
    """Every axis at score=1.0 with sum-to-1.0 weights produces 10.0."""
    result = composite_score(
        type_score=1.0,
        vendor_score=1.0,
        security_score=1.0,
        mutability_score=1.0,
        severity_weights=_VALID_WEIGHTS,
    )
    assert math.isclose(result, 10.0)


def test_composite_score_obeys_documented_formula() -> None:
    """Spot-check the formula at non-trivial inputs."""
    result = composite_score(
        type_score=0.5,
        vendor_score=0.0,
        security_score=1.0,
        mutability_score=0.25,
        severity_weights=_VALID_WEIGHTS,
    )
    # 10 * (0.4*0.5 + 0.2*0 + 0.3*1.0 + 0.1*0.25) = 10 * (0.2 + 0 + 0.3 + 0.025) = 5.25
    assert math.isclose(result, 5.25)


def test_composite_score_with_weight_only_on_one_axis() -> None:
    """When all weight is on one axis, only that axis's score contributes."""
    only_type = {"type": 1.0, "vendor": 0.0, "security_posture": 0.0, "mutability": 0.0}
    result = composite_score(
        type_score=0.7,
        vendor_score=0.5,
        security_score=0.5,
        mutability_score=0.5,
        severity_weights=only_type,
    )
    assert math.isclose(result, 7.0)


@given(
    type_s=st.floats(min_value=0.0, max_value=1.0),
    vendor_s=st.floats(min_value=0.0, max_value=1.0),
    security_s=st.floats(min_value=0.0, max_value=1.0),
    mutability_s=st.floats(min_value=0.0, max_value=1.0),
)
def test_composite_score_property_bounded(
    type_s: float, vendor_s: float, security_s: float, mutability_s: float
) -> None:
    """For any axis scores in [0,1], composite_score lies in [0.0, 10.0]."""
    result = composite_score(
        type_score=type_s,
        vendor_score=vendor_s,
        security_score=security_s,
        mutability_score=mutability_s,
        severity_weights=_VALID_WEIGHTS,
    )
    # Tiny floating-point slop is acceptable at the boundary.
    assert -1e-9 <= result <= 10.0 + 1e-9


# --- base_severity_from_composite ---


def test_severity_at_eight_is_critical() -> None:
    """Boundary inclusive at the top of each tier."""
    assert base_severity_from_composite(8.0) is SeverityLevel.CRITICAL


def test_severity_at_seven_ninety_nine_is_high() -> None:
    assert base_severity_from_composite(7.99) is SeverityLevel.HIGH


def test_severity_at_six_is_high() -> None:
    assert base_severity_from_composite(6.0) is SeverityLevel.HIGH


def test_severity_at_five_ninety_nine_is_medium() -> None:
    assert base_severity_from_composite(5.99) is SeverityLevel.MEDIUM


def test_severity_at_four_is_medium() -> None:
    assert base_severity_from_composite(4.0) is SeverityLevel.MEDIUM


def test_severity_at_three_ninety_nine_is_low() -> None:
    assert base_severity_from_composite(3.99) is SeverityLevel.LOW


def test_severity_at_two_is_low() -> None:
    assert base_severity_from_composite(2.0) is SeverityLevel.LOW


def test_severity_at_one_ninety_nine_is_info() -> None:
    assert base_severity_from_composite(1.99) is SeverityLevel.INFO


def test_severity_at_zero_is_info() -> None:
    assert base_severity_from_composite(0.0) is SeverityLevel.INFO


def test_severity_at_ten_is_critical() -> None:
    """The maximum possible Composite_Score still maps to CRITICAL."""
    assert base_severity_from_composite(10.0) is SeverityLevel.CRITICAL


@given(score=st.floats(min_value=0.0, max_value=10.0))
def test_severity_property_returns_valid_level(score: float) -> None:
    """For any score in [0.0, 10.0], the result is a valid SeverityLevel."""
    result = base_severity_from_composite(score)
    assert result in {
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        SeverityLevel.LOW,
        SeverityLevel.INFO,
    }


# --- security_direction ---


def test_security_direction_secure_to_vulnerable_is_degraded() -> None:
    direction = security_direction(
        target=SecurityPostureLabel.VULNERABLE,
        baseline=SecurityPostureLabel.SECURE,
    )
    assert direction is SecurityDirection.DEGRADED


def test_security_direction_vulnerable_to_secure_is_improved() -> None:
    direction = security_direction(
        target=SecurityPostureLabel.SECURE,
        baseline=SecurityPostureLabel.VULNERABLE,
    )
    assert direction is SecurityDirection.IMPROVED


def test_security_direction_unchanged_for_matching_pairs() -> None:
    """SECURE/SECURE and VULNERABLE/VULNERABLE both yield UNCHANGED."""
    assert (
        security_direction(target=SecurityPostureLabel.SECURE, baseline=SecurityPostureLabel.SECURE)
        is SecurityDirection.UNCHANGED
    )
    assert (
        security_direction(
            target=SecurityPostureLabel.VULNERABLE,
            baseline=SecurityPostureLabel.VULNERABLE,
        )
        is SecurityDirection.UNCHANGED
    )


def test_security_direction_unknown_on_either_side_is_unchanged() -> None:
    """Per R11.3: every other case, including any UNKNOWN, is UNCHANGED."""
    for tgt in SecurityPostureLabel:
        for base in SecurityPostureLabel:
            if SecurityPostureLabel.UNKNOWN in (tgt, base):
                assert security_direction(target=tgt, baseline=base) is SecurityDirection.UNCHANGED


# --- signature_delta ---


def _sig(*, present: bool) -> SignatureInfo:
    return SignatureInfo(present=present, verified=False)


def test_signature_delta_baseline_signed_target_unsigned_is_lost() -> None:
    delta = signature_delta(target=_sig(present=False), baseline=_sig(present=True))
    assert delta is SignatureDelta.LOST


def test_signature_delta_target_signed_baseline_unsigned_is_gained() -> None:
    delta = signature_delta(target=_sig(present=True), baseline=_sig(present=False))
    assert delta is SignatureDelta.GAINED


def test_signature_delta_both_signed_is_none() -> None:
    """v1 reserves CHANGED; both-signed maps to NONE per R12.3 + R12.4."""
    delta = signature_delta(target=_sig(present=True), baseline=_sig(present=True))
    assert delta is SignatureDelta.NONE


def test_signature_delta_both_unsigned_is_none() -> None:
    delta = signature_delta(target=_sig(present=False), baseline=_sig(present=False))
    assert delta is SignatureDelta.NONE


def test_signature_delta_none_target_is_none() -> None:
    """R12.4: either side None -> NONE."""
    delta = signature_delta(target=None, baseline=_sig(present=True))
    assert delta is SignatureDelta.NONE


def test_signature_delta_none_baseline_is_none() -> None:
    delta = signature_delta(target=_sig(present=True), baseline=None)
    assert delta is SignatureDelta.NONE


def test_signature_delta_both_none_is_none() -> None:
    delta = signature_delta(target=None, baseline=None)
    assert delta is SignatureDelta.NONE


def test_signature_delta_v1_never_returns_changed() -> None:
    """R12.3: v1 SHALL NOT emit SignatureDelta.CHANGED."""
    cases = [
        (None, None),
        (None, _sig(present=True)),
        (None, _sig(present=False)),
        (_sig(present=True), None),
        (_sig(present=False), None),
        (_sig(present=True), _sig(present=True)),
        (_sig(present=True), _sig(present=False)),
        (_sig(present=False), _sig(present=True)),
        (_sig(present=False), _sig(present=False)),
    ]
    for target, baseline in cases:
        assert signature_delta(target=target, baseline=baseline) is not SignatureDelta.CHANGED


# --- mutability_change ---


def test_mutability_change_readonly_to_mutable_is_became_mutable() -> None:
    change = mutability_change(target=MutabilityLabel.MUTABLE, baseline=MutabilityLabel.READONLY)
    assert change is MutabilityChange.BECAME_MUTABLE


def test_mutability_change_mutable_to_readonly_is_became_readonly() -> None:
    change = mutability_change(target=MutabilityLabel.READONLY, baseline=MutabilityLabel.MUTABLE)
    assert change is MutabilityChange.BECAME_READONLY


def test_mutability_change_unchanged_for_matching_pairs() -> None:
    assert (
        mutability_change(target=MutabilityLabel.READONLY, baseline=MutabilityLabel.READONLY)
        is MutabilityChange.NONE
    )
    assert (
        mutability_change(target=MutabilityLabel.MUTABLE, baseline=MutabilityLabel.MUTABLE)
        is MutabilityChange.NONE
    )


def test_mutability_change_unknown_on_either_side_is_none() -> None:
    """R13.3: every other case, including any UNKNOWN, is NONE."""
    for tgt in MutabilityLabel:
        for base in MutabilityLabel:
            if MutabilityLabel.UNKNOWN in (tgt, base):
                assert mutability_change(target=tgt, baseline=base) is MutabilityChange.NONE


# --- end-to-end: vendor axis sanity ---


def test_vendor_axis_score_smoke() -> None:
    """Smoke that the vendor axis scoring path works end-to-end."""
    intel = _axis(VendorLabel.INTEL, confidence=1.0)
    amd = _axis(VendorLabel.AMD, confidence=0.9)
    score = axis_score(intel, amd)
    assert math.isclose(score, 0.9)
