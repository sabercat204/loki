"""Tests for ``loki.analysis.posture.derive_posture_rating``.

Covers task 12 acceptance: each rule of the six-rule cascade fires on
the documented input shape; boundary values are inclusive at the top of
each tier; cascade ordering is correct (rule 1 wins over rule 2, etc.);
the cascade never emits ``HARDENED``; multi-finding monotonicity holds.

Validates Property 49 indirectly through example-based + Hypothesis-
generated coverage.
"""

from __future__ import annotations

import uuid

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.analysis.findings import derive_finding_id
from loki.analysis.posture import derive_posture_rating
from loki.models import (
    DeviationScore,
    FindingEvidence,
    FindingRecord,
    MutabilityChange,
    PostureRating,
    SecurityDirection,
    SeverityLevel,
    SignatureDelta,
)

# --- Test fixture helpers ---


def _deviation_score(*, composite: float, rank: int = 1) -> DeviationScore:
    return DeviationScore(
        base_severity=SeverityLevel.HIGH,
        component_criticality=0.5,
        security_direction=SecurityDirection.UNCHANGED,
        signature_delta=SignatureDelta.NONE,
        cve_introduced=False,
        mutability_change=MutabilityChange.NONE,
        composite_score=composite,
        priority_rank=rank,
    )


def _finding(
    *,
    category: str,
    severity: SeverityLevel,
    composite: float | None = None,
) -> FindingRecord:
    cid = uuid.uuid4()
    bid = uuid.uuid4()
    deviation = _deviation_score(composite=composite) if composite is not None else None
    evidence = FindingEvidence(
        classification_record=None,
        matched_rule=None,
        matched_cve=None,
        matched_signature=None,
        raw_indicators=[],
        deviation_score=deviation,
    )
    return FindingRecord(
        finding_id=derive_finding_id(
            baseline_id=bid,
            finding_category=category,
            target_component_id=cid,
        ),
        component_id=cid,
        severity=severity,
        category=category,
        title="t",
        description="d",
        evidence=evidence,
        recommended_action="",
    )


# --- Rule 5 (BASELINE) ---


def test_empty_findings_is_baseline() -> None:
    assert derive_posture_rating([]) is PostureRating.BASELINE


# --- Rule 1a: signature_regression: HIGH ---


def test_signature_regression_high_alone_is_compromised() -> None:
    findings = [_finding(category="signature_regression", severity=SeverityLevel.HIGH)]
    assert derive_posture_rating(findings) is PostureRating.COMPROMISED


def test_signature_regression_medium_alone_does_not_trigger_compromised() -> None:
    """R5.6: target-signed-baseline-unsigned is MEDIUM; must NOT fire rule 1a."""
    findings = [_finding(category="signature_regression", severity=SeverityLevel.MEDIUM)]
    # Falls through to catch-all rule 4 -> DEGRADED.
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


# --- Rule 1b: missing_required_component ---


def test_missing_required_component_alone_is_compromised() -> None:
    findings = [_finding(category="missing_required_component", severity=SeverityLevel.HIGH)]
    assert derive_posture_rating(findings) is PostureRating.COMPROMISED


def test_missing_required_component_at_lower_severity_still_compromised() -> None:
    """Rule 1b fires on category presence; severity is not consulted."""
    findings = [_finding(category="missing_required_component", severity=SeverityLevel.MEDIUM)]
    assert derive_posture_rating(findings) is PostureRating.COMPROMISED


# --- Rule 1c: classification_mismatch CRITICAL (G4-B HARDEN escalation) ---


def test_classification_mismatch_at_8_0_is_compromised() -> None:
    """Boundary inclusive: composite_score == 8.0 -> CRITICAL -> COMPROMISED."""
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.CRITICAL,
            composite=8.0,
        )
    ]
    assert derive_posture_rating(findings) is PostureRating.COMPROMISED


def test_classification_mismatch_at_7_99_is_at_risk() -> None:
    """Just below the CRITICAL boundary -> HIGH -> AT_RISK."""
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.HIGH,
            composite=7.99,
        )
    ]
    assert derive_posture_rating(findings) is PostureRating.AT_RISK


def test_classification_mismatch_at_max_score_is_compromised() -> None:
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.CRITICAL,
            composite=10.0,
        )
    ]
    assert derive_posture_rating(findings) is PostureRating.COMPROMISED


# --- Rule 2 (AT_RISK) ---


def test_classification_mismatch_at_6_0_is_at_risk() -> None:
    """Boundary inclusive: composite_score == 6.0 -> HIGH -> AT_RISK."""
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.HIGH,
            composite=6.0,
        )
    ]
    assert derive_posture_rating(findings) is PostureRating.AT_RISK


def test_classification_mismatch_at_5_99_is_degraded() -> None:
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.MEDIUM,
            composite=5.99,
        )
    ]
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


# --- Rule 3 (DEGRADED — score-based) ---


def test_classification_mismatch_at_2_0_is_degraded() -> None:
    """Boundary inclusive: composite_score == 2.0 -> LOW -> DEGRADED."""
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.LOW,
            composite=2.0,
        )
    ]
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


def test_classification_mismatch_at_4_0_is_degraded() -> None:
    """Mid-range MEDIUM mismatch -> DEGRADED."""
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.MEDIUM,
            composite=4.0,
        )
    ]
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


def test_classification_mismatch_at_1_99_falls_to_catch_all_degraded() -> None:
    """Below 2.0 (INFO severity) -> rule 4 catch-all -> DEGRADED."""
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.INFO,
            composite=1.99,
        )
    ]
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


# --- Rule 4 (G3-A HARDEN catch-all) ---


def test_unexpected_component_alone_is_degraded_via_catch_all() -> None:
    findings = [_finding(category="unexpected_component", severity=SeverityLevel.MEDIUM)]
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


def test_classification_gap_alone_is_degraded_via_catch_all() -> None:
    findings = [_finding(category="classification_gap", severity=SeverityLevel.LOW)]
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


def test_analysis_cancelled_alone_is_degraded_via_catch_all() -> None:
    """A run cancelled with no real findings still has the marker -> DEGRADED."""
    findings = [_finding(category="analysis_cancelled", severity=SeverityLevel.INFO)]
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


def test_mixed_medium_low_findings_via_catch_all() -> None:
    """Multiple MEDIUM/LOW non-rule-1 findings still land at DEGRADED."""
    findings = [
        _finding(category="unexpected_component", severity=SeverityLevel.MEDIUM),
        _finding(category="signature_regression", severity=SeverityLevel.MEDIUM),
        _finding(category="classification_gap", severity=SeverityLevel.LOW),
    ]
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


# --- Cascade ordering ---


def test_signature_regression_high_wins_over_classification_mismatch_high() -> None:
    """Rule 1a beats rule 2."""
    findings = [
        _finding(category="signature_regression", severity=SeverityLevel.HIGH),
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.HIGH,
            composite=6.0,
        ),
    ]
    assert derive_posture_rating(findings) is PostureRating.COMPROMISED


def test_classification_mismatch_critical_wins_over_at_risk() -> None:
    """Rule 1c beats rule 2 even when an AT_RISK finding is also present."""
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.CRITICAL,
            composite=8.5,
        ),
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.HIGH,
            composite=6.0,
        ),
    ]
    assert derive_posture_rating(findings) is PostureRating.COMPROMISED


def test_missing_required_wins_over_classification_mismatch_low() -> None:
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.LOW,
            composite=2.5,
        ),
        _finding(category="missing_required_component", severity=SeverityLevel.HIGH),
    ]
    assert derive_posture_rating(findings) is PostureRating.COMPROMISED


def test_at_risk_wins_over_degraded() -> None:
    """Rule 2 beats rule 3 + rule 4."""
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.HIGH,
            composite=6.5,
        ),
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.LOW,
            composite=2.5,
        ),
        _finding(category="unexpected_component", severity=SeverityLevel.MEDIUM),
    ]
    assert derive_posture_rating(findings) is PostureRating.AT_RISK


def test_max_score_drives_rule_2_not_average() -> None:
    """The cascade reads the MAXIMUM mismatch score, not the average."""
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.HIGH,
            composite=6.0,
        ),
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.INFO,
            composite=0.5,
        ),
    ]
    assert derive_posture_rating(findings) is PostureRating.AT_RISK


# --- HARDENED never emitted ---


def test_hardened_never_returned_from_any_input() -> None:
    """HARDENED is reserved for a future revision (R17.5)."""
    cases = [
        [],
        [_finding(category="unexpected_component", severity=SeverityLevel.MEDIUM)],
        [_finding(category="missing_required_component", severity=SeverityLevel.HIGH)],
        [_finding(category="signature_regression", severity=SeverityLevel.HIGH)],
        [_finding(category="signature_regression", severity=SeverityLevel.MEDIUM)],
        [_finding(category="classification_gap", severity=SeverityLevel.LOW)],
        [_finding(category="analysis_cancelled", severity=SeverityLevel.INFO)],
        [
            _finding(
                category="classification_mismatch",
                severity=SeverityLevel.CRITICAL,
                composite=10.0,
            )
        ],
    ]
    for findings in cases:
        assert derive_posture_rating(findings) is not PostureRating.HARDENED


# --- Multi-finding monotonicity ---


def test_adding_signature_regression_high_to_baseline_yields_compromised() -> None:
    new_findings = [_finding(category="signature_regression", severity=SeverityLevel.HIGH)]
    assert derive_posture_rating(new_findings) is PostureRating.COMPROMISED


def test_adding_signature_regression_high_to_at_risk_yields_compromised() -> None:
    findings = [
        _finding(
            category="classification_mismatch",
            severity=SeverityLevel.HIGH,
            composite=6.5,
        ),
        _finding(category="signature_regression", severity=SeverityLevel.HIGH),
    ]
    assert derive_posture_rating(findings) is PostureRating.COMPROMISED


# --- Defensive: missing deviation_score ---


def test_classification_mismatch_without_deviation_score_falls_through_to_catch_all() -> None:
    """Defensive: if a classification_mismatch lacks a DeviationScore (e.g. a hand-built
    test fixture), the cascade treats its score as 0.0 and the finding still
    triggers rule 4 (catch-all DEGRADED) because at least one finding is emitted.
    """
    findings = [_finding(category="classification_mismatch", severity=SeverityLevel.INFO)]
    # composite=None -> deviation_score=None -> _composite_score_or_zero returns 0.0
    # -> rule 1c, 2, 3 all skip -> rule 4 catch-all fires.
    assert derive_posture_rating(findings) is PostureRating.DEGRADED


# --- Property: closed function (Hypothesis) ---


@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
@given(
    sig_high=st.booleans(),
    sig_medium=st.booleans(),
    missing=st.booleans(),
    mismatch_score=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0)),
    unexpected=st.booleans(),
    gap=st.booleans(),
    cancelled=st.booleans(),
)
def test_property_49_cascade_returns_valid_rating(
    sig_high: bool,
    sig_medium: bool,
    missing: bool,
    mismatch_score: float | None,
    unexpected: bool,
    gap: bool,
    cancelled: bool,
) -> None:
    findings: list[FindingRecord] = []
    if sig_high:
        findings.append(_finding(category="signature_regression", severity=SeverityLevel.HIGH))
    if sig_medium:
        findings.append(_finding(category="signature_regression", severity=SeverityLevel.MEDIUM))
    if missing:
        findings.append(
            _finding(category="missing_required_component", severity=SeverityLevel.HIGH)
        )
    if mismatch_score is not None:
        findings.append(
            _finding(
                category="classification_mismatch",
                severity=SeverityLevel.HIGH,
                composite=mismatch_score,
            )
        )
    if unexpected:
        findings.append(_finding(category="unexpected_component", severity=SeverityLevel.MEDIUM))
    if gap:
        findings.append(_finding(category="classification_gap", severity=SeverityLevel.LOW))
    if cancelled:
        findings.append(_finding(category="analysis_cancelled", severity=SeverityLevel.INFO))

    rating = derive_posture_rating(findings)
    assert rating in {
        PostureRating.COMPROMISED,
        PostureRating.AT_RISK,
        PostureRating.DEGRADED,
        PostureRating.BASELINE,
    }
    assert rating is not PostureRating.HARDENED
