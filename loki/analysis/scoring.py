"""Axis_Score, Composite_Score, and ``DeviationScore`` axis helpers.

Six pure functions backing the analysis engine's
``classification_mismatch`` finding emitter (Wave 5, task 13). Each
function is deterministic, side-effect free, and exposed individually
so the property-based test suite (P46) can exercise them without
constructing a full pipeline.

The functions:

- ``axis_score`` (R9.3): one Axis_Score in ``[0.0, 1.0]`` from a pair
  of ``AxisClassification`` instances.
- ``composite_score`` (R9.4): the weighted Composite_Score in
  ``[0.0, 10.0]`` from four Axis_Scores plus the
  ``severity_weights`` dict.
- ``base_severity_from_composite`` (R10.7): the closed mapping from
  Composite_Score to ``SeverityLevel``.
- ``security_direction`` (R11): SECURE/VULNERABLE/UNKNOWN -> the
  three-way ``SecurityDirection``.
- ``signature_delta`` (R12): the four-way ``SignatureDelta`` from a
  pair of ``SignatureInfo`` values. v1 never returns ``CHANGED``
  (R12.3 reservation).
- ``mutability_change`` (R13): READONLY/MUTABLE/UNKNOWN -> the
  three-way ``MutabilityChange``.

The ``severity_weights`` dict is contracted by R14.1 + the matching
module's ``validate_analysis_config`` to carry exactly the four
keys ``{"type", "vendor", "security_posture", "mutability"}`` whose
values sum to 1.0; ``composite_score`` does not re-validate the
keyset, since the pipeline runs validation at construction time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from loki.models.enums import (
    MutabilityChange,
    MutabilityLabel,
    SecurityDirection,
    SecurityPostureLabel,
    SeverityLevel,
    SignatureDelta,
)

if TYPE_CHECKING:
    from loki.models.classification import AxisClassification, SignatureInfo

__all__ = [
    "axis_score",
    "base_severity_from_composite",
    "composite_score",
    "mutability_change",
    "security_direction",
    "signature_delta",
]

#: The four severity-weight keys ``composite_score`` reads, in the
#: order matching the four ``ClassificationRecord`` axes.
_AXIS_KEYS: tuple[str, str, str, str] = (
    "type",
    "vendor",
    "security_posture",
    "mutability",
)


def axis_score(
    target_axis: AxisClassification,
    baseline_axis: AxisClassification,
) -> float:
    """Compute one Axis_Score (R9.3).

    Returns ``0.0`` when the two axis labels agree; returns
    ``target_axis.confidence * baseline_axis.confidence`` when they
    disagree. The result lies in ``[0.0, 1.0]`` because both
    confidences are constrained to ``[0.0, 1.0]`` by the model layer.
    """
    if target_axis.label == baseline_axis.label:
        return 0.0
    return target_axis.confidence * baseline_axis.confidence


def composite_score(
    *,
    type_score: float,
    vendor_score: float,
    security_score: float,
    mutability_score: float,
    severity_weights: dict[str, float],
) -> float:
    """Compute the Composite_Score (R9.4).

    The formula is::

        10.0 * (
            w_type * s_type
            + w_vendor * s_vendor
            + w_security_posture * s_security
            + w_mutability * s_mutability
        )

    where ``w_*`` come from ``severity_weights`` and ``s_*`` are the
    four Axis_Scores. The pipeline guarantees ``severity_weights``
    carries exactly the four keys per R14.1 (the matching module's
    ``validate_analysis_config`` enforces this); the model layer's
    sum-to-1.0 validator caps the maximum at 10.0 when every axis
    disagrees at full confidence on both sides.
    """
    weighted = (
        severity_weights[_AXIS_KEYS[0]] * type_score
        + severity_weights[_AXIS_KEYS[1]] * vendor_score
        + severity_weights[_AXIS_KEYS[2]] * security_score
        + severity_weights[_AXIS_KEYS[3]] * mutability_score
    )
    return 10.0 * weighted


def base_severity_from_composite(score: float) -> SeverityLevel:
    """Derive ``base_severity`` from Composite_Score per R10.7.

    Closed mapping (boundary values inclusive at the top of each tier)::

        score >= 8.0 -> CRITICAL
        6.0 <= score < 8.0 -> HIGH
        4.0 <= score < 6.0 -> MEDIUM
        2.0 <= score < 4.0 -> LOW
        score < 2.0 -> INFO
    """
    if score >= 8.0:
        return SeverityLevel.CRITICAL
    if score >= 6.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    if score >= 2.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def security_direction(
    target: str,
    baseline: str,
) -> SecurityDirection:
    """Compute ``SecurityDirection`` per R11.

    The two arguments are ``str`` because the model layer's
    ``AxisClassification.label`` is typed as ``str`` (rules may produce
    any label string; the StrEnum values are the canonical set but
    not the only permitted values). Comparisons against
    ``SecurityPostureLabel`` members work via StrEnum equality:
    ``SecurityPostureLabel.SECURE == "SECURE"``.

    DEGRADED: target=VULNERABLE, baseline=SECURE.
    IMPROVED: target=SECURE, baseline=VULNERABLE.
    UNCHANGED: every other case (including any UNKNOWN on either side
    or any non-canonical label string).
    """
    if target == SecurityPostureLabel.VULNERABLE and baseline == SecurityPostureLabel.SECURE:
        return SecurityDirection.DEGRADED
    if target == SecurityPostureLabel.SECURE and baseline == SecurityPostureLabel.VULNERABLE:
        return SecurityDirection.IMPROVED
    return SecurityDirection.UNCHANGED


def signature_delta(
    target: SignatureInfo | None,
    baseline: SignatureInfo | None,
) -> SignatureDelta:
    """Compute ``SignatureDelta`` per R12.

    LOST:    baseline.present=True,  target.present=False.
    GAINED:  baseline.present=False, target.present=True.
    NONE:    every other case (including either side ``None``).
    CHANGED: reserved for a future revision; v1 SHALL NOT emit it
             (R12.3) because v1 does not parse signer identity.
    """
    if target is None or baseline is None:
        return SignatureDelta.NONE
    if baseline.present is True and target.present is False:
        return SignatureDelta.LOST
    if baseline.present is False and target.present is True:
        return SignatureDelta.GAINED
    return SignatureDelta.NONE


def mutability_change(
    target: str,
    baseline: str,
) -> MutabilityChange:
    """Compute ``MutabilityChange`` per R13.

    The two arguments are ``str`` for the same reason as
    ``security_direction``: ``AxisClassification.label`` is typed as
    ``str`` at the model layer.

    BECAME_MUTABLE:  baseline=READONLY, target=MUTABLE.
    BECAME_READONLY: baseline=MUTABLE,  target=READONLY.
    NONE:            every other case (including any UNKNOWN or
                     non-canonical label string).
    """
    if baseline == MutabilityLabel.READONLY and target == MutabilityLabel.MUTABLE:
        return MutabilityChange.BECAME_MUTABLE
    if baseline == MutabilityLabel.MUTABLE and target == MutabilityLabel.READONLY:
        return MutabilityChange.BECAME_READONLY
    return MutabilityChange.NONE
