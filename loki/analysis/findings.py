"""Per-category finding emitters and the ``derive_finding_id`` helper.

This module hosts:

- ``derive_finding_id`` (R15.7): the deterministic UUIDv5 derivation
  every emitter routes through to compute ``FindingRecord.finding_id``.
- ``ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID`` (R7.2): the fixed UUID
  the Cancellation_Marker carries as ``component_id``. Derived once at
  import time from the ``LOKI_NAMESPACE`` and the literal string
  ``"analysis-cancelled"``; cannot collide with any
  ``ExtractedComponent.component_id`` because real component_ids are
  derived from ``(file_hash, offset, raw_hash)`` tuples per the
  extraction pipeline's determinism contract.
- ``make_cancellation_marker`` (R7.1-R7.7): the constructor for the
  ``analysis_cancelled`` Cancellation_Marker finding.

Per-category emitters land in Wave 5 (tasks 13-17). The analysis
pipeline orchestrates emitter calls; the emitters themselves are pure
functions with no logging or other side effects.
"""

from __future__ import annotations

import uuid

from loki.analysis.scoring import (
    axis_score,
    base_severity_from_composite,
    composite_score,
    mutability_change,
    security_direction,
    signature_delta,
)
from loki.models.analysis import DeviationScore, FindingEvidence, FindingRecord
from loki.models.classification import ClassificationRecord
from loki.models.enums import SeverityLevel
from loki.models.firmware import LOKI_NAMESPACE

__all__ = [
    "ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID",
    "derive_finding_id",
    "emit_classification_gap",
    "emit_classification_mismatch",
    "emit_missing_required_component",
    "emit_signature_expired",
    "emit_signature_regression",
    "emit_unexpected_component",
    "make_cancellation_marker",
]

#: Deterministic sentinel ``component_id`` for the Cancellation_Marker (R7.2).
#: Derived from the fixed string ``"analysis-cancelled"`` so the value is
#: bit-equal across runs and across hosts. Real ``component_id`` values
#: are derived from ``(file_hash, offset, raw_hash)`` tuples per the
#: extraction pipeline; this sentinel cannot collide with any of them
#: because no real component_id can be derived from the literal string
#: ``"analysis-cancelled"``.
ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID: uuid.UUID = uuid.uuid5(
    LOKI_NAMESPACE, "analysis-cancelled"
)


def derive_finding_id(
    *,
    baseline_id: uuid.UUID,
    finding_category: str,
    target_component_id: uuid.UUID,
) -> uuid.UUID:
    """Derive a ``FindingRecord.finding_id`` deterministically (R15.7).

    Returns ``uuid.uuid5(LOKI_NAMESPACE, f"{baseline_id}:{finding_category}:{target_component_id}")``.

    The same ``(baseline_id, finding_category, target_component_id)``
    tuple always produces the same UUID across runs and across hosts.
    Different baselines, different categories, and different target
    component_ids each produce distinct UUIDs.

    The third tuple element is named ``target_component_id`` for
    historical reasons; for ``missing_required_component`` findings
    the value is sourced from the baseline manifest record (R8.3),
    and for the Cancellation_Marker it is the
    ``ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID`` (R7.7). The TENSION
    pass's M1 cosmetic recommendation noted the naming gap; the
    formula is unambiguous as-is and a future cosmetic amendment may
    rename the parameter without changing behaviour.
    """
    name = f"{baseline_id}:{finding_category}:{target_component_id}"
    return uuid.uuid5(LOKI_NAMESPACE, name)


def make_cancellation_marker(
    *,
    baseline_id: uuid.UUID,
    cancelled_at_index: int,
) -> FindingRecord:
    """Construct the Cancellation_Marker finding (R7.1-R7.7).

    Called exactly once per cancelled run, after partial findings have
    already been emitted. The 1-based ``cancelled_at_index`` is the
    position of the Target_Record that was about to be processed when
    the cancellation token returned ``True``.

    The marker carries fixed, non-leaking ``title`` and ``description``
    strings (R7.5) and a single-entry
    ``evidence.raw_indicators=["cancelled-at-index=N"]`` (R7.4). The
    index value is recorded in the persisted report only and SHALL
    NOT appear in any log record (Property 50; the no-leakage AST
    audit in Wave 7's task 22 will pin this).

    The returned finding is a Pydantic-validated ``FindingRecord``;
    construction of the fields documented in R7 produces no
    validation errors under v1's contracts.
    """
    finding_id = derive_finding_id(
        baseline_id=baseline_id,
        finding_category="analysis_cancelled",
        target_component_id=ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID,
    )
    return FindingRecord(
        finding_id=finding_id,
        component_id=ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID,
        severity=SeverityLevel.INFO,
        category="analysis_cancelled",
        title="analysis cancelled",
        description="cooperative cancellation observed; partial findings returned",
        evidence=FindingEvidence(
            classification_record=None,
            matched_rule=None,
            matched_cve=None,
            matched_signature=None,
            raw_indicators=[f"cancelled-at-index={cancelled_at_index}"],
            deviation_score=None,
        ),
        recommended_action="",
    )


def emit_classification_mismatch(
    *,
    target: ClassificationRecord,
    baseline: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
    severity_weights: dict[str, float],
    cve_score_bump: float = 0.0,
) -> FindingRecord:
    """Emit a ``classification_mismatch`` finding (R4.1-R4.8).

    Pre-condition enforced by the pipeline (not the emitter): at least
    one of the four axis labels disagrees between ``target`` and
    ``baseline``, per R4.2. The emitter does not double-check; it
    constructs the finding unconditionally and lets the pipeline
    decide whether to call it.

    The emitter:

    - Computes four ``Axis_Score`` values via ``axis_score`` for each
      axis (R9.2-R9.3).
    - Computes ``Composite_Score`` via ``composite_score`` (R9.4).
    - Derives ``base_severity`` from ``Composite_Score`` per R10.7.
    - Computes the three ``DeviationScore`` axis fields
      (``security_direction``, ``signature_delta``,
      ``mutability_change``) per R11 / R12 / R13.
    - Sets ``component_criticality`` to ``baseline.composite_confidence``
      per R9.7.
    - Determines ``cve_introduced`` from target vs baseline
      ``cve_matches`` (consumer-wiring R2.2-R2.3).
    - When ``cve_introduced`` is True, bumps composite_score by
      ``cve_score_bump`` before clamping (consumer-wiring R2.4).
    - Constructs a ``DeviationScore`` with ``priority_rank=0`` as a
      placeholder. The pipeline's second pass overwrites this with the
      real rank per R9.10.
    - Constructs the ``FindingRecord`` with deterministic ``finding_id``
      and templated ``title`` + ``description`` strings derived from
      the disagreeing axes (both fields are in the
      Forbidden_Leakage_Field_Set; never logged).

    The emitter is pure (no logging, no I/O, no side effects beyond
    its return value).
    """
    type_score = axis_score(target.type_axis, baseline.type_axis)
    vendor_score = axis_score(target.vendor_axis, baseline.vendor_axis)
    security_score = axis_score(target.security_axis, baseline.security_axis)
    mutability_score = axis_score(target.mutability_axis, baseline.mutability_axis)

    composite = composite_score(
        type_score=type_score,
        vendor_score=vendor_score,
        security_score=security_score,
        mutability_score=mutability_score,
        severity_weights=severity_weights,
    )

    # CVE introduction detection (consumer-wiring R2.1-R2.3)
    target_cves = set(target.cve_matches)
    baseline_cves = set(baseline.cve_matches)
    cve_introduced = bool(target_cves - baseline_cves)

    # Lex-first for v1; future revision may select by highest-CVSS
    # when cve_matches carries score data (consumer-wiring G2-B).
    matched_cve: str | None = target.cve_matches[0] if target.cve_matches else None

    # CVE introduction bumps composite score (consumer-wiring R2.4)
    if cve_introduced:
        composite += cve_score_bump

    # Floating-point accumulation can push the composite slightly above
    # 10.0 even when every input is in [0.0, 1.0] and weights sum to
    # 1.0 within tolerance (e.g. 10 * (0.4+0.2+0.3+0.1) = 10.0+2e-15).
    # The model layer's strict ``<= 10.0`` validator on
    # ``DeviationScore.composite_score`` rejects such values; clamp at
    # the producer side to keep the model contract intact.
    composite = max(0.0, min(composite, 10.0))
    severity = base_severity_from_composite(composite)

    deviation = DeviationScore(
        base_severity=severity,
        component_criticality=baseline.composite_confidence,
        security_direction=security_direction(
            target=target.security_axis.label,
            baseline=baseline.security_axis.label,
        ),
        signature_delta=signature_delta(
            target=target.signature_info,
            baseline=baseline.signature_info,
        ),
        cve_introduced=cve_introduced,
        mutability_change=mutability_change(
            target=target.mutability_axis.label,
            baseline=baseline.mutability_axis.label,
        ),
        composite_score=composite,
        # Placeholder; pipeline overwrites with the real rank in a
        # second pass per R9.10.
        priority_rank=1,
    )

    disagreeing_axes = _disagreeing_axes(target=target, baseline=baseline)
    title, description = _classification_mismatch_text(
        disagreeing_axes=disagreeing_axes,
    )

    finding_id = derive_finding_id(
        baseline_id=matched_baseline_id,
        finding_category="classification_mismatch",
        target_component_id=target.component_id,
    )
    return FindingRecord(
        finding_id=finding_id,
        component_id=target.component_id,
        severity=severity,
        category="classification_mismatch",
        title=title,
        description=description,
        evidence=FindingEvidence(
            classification_record=target,
            matched_rule=None,
            matched_cve=matched_cve,
            matched_signature=None,
            raw_indicators=[],
            deviation_score=deviation,
        ),
        recommended_action="",
    )


def _disagreeing_axes(
    *,
    target: ClassificationRecord,
    baseline: ClassificationRecord,
) -> list[str]:
    """Return the names of the axes whose labels disagree."""
    disagreeing: list[str] = []
    if target.type_axis.label != baseline.type_axis.label:
        disagreeing.append("type")
    if target.vendor_axis.label != baseline.vendor_axis.label:
        disagreeing.append("vendor")
    if target.security_axis.label != baseline.security_axis.label:
        disagreeing.append("security_posture")
    if target.mutability_axis.label != baseline.mutability_axis.label:
        disagreeing.append("mutability")
    return disagreeing


def _classification_mismatch_text(*, disagreeing_axes: list[str]) -> tuple[str, str]:
    """Templated title + description strings for a classification_mismatch.

    The pipeline does not log either string (Forbidden_Leakage_Field_Set
    per R20.5). Both are persisted in the report only.
    """
    if not disagreeing_axes:
        # Defensive — the pipeline does not call the emitter when no
        # axis disagrees, but if it ever does, surface a clear marker.
        title = "classification mismatch (no axis disagreement)"
        description = (
            "classification_mismatch finding emitted without any axis label "
            "disagreement; this should not happen under v1's pipeline logic"
        )
    else:
        joined = ", ".join(disagreeing_axes)
        title = f"classification mismatch on {joined}"
        description = (
            f"target classification disagrees with baseline on the following axes: {joined}"
        )
    return title, description


def emit_signature_regression(
    *,
    target: ClassificationRecord,
    baseline: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
) -> FindingRecord:
    """Emit a ``signature_regression`` finding (R5.1-R5.6).

    Pre-conditions enforced by the pipeline: both ``target.signature_info``
    and ``baseline.signature_info`` are non-None, and their ``present``
    fields differ.

    Severity is fixed per R5.6:

    - ``HIGH`` when the regression direction is "baseline-signed,
      target-unsigned" (signature lost).
    - ``MEDIUM`` when the regression direction is "target-signed,
      baseline-unsigned" (signature gained, treated as still
      surfacing-worthy because operators may want to know about new
      signing).

    ``evidence.matched_signature`` carries one of the two literal
    strings ``"BASELINE_SIGNED"`` or ``"TARGET_SIGNED"`` per R5.5;
    the engine never sets a signer identity in v1 (signature
    verification is out of scope per the requirements introduction).

    The emitter is pure. It does not construct a ``DeviationScore``
    (R9.11; only ``classification_mismatch`` findings carry one).
    """
    # Pre-condition asserted by the pipeline; defensive error if it
    # ever isn't (we don't want to emit a malformed finding).
    if target.signature_info is None or baseline.signature_info is None:
        msg = (
            "signature_regression emitter pre-condition violated: both "
            "target.signature_info and baseline.signature_info must be non-None"
        )
        raise ValueError(msg)

    baseline_signed = baseline.signature_info.present
    target_signed = target.signature_info.present
    if baseline_signed and not target_signed:
        severity = SeverityLevel.HIGH
        matched_signature = "BASELINE_SIGNED"
        title = "signature regression: signature lost"
        description = "baseline component was signed; target component is unsigned"
    elif target_signed and not baseline_signed:
        severity = SeverityLevel.MEDIUM
        matched_signature = "TARGET_SIGNED"
        title = "signature regression: signature gained"
        description = "baseline component was unsigned; target component is now signed"
    else:
        # Pre-condition asserted by the pipeline; defensive.
        msg = (
            "signature_regression emitter pre-condition violated: "
            "target.signature_info.present must differ from "
            "baseline.signature_info.present"
        )
        raise ValueError(msg)

    finding_id = derive_finding_id(
        baseline_id=matched_baseline_id,
        finding_category="signature_regression",
        target_component_id=target.component_id,
    )
    return FindingRecord(
        finding_id=finding_id,
        component_id=target.component_id,
        severity=severity,
        category="signature_regression",
        title=title,
        description=description,
        evidence=FindingEvidence(
            classification_record=target,
            matched_rule=None,
            matched_cve=None,
            matched_signature=matched_signature,
            raw_indicators=[],
            deviation_score=None,
        ),
        recommended_action="",
    )


def emit_unexpected_component(
    *,
    target: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
) -> FindingRecord:
    """Emit an ``unexpected_component`` finding (R6.1-R6.7).

    Pre-condition enforced by the pipeline: ``target.component_id`` does
    not appear in the matched baseline's manifest.

    Severity is fixed at ``MEDIUM`` per R6.5; v1 does not weight by
    axis-specific risk. ``evidence.classification_record`` carries the
    unpaired Target_Record itself.

    The emitter is pure. It does not construct a ``DeviationScore``
    (R9.11).
    """
    finding_id = derive_finding_id(
        baseline_id=matched_baseline_id,
        finding_category="unexpected_component",
        target_component_id=target.component_id,
    )
    return FindingRecord(
        finding_id=finding_id,
        component_id=target.component_id,
        severity=SeverityLevel.MEDIUM,
        category="unexpected_component",
        title="unexpected component",
        description=("target component_id has no counterpart in the matched baseline"),
        evidence=FindingEvidence(
            classification_record=target,
            matched_rule=None,
            matched_cve=None,
            matched_signature=None,
            raw_indicators=[],
            deviation_score=None,
        ),
        recommended_action="",
    )


def emit_missing_required_component(
    *,
    baseline: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
) -> FindingRecord:
    """Emit a ``missing_required_component`` finding (R8.1-R8.6).

    Pre-condition enforced by the pipeline: ``baseline.component_id``
    does not appear in the target_records sequence.

    Severity is fixed at ``HIGH`` per R8.5; missing-required findings
    represent removal of a component that the baseline curator named
    as expected, and the strict default reflects that.

    Per R8.3, ``component_id`` on the emitted ``FindingRecord`` is the
    BASELINE record's ``component_id`` (the field is non-optional on
    ``FindingRecord``; the value comes from the baseline manifest
    because no target record exists with this id). The
    ``finding_id`` derivation uses the baseline's ``component_id`` as
    its ``target_component_id`` argument, per R15.7's note that the
    third tuple element is sourced from the relevant side per
    finding category.

    The emitter is pure. It does not construct a ``DeviationScore``
    (R9.11).
    """
    finding_id = derive_finding_id(
        baseline_id=matched_baseline_id,
        finding_category="missing_required_component",
        target_component_id=baseline.component_id,
    )
    return FindingRecord(
        finding_id=finding_id,
        component_id=baseline.component_id,
        severity=SeverityLevel.HIGH,
        category="missing_required_component",
        title="missing required component",
        description=("baseline component_id has no counterpart in the target image"),
        evidence=FindingEvidence(
            classification_record=baseline,
            matched_rule=None,
            matched_cve=None,
            matched_signature=None,
            raw_indicators=[],
            deviation_score=None,
        ),
        recommended_action="",
    )


def emit_classification_gap(
    *,
    target: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
) -> FindingRecord:
    """Emit a ``classification_gap`` finding (R10.1-R10.6).

    Pre-condition enforced by the pipeline:
    ``target.composite_confidence < config.confidence_gap_threshold``.

    Severity is fixed at ``LOW`` per R10.6; classification gaps are
    diagnostic, not threat indicators. Per R10.2, the gap finding is
    independent of pairing — both paired and unpaired Target_Records
    can receive one when the gap condition is met.

    The emitter is pure. It does not construct a ``DeviationScore``
    (R9.11).
    """
    finding_id = derive_finding_id(
        baseline_id=matched_baseline_id,
        finding_category="classification_gap",
        target_component_id=target.component_id,
    )
    return FindingRecord(
        finding_id=finding_id,
        component_id=target.component_id,
        severity=SeverityLevel.LOW,
        category="classification_gap",
        title="classification confidence gap",
        description=(
            "target classification composite_confidence is below the configured gap threshold"
        ),
        evidence=FindingEvidence(
            classification_record=target,
            matched_rule=None,
            matched_cve=None,
            matched_signature=None,
            raw_indicators=[],
            deviation_score=None,
        ),
        recommended_action="",
    )


def emit_signature_expired(
    *,
    target: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
    expiry_iso: str,
) -> FindingRecord:
    """Emit a ``signature_expired`` finding when a component's cert has expired.

    Severity is MEDIUM: the code is validly signed but the trust period
    has lapsed. Operators should re-sign or rotate the certificate.
    """
    finding_id = derive_finding_id(
        baseline_id=matched_baseline_id,
        finding_category="signature_expired",
        target_component_id=target.component_id,
    )
    return FindingRecord(
        finding_id=finding_id,
        component_id=target.component_id,
        severity=SeverityLevel.MEDIUM,
        category="signature_expired",
        title="signing certificate expired",
        description=(
            f"component signature certificate expired at {expiry_iso}; "
            "the signature is valid but the trust period has lapsed"
        ),
        evidence=FindingEvidence(
            classification_record=target,
            matched_rule=None,
            matched_cve=None,
            matched_signature=None,
            raw_indicators=[f"cert_expiry={expiry_iso}"],
            deviation_score=None,
        ),
        recommended_action="Re-sign component with a current certificate",
    )
