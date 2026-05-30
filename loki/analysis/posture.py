"""``PostureRating`` six-rule cascade evaluator (R17.5 post-HARDEN).

The cascade lands the G3-A + G4-B HARDEN amendments from the TENSION
pass: a fourth rule (catch-all DEGRADED) for runs whose only findings
are ``unexpected_component``, ``signature_regression: MEDIUM``,
``classification_gap``, or ``analysis_cancelled``; and an extension
to the COMPROMISED rule that escalates ``classification_mismatch``
findings whose ``Composite_Score >= 8.0`` (severity CRITICAL) to
COMPROMISED rather than AT_RISK.

The cascade walks the finding list once, collecting four flags and a
running maximum, then returns the matching rating per the closed
mapping. It is pure (no logging, no I/O) and total: every input list
maps to a defined ``PostureRating`` value.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from loki.models.enums import PostureRating, SeverityLevel

if TYPE_CHECKING:
    from loki.models.analysis import FindingRecord

__all__ = ["derive_posture_rating"]


def derive_posture_rating(findings: Sequence[FindingRecord]) -> PostureRating:
    """Derive ``PostureRating`` from the finding list per R17.5 (post-HARDEN).

    Rule cascade (top wins; first match returns):

    1. ``COMPROMISED`` if any:
       - ``signature_regression`` finding has severity ``HIGH``, OR
       - ``missing_required_component`` finding is emitted (any
         severity; v1 always ``HIGH``), OR
       - ``classification_mismatch`` finding has
         ``evidence.deviation_score.composite_score >= 8.0``
         (i.e. severity CRITICAL per R10.7 — G4-B HARDEN escalation).
    2. ``AT_RISK`` if any ``classification_mismatch`` finding has
       ``composite_score >= 6.0``.
    3. ``DEGRADED`` if any ``classification_mismatch`` finding has
       ``composite_score >= 2.0``.
    4. ``DEGRADED`` if any finding of any category is emitted but no
       rule above fires (G3-A HARDEN catch-all; covers runs whose
       only findings are ``unexpected_component``,
       ``signature_regression: MEDIUM``, ``classification_gap``, or
       ``analysis_cancelled``).
    5. ``BASELINE`` if no findings are emitted at all.

    ``HARDENED`` is reserved for a future revision and SHALL NOT be
    emitted by v1 (R17.5).
    """
    if not findings:
        return PostureRating.BASELINE

    has_signature_regression_high = False
    has_missing_required = False
    has_classification_mismatch_critical = False
    max_classification_mismatch_score = 0.0

    for finding in findings:
        if finding.category == "signature_regression" and finding.severity is SeverityLevel.HIGH:
            has_signature_regression_high = True
        elif finding.category == "missing_required_component":
            has_missing_required = True
        elif finding.category == "classification_mismatch":
            score = _composite_score_or_zero(finding)
            if score > max_classification_mismatch_score:
                max_classification_mismatch_score = score
            if score >= 8.0:
                has_classification_mismatch_critical = True

    if (
        has_signature_regression_high
        or has_missing_required
        or has_classification_mismatch_critical
    ):
        return PostureRating.COMPROMISED
    if max_classification_mismatch_score >= 6.0:
        return PostureRating.AT_RISK
    if max_classification_mismatch_score >= 2.0:
        return PostureRating.DEGRADED
    # Catch-all (G3-A): any finding emitted but no score-based rule
    # fired. Covers unexpected_component, signature_regression: MEDIUM,
    # classification_gap, analysis_cancelled, and classification_mismatch
    # findings with composite_score < 2.0.
    return PostureRating.DEGRADED


def _composite_score_or_zero(finding: FindingRecord) -> float:
    """Read ``finding.evidence.deviation_score.composite_score`` or return 0.0.

    Defensive: per R9.1 the analysis engine constructs a
    ``DeviationScore`` for every ``classification_mismatch`` finding, so
    ``finding.evidence.deviation_score`` is always populated when
    ``finding.category == "classification_mismatch"``. If a future
    revision or a hand-constructed test fixture fails to populate it,
    the cascade treats the missing score as 0.0 (the gentlest default;
    rule 4's catch-all will still classify the finding correctly).
    """
    if finding.evidence.deviation_score is None:
        return 0.0
    return finding.evidence.deviation_score.composite_score
