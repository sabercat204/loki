"""Per-axis classifier.

Defines ``classify_axis(rules, axis, component)``: filters the
Rule_Set to the requested axis, evaluates every rule's matcher
against the component, picks the Winning_Rule (max-confidence,
lexicographic ``rule_id`` tie-break), and returns the resulting
``AxisClassification``. When no rule fires, returns the axis's
``UNKNOWN`` enum value at confidence ``0.0`` (R4.8).
"""

from __future__ import annotations

from loki.classification.rules.matcher import matches
from loki.classification.rules.schema import Rule
from loki.models import ExtractedComponent
from loki.models.classification import AxisClassification
from loki.models.enums import (
    ClassificationMethod,
    ComponentTypeLabel,
    MutabilityLabel,
    SecurityPostureLabel,
    VendorLabel,
)

__all__ = ["classify_axis"]

# Per-axis UNKNOWN enum lookup (R4.8). Each entry maps an axis
# string to the corresponding axis enum's UNKNOWN member.
_AXIS_UNKNOWN: dict[str, str] = {
    "type": ComponentTypeLabel.UNKNOWN.value,
    "vendor": VendorLabel.UNKNOWN.value,
    "security_posture": SecurityPostureLabel.UNKNOWN.value,
    "mutability": MutabilityLabel.UNKNOWN.value,
}


def classify_axis(
    rules: tuple[Rule, ...],
    axis: str,
    component: ExtractedComponent,
) -> AxisClassification:
    """Classify ``component`` on ``axis`` against the rule set.

    Filters ``rules`` to those whose ``axis`` matches, evaluates
    each via ``matches(rule, component)``, picks the
    Winning_Rule per R4.4-R4.5, and returns the resulting
    ``AxisClassification``. When no rule fires, returns the
    axis-specific ``UNKNOWN`` fallback at confidence ``0.0``,
    method ``HEURISTIC``, ``rule_id=None``, ``evidence=None``
    (R4.8).

    The Winning_Rule selection is deterministic:
    max-``effect.confidence`` wins, with lexicographically
    smallest ``rule_id`` as the tie-break (R4.5). Implemented as
    ``min(firing, key=lambda r: (-r.effect.confidence, r.rule_id))``
    so the *smallest* tuple wins — which is also the
    highest-confidence rule with the smallest rule_id on ties.

    Args:
        rules: The full Rule_Set's rules tuple. Filtering by
            axis happens here; the caller passes the whole
            tuple unmodified per the design.
        axis: One of ``"type"``, ``"vendor"``,
            ``"security_posture"``, ``"mutability"``.
        component: The component to classify on this axis.

    Returns:
        A validated ``AxisClassification`` instance. The model
        layer's strict validators run on construction.

    Raises:
        KeyError: ``axis`` is not one of the four valid axis
            strings. The caller is the pipeline coordinator,
            which only ever passes the four valid literal
            strings, so this is a programmer error rather than
            a runtime condition.
    """

    # Filter to rules targeting the requested axis (R4.4 first
    # half).
    axis_rules = [rule for rule in rules if rule.axis == axis]

    # Collect firing rules.
    firing = [rule for rule in axis_rules if matches(rule, component)]

    if not firing:
        # R4.8: no-rule-fires fallback.
        return AxisClassification(
            label=_AXIS_UNKNOWN[axis],
            confidence=0.0,
            method=ClassificationMethod.HEURISTIC,
            rule_id=None,
            evidence=None,
        )

    # R4.4 second half + R4.5: max-confidence wins, with
    # lexicographic rule_id tie-break. Encoded as
    # min(...) over a (negated_confidence, rule_id) tuple so
    # the smallest tuple corresponds to the largest confidence
    # and, on ties, the smallest rule_id.
    winner = min(firing, key=lambda r: (-r.effect.confidence, r.rule_id))

    # R4.6 + R4.7: build the AxisClassification.
    evidence = [winner.effect.evidence] if winner.effect.evidence else None
    return AxisClassification(
        label=winner.effect.label,
        confidence=winner.effect.confidence,
        method=winner.effect.method,
        rule_id=winner.rule_id,
        evidence=evidence,
    )
