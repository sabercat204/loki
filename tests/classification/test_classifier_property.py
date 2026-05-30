"""Hypothesis property test for per-axis Winning_Rule selection.

Covers Property 34 (R4.4 + R4.5): ``classify_axis`` selection is
deterministic — the same firing-rules list permuted in any order
produces the same ``AxisClassification.rule_id``.
"""

from __future__ import annotations

import uuid

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.classification.classifier import classify_axis
from loki.classification.rules.schema import (
    Effect,
    GuidPredicate,
    Matcher,
    Rule,
)
from loki.models import ExtractedComponent
from loki.models.enums import ClassificationMethod

# In-memory tests (no I/O), so we can use the larger sample
# count from the project convention.
_IN_MEMORY_SETTINGS = settings(
    max_examples=50,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)


_VALID_UUID = "8c8ce578-8a3d-4f1c-9935-896185c32dd3"


def _component() -> ExtractedComponent:
    """A component that all rules in the strategy fire on (matcher
    is GUID-based and uses the same canonical UUID)."""
    return ExtractedComponent(
        component_id=uuid.uuid5(uuid.NAMESPACE_DNS, "classifier-property"),
        source_image_id=uuid.uuid5(uuid.NAMESPACE_DNS, "image"),
        offset="0x0",
        size=4096,
        raw_hash="0" * 64,
        component_type_hint="dxe_driver",
        guid=_VALID_UUID,
        name="PROP",
        raw_path=None,
    )


def _rule_strategy() -> st.SearchStrategy[Rule]:
    """A strategy for Rules that all fire on the canonical
    component and target the ``type`` axis. The label is fixed
    to ``UEFI_DRIVER`` (a valid ComponentTypeLabel) so every
    generated rule is a valid winner candidate."""
    return st.builds(
        Rule,
        rule_id=st.from_regex(r"[a-z][a-z0-9]{2,15}", fullmatch=True),
        axis=st.just("type"),
        matcher=st.just(Matcher(guid=GuidPredicate(values=(_VALID_UUID,)))),
        effect=st.builds(
            Effect,
            label=st.just("UEFI_DRIVER"),
            confidence=st.floats(min_value=0.01, max_value=1.0, allow_nan=False),
            method=st.just(ClassificationMethod.RULE),
            evidence=st.none(),
        ),
    )


@given(rules=st.lists(_rule_strategy(), min_size=1, max_size=10, unique_by=lambda r: r.rule_id))
@_IN_MEMORY_SETTINGS
def test_property_34_winning_rule_selection_is_deterministic_under_permutation(
    rules: list[Rule],
) -> None:
    """R4.4 + R4.5: classify_axis returns the same
    AxisClassification.rule_id regardless of input order.

    Two random permutations of the same rules-list should
    produce the same winning rule_id (max-confidence wins,
    lexicographic rule_id breaks ties).
    """
    component = _component()
    forward = classify_axis(tuple(rules), "type", component)
    backward = classify_axis(tuple(reversed(rules)), "type", component)
    assert forward.rule_id == backward.rule_id
    assert forward.confidence == backward.confidence
    assert forward.label == backward.label


@given(rules=st.lists(_rule_strategy(), min_size=2, max_size=10, unique_by=lambda r: r.rule_id))
@_IN_MEMORY_SETTINGS
def test_property_34_max_confidence_wins(rules: list[Rule]) -> None:
    """The winning rule is always the one with maximum
    confidence (modulo lexicographic tie-break)."""
    component = _component()
    result = classify_axis(tuple(rules), "type", component)
    max_confidence = max(r.effect.confidence for r in rules)
    assert result.confidence == max_confidence


@given(rules=st.lists(_rule_strategy(), min_size=1, max_size=10, unique_by=lambda r: r.rule_id))
@_IN_MEMORY_SETTINGS
def test_property_34_winner_is_among_input_rules(rules: list[Rule]) -> None:
    """The winning rule_id is one of the input rule_ids."""
    component = _component()
    result = classify_axis(tuple(rules), "type", component)
    rule_ids = {r.rule_id for r in rules}
    assert result.rule_id in rule_ids


@given(rules=st.lists(_rule_strategy(), min_size=2, max_size=10, unique_by=lambda r: r.rule_id))
@_IN_MEMORY_SETTINGS
def test_property_34_tie_break_picks_lexicographic_smallest(rules: list[Rule]) -> None:
    """When multiple rules tie on confidence, the lexicographically
    smallest rule_id wins. Construct a list where every rule
    has the same confidence to force the tie path."""
    component = _component()
    # Replace every rule's effect with one at confidence 0.5.
    same_conf_rules = tuple(
        Rule(
            rule_id=r.rule_id,
            axis=r.axis,
            matcher=r.matcher,
            effect=Effect(
                label=r.effect.label,
                confidence=0.5,
                method=r.effect.method,
                evidence=r.effect.evidence,
            ),
        )
        for r in rules
    )
    result = classify_axis(same_conf_rules, "type", component)
    expected = min(r.rule_id for r in rules)
    assert result.rule_id == expected
