"""Tests for the per-axis classifier.

Covers Requirement 4: per-axis Winning_Rule selection,
max-confidence + lexicographic tie-break, no-rule-fires
fallback to the axis-specific ``UNKNOWN`` enum value, evidence
wrapping per R4.7, and four-axis independence.
"""

from __future__ import annotations

import uuid

from loki.classification.classifier import classify_axis
from loki.classification.rules.schema import (
    Effect,
    GuidPredicate,
    Matcher,
    NamePredicate,
    Rule,
)
from loki.models import ExtractedComponent
from loki.models.enums import (
    ClassificationMethod,
    ComponentTypeLabel,
    MutabilityLabel,
    SecurityPostureLabel,
    VendorLabel,
)

# A real, valid UUID for tests.
_VALID_UUID = "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
_OTHER_UUID = "4aafd29d-68df-49ee-8aa9-347d375665a7"


def _component(
    *,
    guid: str | None = _VALID_UUID,
    name: str | None = "AMI Aptio",
) -> ExtractedComponent:
    """Build an ExtractedComponent with sensible defaults for classifier tests."""
    return ExtractedComponent(
        component_id=uuid.uuid5(uuid.NAMESPACE_DNS, "test-classifier"),
        source_image_id=uuid.uuid5(uuid.NAMESPACE_DNS, "test-image"),
        offset="0x1000",
        size=4096,
        raw_hash="a" * 64,
        component_type_hint="dxe_driver",
        guid=guid,
        name=name,
        raw_path=None,
    )


def _rule(
    *,
    rule_id: str,
    axis: str,
    label: str,
    confidence: float,
    matcher: Matcher | None = None,
    evidence: str | None = None,
    method: ClassificationMethod = ClassificationMethod.RULE,
) -> Rule:
    """Build a Rule with sensible defaults."""
    if matcher is None:
        matcher = Matcher(guid=GuidPredicate(values=(_VALID_UUID,)))
    return Rule(
        rule_id=rule_id,
        axis=axis,  # type: ignore[arg-type]
        matcher=matcher,
        effect=Effect(
            label=label,
            confidence=confidence,
            method=method,
            evidence=evidence,
        ),
    )


# ---------------------------------------------------------------------------
# No-rule-fires fallback (R4.8)
# ---------------------------------------------------------------------------


def test_empty_rule_set_returns_unknown_fallback_for_type() -> None:
    result = classify_axis((), "type", _component())
    assert result.label == ComponentTypeLabel.UNKNOWN.value
    assert result.confidence == 0.0
    assert result.method == ClassificationMethod.HEURISTIC
    assert result.rule_id is None
    assert result.evidence is None


def test_empty_rule_set_returns_unknown_fallback_for_vendor() -> None:
    result = classify_axis((), "vendor", _component())
    assert result.label == VendorLabel.UNKNOWN.value
    assert result.confidence == 0.0
    assert result.method == ClassificationMethod.HEURISTIC


def test_empty_rule_set_returns_unknown_fallback_for_security_posture() -> None:
    result = classify_axis((), "security_posture", _component())
    assert result.label == SecurityPostureLabel.UNKNOWN.value
    assert result.confidence == 0.0
    assert result.method == ClassificationMethod.HEURISTIC


def test_empty_rule_set_returns_unknown_fallback_for_mutability() -> None:
    result = classify_axis((), "mutability", _component())
    assert result.label == MutabilityLabel.UNKNOWN.value
    assert result.confidence == 0.0
    assert result.method == ClassificationMethod.HEURISTIC


def test_no_matching_rules_returns_unknown_fallback() -> None:
    """Rules exist but none fire on the component."""
    rules = (
        _rule(
            rule_id="other.rule",
            axis="type",
            label="UEFI_DRIVER",
            confidence=0.9,
            matcher=Matcher(guid=GuidPredicate(values=(_OTHER_UUID,))),
        ),
    )
    result = classify_axis(rules, "type", _component(guid=_VALID_UUID))
    assert result.label == ComponentTypeLabel.UNKNOWN.value
    assert result.confidence == 0.0
    assert result.rule_id is None


def test_rules_for_other_axes_do_not_fire_on_requested_axis() -> None:
    """A rule on `vendor` cannot win the `type` axis even if its
    matcher fires (R4.3: four-axis independence)."""
    rules = (
        _rule(
            rule_id="vendor.match",
            axis="vendor",
            label="INTEL",
            confidence=1.0,
            matcher=Matcher(guid=GuidPredicate(values=(_VALID_UUID,))),
        ),
    )
    result = classify_axis(rules, "type", _component())
    assert result.label == ComponentTypeLabel.UNKNOWN.value
    assert result.rule_id is None


# ---------------------------------------------------------------------------
# Single firing rule (R4.4-R4.6)
# ---------------------------------------------------------------------------


def test_single_firing_rule_is_the_winner() -> None:
    rules = (
        _rule(
            rule_id="solo.rule",
            axis="type",
            label="UEFI_DRIVER",
            confidence=0.85,
            matcher=Matcher(guid=GuidPredicate(values=(_VALID_UUID,))),
        ),
    )
    result = classify_axis(rules, "type", _component())
    assert result.label == "UEFI_DRIVER"
    assert result.confidence == 0.85
    assert result.method == ClassificationMethod.RULE
    assert result.rule_id == "solo.rule"


def test_winner_method_carries_through_from_effect() -> None:
    """The Effect's method field becomes the AxisClassification's method."""
    rules = (
        _rule(
            rule_id="signature.rule",
            axis="type",
            label="UEFI_DRIVER",
            confidence=0.7,
            method=ClassificationMethod.SIGNATURE,
        ),
    )
    result = classify_axis(rules, "type", _component())
    assert result.method == ClassificationMethod.SIGNATURE


# ---------------------------------------------------------------------------
# Max-confidence wins (R4.4)
# ---------------------------------------------------------------------------


def test_max_confidence_wins_over_lower_confidence() -> None:
    """When two rules fire, the one with higher confidence wins."""
    rules = (
        _rule(rule_id="low", axis="type", label="UEFI_DRIVER", confidence=0.3),
        _rule(rule_id="high", axis="type", label="DXE_DRIVER", confidence=0.9),
    )
    result = classify_axis(rules, "type", _component())
    assert result.label == "DXE_DRIVER"
    assert result.confidence == 0.9
    assert result.rule_id == "high"


def test_max_confidence_wins_regardless_of_input_order() -> None:
    """Order of rules in the input tuple doesn't change which rule wins."""
    rule_low = _rule(rule_id="low", axis="type", label="UEFI_DRIVER", confidence=0.3)
    rule_high = _rule(rule_id="high", axis="type", label="DXE_DRIVER", confidence=0.9)
    forward = classify_axis((rule_low, rule_high), "type", _component())
    backward = classify_axis((rule_high, rule_low), "type", _component())
    assert forward.label == backward.label == "DXE_DRIVER"
    assert forward.rule_id == backward.rule_id == "high"


# ---------------------------------------------------------------------------
# Lexicographic tie-break (R4.5)
# ---------------------------------------------------------------------------


def test_tie_breaks_on_lexicographic_smallest_rule_id() -> None:
    """Two rules at the same confidence; the smaller rule_id wins."""
    rules = (
        _rule(rule_id="z.rule", axis="type", label="DXE_DRIVER", confidence=0.5),
        _rule(rule_id="a.rule", axis="type", label="UEFI_DRIVER", confidence=0.5),
    )
    result = classify_axis(rules, "type", _component())
    assert result.rule_id == "a.rule"
    assert result.label == "UEFI_DRIVER"


def test_tie_break_independent_of_input_order() -> None:
    rule_z = _rule(rule_id="z.rule", axis="type", label="DXE_DRIVER", confidence=0.5)
    rule_a = _rule(rule_id="a.rule", axis="type", label="UEFI_DRIVER", confidence=0.5)
    forward = classify_axis((rule_z, rule_a), "type", _component())
    backward = classify_axis((rule_a, rule_z), "type", _component())
    assert forward.rule_id == backward.rule_id == "a.rule"


def test_three_way_tie_picks_lexicographic_smallest() -> None:
    rules = (
        _rule(rule_id="m.rule", axis="type", label="DXE_DRIVER", confidence=0.5),
        _rule(rule_id="z.rule", axis="type", label="UEFI_DRIVER", confidence=0.5),
        _rule(rule_id="a.rule", axis="type", label="PEI_MODULE", confidence=0.5),
    )
    result = classify_axis(rules, "type", _component())
    assert result.rule_id == "a.rule"
    assert result.label == "PEI_MODULE"


# ---------------------------------------------------------------------------
# Evidence wrapping (R4.7)
# ---------------------------------------------------------------------------


def test_evidence_wraps_into_single_element_list_when_present() -> None:
    rules = (
        _rule(
            rule_id="with.evidence",
            axis="type",
            label="UEFI_DRIVER",
            confidence=0.8,
            evidence="GUID match for Intel ME",
        ),
    )
    result = classify_axis(rules, "type", _component())
    assert result.evidence == ["GUID match for Intel ME"]


def test_evidence_is_none_when_effect_has_no_evidence() -> None:
    rules = (
        _rule(
            rule_id="no.evidence",
            axis="type",
            label="UEFI_DRIVER",
            confidence=0.8,
            evidence=None,
        ),
    )
    result = classify_axis(rules, "type", _component())
    assert result.evidence is None


def test_evidence_only_from_winning_rule() -> None:
    """When two rules fire, only the winner's evidence shows up."""
    rules = (
        _rule(
            rule_id="loser",
            axis="type",
            label="DXE_DRIVER",
            confidence=0.3,
            evidence="loser evidence",
        ),
        _rule(
            rule_id="winner",
            axis="type",
            label="UEFI_DRIVER",
            confidence=0.9,
            evidence="winner evidence",
        ),
    )
    result = classify_axis(rules, "type", _component())
    assert result.evidence == ["winner evidence"]


# ---------------------------------------------------------------------------
# Four-axis independence (R4.3)
# ---------------------------------------------------------------------------


def test_classifying_two_axes_with_same_rules_returns_independent_results() -> None:
    """A type rule and a vendor rule both fire on the same
    component; classifying type and vendor produces axis-specific
    results without cross-contamination."""
    rules = (
        _rule(rule_id="type.r", axis="type", label="UEFI_DRIVER", confidence=0.9),
        _rule(rule_id="vendor.r", axis="vendor", label="INTEL", confidence=0.8),
    )
    type_result = classify_axis(rules, "type", _component())
    vendor_result = classify_axis(rules, "vendor", _component())
    assert type_result.label == "UEFI_DRIVER"
    assert type_result.rule_id == "type.r"
    assert vendor_result.label == "INTEL"
    assert vendor_result.rule_id == "vendor.r"


def test_classifying_axis_does_not_mutate_rules_tuple() -> None:
    """The classifier reads from the rules tuple; the tuple is
    immutable by construction (frozen RuleSet), so this test
    asserts the input tuple is the same object after the call."""
    rules = (
        _rule(rule_id="rule.1", axis="type", label="UEFI_DRIVER", confidence=0.9),
        _rule(rule_id="rule.2", axis="vendor", label="INTEL", confidence=0.8),
    )
    rules_before = rules
    classify_axis(rules, "type", _component())
    assert rules is rules_before


# ---------------------------------------------------------------------------
# Determinism (Property 34 setup)
# ---------------------------------------------------------------------------


def test_classify_axis_is_deterministic_across_runs() -> None:
    """Same inputs produce the same output across multiple calls."""
    rules = (
        _rule(rule_id="b.rule", axis="type", label="DXE_DRIVER", confidence=0.5),
        _rule(rule_id="a.rule", axis="type", label="UEFI_DRIVER", confidence=0.5),
        _rule(rule_id="c.rule", axis="type", label="PEI_MODULE", confidence=0.7),
    )
    component = _component()
    runs = [classify_axis(rules, "type", component) for _ in range(10)]
    first = runs[0]
    for r in runs[1:]:
        assert r.label == first.label
        assert r.confidence == first.confidence
        assert r.rule_id == first.rule_id
        assert r.evidence == first.evidence


def test_classify_axis_uses_name_predicate_correctly() -> None:
    """End-to-end: a name-prefix rule fires when the component
    name matches; the resulting classification carries the
    expected fields."""
    rules = (
        _rule(
            rule_id="ami.aptio",
            axis="vendor",
            label="AMI",
            confidence=0.85,
            matcher=Matcher(name=NamePredicate(op="prefix", value="AMI")),
            evidence="AMI prefix on name",
        ),
    )
    result = classify_axis(rules, "vendor", _component(name="AMI Aptio"))
    assert result.label == "AMI"
    assert result.confidence == 0.85
    assert result.rule_id == "ami.aptio"
    assert result.evidence == ["AMI prefix on name"]
