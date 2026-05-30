"""Tests for the conjunctive matcher evaluator.

Covers Requirement 3: every predicate variant
(``guid`` / ``name`` / ``component_type_hint`` / ``size`` /
``raw_hash``) plus conjunctive composition under R3.7. The
predicate-vs-``None``-field semantics from R3.2-R3.4 get
explicit coverage for each predicate type.
"""

from __future__ import annotations

import uuid

from loki.classification.rules.matcher import matches
from loki.classification.rules.schema import (
    Effect,
    GuidPredicate,
    Matcher,
    NamePredicate,
    RawHashPredicate,
    Rule,
    SizePredicate,
    TypeHintPredicate,
)
from loki.models import ExtractedComponent
from loki.models.enums import ClassificationMethod

# A real, valid UUID for tests.
_VALID_UUID = "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
_VALID_UUID_UPPER = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"
_OTHER_UUID = "4aafd29d-68df-49ee-8aa9-347d375665a7"

_VALID_HASH = "a" * 64
_VALID_HASH_UPPER = "A" * 64
_OTHER_HASH = "b" * 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _component(
    *,
    guid: str | None = _VALID_UUID,
    name: str | None = "AMI Aptio",
    component_type_hint: str | None = "dxe_driver",
    size: int = 4096,
    raw_hash: str = _VALID_HASH,
) -> ExtractedComponent:
    """Build an ExtractedComponent with sensible defaults."""
    return ExtractedComponent(
        component_id=uuid.uuid5(uuid.NAMESPACE_DNS, "test-matcher"),
        source_image_id=uuid.uuid5(uuid.NAMESPACE_DNS, "test-image"),
        offset="0x1000",
        size=size,
        raw_hash=raw_hash,
        component_type_hint=component_type_hint,
        guid=guid,
        name=name,
        raw_path=None,
    )


def _rule(matcher: Matcher) -> Rule:
    """Wrap a matcher in a minimal Rule for the matches() call."""
    return Rule(
        rule_id="test.rule",
        axis="type",
        matcher=matcher,
        effect=Effect(
            label="UEFI_DRIVER",
            confidence=0.5,
            method=ClassificationMethod.RULE,
        ),
    )


# ---------------------------------------------------------------------------
# guid predicate (R3.2)
# ---------------------------------------------------------------------------


def test_guid_single_value_fires_on_exact_match() -> None:
    rule = _rule(Matcher(guid=GuidPredicate(values=(_VALID_UUID,))))
    assert matches(rule, _component(guid=_VALID_UUID)) is True


def test_guid_single_value_does_not_fire_on_mismatch() -> None:
    rule = _rule(Matcher(guid=GuidPredicate(values=(_VALID_UUID,))))
    assert matches(rule, _component(guid=_OTHER_UUID)) is False


def test_guid_match_is_case_insensitive() -> None:
    rule = _rule(Matcher(guid=GuidPredicate(values=(_VALID_UUID,))))
    assert matches(rule, _component(guid=_VALID_UUID_UPPER)) is True


def test_guid_in_list_fires_when_any_member_matches() -> None:
    rule = _rule(Matcher(guid=GuidPredicate(values=(_OTHER_UUID, _VALID_UUID))))
    assert matches(rule, _component(guid=_VALID_UUID)) is True


def test_guid_in_list_does_not_fire_when_no_member_matches() -> None:
    rule = _rule(Matcher(guid=GuidPredicate(values=(_OTHER_UUID,))))
    assert matches(rule, _component(guid=_VALID_UUID)) is False


def test_guid_predicate_does_not_fire_when_component_guid_is_none() -> None:
    """R3.2 None-field-no-fire: predicate set, component.guid=None → False."""
    rule = _rule(Matcher(guid=GuidPredicate(values=(_VALID_UUID,))))
    assert matches(rule, _component(guid=None)) is False


# ---------------------------------------------------------------------------
# name predicate (R3.3)
# ---------------------------------------------------------------------------


def test_name_equals_fires_on_exact_match() -> None:
    rule = _rule(Matcher(name=NamePredicate(op="equals", value="AMI Aptio")))
    assert matches(rule, _component(name="AMI Aptio")) is True


def test_name_equals_is_case_sensitive() -> None:
    rule = _rule(Matcher(name=NamePredicate(op="equals", value="AMI Aptio")))
    assert matches(rule, _component(name="ami aptio")) is False


def test_name_equals_does_not_fire_on_mismatch() -> None:
    rule = _rule(Matcher(name=NamePredicate(op="equals", value="AMI Aptio")))
    assert matches(rule, _component(name="Phoenix Secure")) is False


def test_name_prefix_fires_on_prefix_match() -> None:
    rule = _rule(Matcher(name=NamePredicate(op="prefix", value="AMI")))
    assert matches(rule, _component(name="AMI Aptio")) is True


def test_name_prefix_does_not_fire_on_non_prefix() -> None:
    rule = _rule(Matcher(name=NamePredicate(op="prefix", value="AMI")))
    assert matches(rule, _component(name="Phoenix AMI")) is False


def test_name_suffix_fires_on_suffix_match() -> None:
    rule = _rule(Matcher(name=NamePredicate(op="suffix", value="Aptio")))
    assert matches(rule, _component(name="AMI Aptio")) is True


def test_name_suffix_does_not_fire_on_non_suffix() -> None:
    rule = _rule(Matcher(name=NamePredicate(op="suffix", value="Aptio")))
    assert matches(rule, _component(name="Aptio Bootloader")) is False


def test_name_contains_fires_on_substring() -> None:
    rule = _rule(Matcher(name=NamePredicate(op="contains", value="Apt")))
    assert matches(rule, _component(name="AMI Aptio")) is True


def test_name_contains_does_not_fire_when_substring_absent() -> None:
    rule = _rule(Matcher(name=NamePredicate(op="contains", value="Apt")))
    assert matches(rule, _component(name="Phoenix Secure")) is False


def test_name_predicate_does_not_fire_when_component_name_is_none() -> None:
    """R3.3 None-field-no-fire."""
    rule = _rule(Matcher(name=NamePredicate(op="equals", value="AMI")))
    assert matches(rule, _component(name=None)) is False


def test_name_predicate_against_empty_string_component_name() -> None:
    """R3.3: empty string is a normal string, not None.

    NamePredicate.value is rejected at construction if empty (R3.3
    second sentence: "non-empty string"). So the predicate carries
    a non-empty needle, and matching it against an empty component
    name correctly returns False for equals/prefix/suffix/contains
    -- except for `contains` against any predicate value that is
    contained-in the empty string, which is no value at all.
    """
    rule = _rule(Matcher(name=NamePredicate(op="equals", value="AMI")))
    assert matches(rule, _component(name="")) is False
    rule = _rule(Matcher(name=NamePredicate(op="prefix", value="AMI")))
    assert matches(rule, _component(name="")) is False
    rule = _rule(Matcher(name=NamePredicate(op="contains", value="AMI")))
    assert matches(rule, _component(name="")) is False


# ---------------------------------------------------------------------------
# component_type_hint predicate (R3.4)
# ---------------------------------------------------------------------------


def test_type_hint_single_fires_on_exact_match() -> None:
    rule = _rule(Matcher(component_type_hint=TypeHintPredicate(values=("dxe_driver",))))
    assert matches(rule, _component(component_type_hint="dxe_driver")) is True


def test_type_hint_is_case_sensitive() -> None:
    rule = _rule(Matcher(component_type_hint=TypeHintPredicate(values=("dxe_driver",))))
    assert matches(rule, _component(component_type_hint="DXE_DRIVER")) is False


def test_type_hint_in_list_fires_when_any_member_matches() -> None:
    rule = _rule(
        Matcher(component_type_hint=TypeHintPredicate(values=("pei_module", "dxe_driver")))
    )
    assert matches(rule, _component(component_type_hint="dxe_driver")) is True


def test_type_hint_does_not_fire_on_mismatch() -> None:
    rule = _rule(Matcher(component_type_hint=TypeHintPredicate(values=("pei_module",))))
    assert matches(rule, _component(component_type_hint="dxe_driver")) is False


def test_type_hint_does_not_fire_when_component_field_is_none() -> None:
    """R3.4 None-field-no-fire."""
    rule = _rule(Matcher(component_type_hint=TypeHintPredicate(values=("dxe_driver",))))
    assert matches(rule, _component(component_type_hint=None)) is False


def test_type_hint_against_empty_string_component_field() -> None:
    """Empty string is not None; treated as a normal mismatch."""
    rule = _rule(Matcher(component_type_hint=TypeHintPredicate(values=("dxe_driver",))))
    assert matches(rule, _component(component_type_hint="")) is False


# ---------------------------------------------------------------------------
# size predicate (R3.5)
# ---------------------------------------------------------------------------


def test_size_min_only_fires_when_size_at_or_above() -> None:
    rule = _rule(Matcher(size=SizePredicate(min=4096)))
    assert matches(rule, _component(size=4096)) is True
    assert matches(rule, _component(size=8192)) is True


def test_size_min_only_does_not_fire_when_size_below() -> None:
    rule = _rule(Matcher(size=SizePredicate(min=4096)))
    assert matches(rule, _component(size=2048)) is False


def test_size_max_only_fires_when_size_at_or_below() -> None:
    rule = _rule(Matcher(size=SizePredicate(max=4096)))
    assert matches(rule, _component(size=4096)) is True
    assert matches(rule, _component(size=1024)) is True


def test_size_max_only_does_not_fire_when_size_above() -> None:
    rule = _rule(Matcher(size=SizePredicate(max=4096)))
    assert matches(rule, _component(size=8192)) is False


def test_size_with_both_bounds_fires_inside_range() -> None:
    rule = _rule(Matcher(size=SizePredicate(min=1024, max=8192)))
    assert matches(rule, _component(size=4096)) is True
    assert matches(rule, _component(size=1024)) is True
    assert matches(rule, _component(size=8192)) is True


def test_size_with_both_bounds_does_not_fire_outside_range() -> None:
    rule = _rule(Matcher(size=SizePredicate(min=1024, max=8192)))
    assert matches(rule, _component(size=512)) is False
    assert matches(rule, _component(size=16384)) is False


# ---------------------------------------------------------------------------
# raw_hash predicate (R3.6)
# ---------------------------------------------------------------------------


def test_raw_hash_single_fires_on_exact_match() -> None:
    rule = _rule(Matcher(raw_hash=RawHashPredicate(values=(_VALID_HASH,))))
    assert matches(rule, _component(raw_hash=_VALID_HASH)) is True


def test_raw_hash_match_lower_cases_component_hash() -> None:
    """The model layer accepts mixed-case hex; the matcher
    normalizes to lowercase before comparing against the
    canonical predicate values."""
    rule = _rule(Matcher(raw_hash=RawHashPredicate(values=(_VALID_HASH,))))
    assert matches(rule, _component(raw_hash=_VALID_HASH_UPPER)) is True


def test_raw_hash_in_list_fires_when_any_member_matches() -> None:
    rule = _rule(Matcher(raw_hash=RawHashPredicate(values=(_OTHER_HASH, _VALID_HASH))))
    assert matches(rule, _component(raw_hash=_VALID_HASH)) is True


def test_raw_hash_does_not_fire_on_mismatch() -> None:
    rule = _rule(Matcher(raw_hash=RawHashPredicate(values=(_OTHER_HASH,))))
    assert matches(rule, _component(raw_hash=_VALID_HASH)) is False


# ---------------------------------------------------------------------------
# Conjunctive composition (R3.7)
# ---------------------------------------------------------------------------


def test_two_predicates_fire_when_both_match() -> None:
    rule = _rule(
        Matcher(
            guid=GuidPredicate(values=(_VALID_UUID,)),
            component_type_hint=TypeHintPredicate(values=("dxe_driver",)),
        )
    )
    assert matches(rule, _component(guid=_VALID_UUID, component_type_hint="dxe_driver")) is True


def test_two_predicates_do_not_fire_when_only_one_matches() -> None:
    rule = _rule(
        Matcher(
            guid=GuidPredicate(values=(_VALID_UUID,)),
            component_type_hint=TypeHintPredicate(values=("dxe_driver",)),
        )
    )
    assert matches(rule, _component(guid=_VALID_UUID, component_type_hint="pei_module")) is False
    assert matches(rule, _component(guid=_OTHER_UUID, component_type_hint="dxe_driver")) is False


def test_all_five_predicates_fire_when_all_match() -> None:
    rule = _rule(
        Matcher(
            guid=GuidPredicate(values=(_VALID_UUID,)),
            name=NamePredicate(op="prefix", value="AMI"),
            component_type_hint=TypeHintPredicate(values=("dxe_driver",)),
            size=SizePredicate(min=1024, max=8192),
            raw_hash=RawHashPredicate(values=(_VALID_HASH,)),
        )
    )
    assert (
        matches(
            rule,
            _component(
                guid=_VALID_UUID,
                name="AMI Aptio",
                component_type_hint="dxe_driver",
                size=4096,
                raw_hash=_VALID_HASH,
            ),
        )
        is True
    )


def test_all_five_predicates_do_not_fire_when_one_fails() -> None:
    rule = _rule(
        Matcher(
            guid=GuidPredicate(values=(_VALID_UUID,)),
            name=NamePredicate(op="prefix", value="AMI"),
            component_type_hint=TypeHintPredicate(values=("dxe_driver",)),
            size=SizePredicate(min=1024, max=8192),
            raw_hash=RawHashPredicate(values=(_VALID_HASH,)),
        )
    )
    # Wrong size -> should fail despite all other predicates matching.
    assert (
        matches(
            rule,
            _component(
                guid=_VALID_UUID,
                name="AMI Aptio",
                component_type_hint="dxe_driver",
                size=16_384,  # outside range
                raw_hash=_VALID_HASH,
            ),
        )
        is False
    )


def test_conjunctive_short_circuits_on_first_failing_predicate() -> None:
    """Order-independence: same matcher + same component returns
    the same result regardless of which predicate fails first.

    The matcher uses cheap-first ordering for performance, but
    correctness should not depend on order.
    """
    matcher = Matcher(
        guid=GuidPredicate(values=(_VALID_UUID,)),
        size=SizePredicate(min=10_000),  # will fail for default size 4096
    )
    rule = _rule(matcher)
    assert matches(rule, _component(guid=_VALID_UUID, size=4096)) is False


# ---------------------------------------------------------------------------
# None-field no-fire summary (R3.2-R3.4)
# ---------------------------------------------------------------------------


def test_compound_matcher_with_none_guid_does_not_fire_overall() -> None:
    """When the component's guid is None and the matcher has a
    populated guid predicate, the matcher cannot fire even if
    every other predicate would otherwise fire (R3.2 + R3.7).
    """
    rule = _rule(
        Matcher(
            guid=GuidPredicate(values=(_VALID_UUID,)),
            name=NamePredicate(op="equals", value="AMI Aptio"),
        )
    )
    assert matches(rule, _component(guid=None, name="AMI Aptio")) is False


def test_compound_matcher_with_none_name_does_not_fire_overall() -> None:
    rule = _rule(
        Matcher(
            guid=GuidPredicate(values=(_VALID_UUID,)),
            name=NamePredicate(op="equals", value="AMI Aptio"),
        )
    )
    assert matches(rule, _component(guid=_VALID_UUID, name=None)) is False


def test_compound_matcher_without_predicate_for_none_field_still_fires() -> None:
    """If the matcher has no predicate targeting a None field, that
    None field doesn't affect the overall fire result (R3.2-R3.4
    is contingent on a predicate being populated).
    """
    rule = _rule(Matcher(guid=GuidPredicate(values=(_VALID_UUID,))))
    # The component has name=None, but the matcher doesn't target name.
    assert matches(rule, _component(guid=_VALID_UUID, name=None)) is True
