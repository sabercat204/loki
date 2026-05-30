"""Tests for the rule schema Pydantic shapes.

Covers Requirements 2.7, 3.1-3.6, 3.8-3.9, 4.1-4.2: every
validator on every typed shape, both positive and negative
cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from loki.classification.rules.schema import (
    Effect,
    GuidPredicate,
    Matcher,
    NamePredicate,
    RawHashPredicate,
    Rule,
    RuleSet,
    SizePredicate,
    TypeHintPredicate,
)
from loki.models.enums import ClassificationMethod

# A real, valid UUID for tests.
_VALID_UUID = "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
_VALID_UUID_UPPER = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"
_OTHER_UUID = "4aafd29d-68df-49ee-8aa9-347d375665a7"

# 64-char lower-case hex.
_VALID_HASH = "a" * 64
_VALID_HASH_UPPER = "A" * 64
_OTHER_HASH = "b" * 64


# ---------------------------------------------------------------------------
# GuidPredicate
# ---------------------------------------------------------------------------


def test_guid_predicate_accepts_canonical_lowercase_uuid() -> None:
    p = GuidPredicate(values=(_VALID_UUID,))
    assert p.values == (_VALID_UUID,)


def test_guid_predicate_normalizes_uppercase_uuid_to_lowercase() -> None:
    p = GuidPredicate(values=(_VALID_UUID_UPPER,))
    assert p.values == (_VALID_UUID,)


def test_guid_predicate_accepts_multiple_values() -> None:
    p = GuidPredicate(values=(_VALID_UUID, _OTHER_UUID))
    assert p.values == (_VALID_UUID, _OTHER_UUID)


def test_guid_predicate_rejects_empty_values() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        GuidPredicate(values=())


def test_guid_predicate_rejects_non_uuid_string() -> None:
    with pytest.raises(ValidationError, match="not a valid UUID"):
        GuidPredicate(values=("not-a-uuid",))


def test_guid_predicate_rejects_extra_keys() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        GuidPredicate.model_validate({"values": (_VALID_UUID,), "extra": "key"})


def test_guid_predicate_is_frozen() -> None:
    p = GuidPredicate(values=(_VALID_UUID,))
    with pytest.raises(ValidationError):
        p.values = (_OTHER_UUID,)  # type: ignore[misc]


# ---------------------------------------------------------------------------
# NamePredicate
# ---------------------------------------------------------------------------


def test_name_predicate_accepts_each_op() -> None:
    for op in ["equals", "prefix", "suffix", "contains"]:
        p = NamePredicate(op=op, value="AMI")  # type: ignore[arg-type]
        assert p.op == op
        assert p.value == "AMI"


def test_name_predicate_rejects_unknown_op() -> None:
    with pytest.raises(ValidationError):
        NamePredicate(op="matches", value="AMI")  # type: ignore[arg-type]


def test_name_predicate_rejects_empty_value() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        NamePredicate(op="equals", value="")


def test_name_predicate_rejects_whitespace_only_value() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        NamePredicate(op="equals", value="   \t  ")


def test_name_predicate_rejects_extra_keys() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        NamePredicate.model_validate({"op": "equals", "value": "AMI", "extra": "key"})


# ---------------------------------------------------------------------------
# TypeHintPredicate
# ---------------------------------------------------------------------------


def test_type_hint_predicate_accepts_single_value() -> None:
    p = TypeHintPredicate(values=("dxe_driver",))
    assert p.values == ("dxe_driver",)


def test_type_hint_predicate_accepts_multiple_values() -> None:
    p = TypeHintPredicate(values=("dxe_driver", "pei_module"))
    assert p.values == ("dxe_driver", "pei_module")


def test_type_hint_predicate_rejects_empty_values() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        TypeHintPredicate(values=())


def test_type_hint_predicate_rejects_empty_string_inside() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        TypeHintPredicate(values=("dxe_driver", ""))


def test_type_hint_predicate_rejects_whitespace_string_inside() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        TypeHintPredicate(values=("dxe_driver", "  "))


# ---------------------------------------------------------------------------
# SizePredicate
# ---------------------------------------------------------------------------


def test_size_predicate_accepts_min_only() -> None:
    p = SizePredicate(min=1024)
    assert p.min == 1024
    assert p.max is None


def test_size_predicate_accepts_max_only() -> None:
    p = SizePredicate(max=1_000_000)
    assert p.min is None
    assert p.max == 1_000_000


def test_size_predicate_accepts_both() -> None:
    p = SizePredicate(min=1024, max=1_000_000)
    assert p.min == 1024
    assert p.max == 1_000_000


def test_size_predicate_accepts_equal_min_max() -> None:
    p = SizePredicate(min=512, max=512)
    assert p.min == 512
    assert p.max == 512


def test_size_predicate_rejects_neither_set() -> None:
    with pytest.raises(ValidationError, match="at least one of min or max"):
        SizePredicate()


def test_size_predicate_rejects_min_greater_than_max() -> None:
    with pytest.raises(ValidationError, match="must be <="):
        SizePredicate(min=2_000_000, max=1_000_000)


def test_size_predicate_rejects_negative_min() -> None:
    with pytest.raises(ValidationError, match="non-negative"):
        SizePredicate(min=-1)


def test_size_predicate_rejects_negative_max() -> None:
    with pytest.raises(ValidationError, match="non-negative"):
        SizePredicate(max=-1)


def test_size_predicate_accepts_zero_bounds() -> None:
    p = SizePredicate(min=0, max=0)
    assert p.min == 0
    assert p.max == 0


# ---------------------------------------------------------------------------
# RawHashPredicate
# ---------------------------------------------------------------------------


def test_raw_hash_predicate_accepts_lowercase_hex() -> None:
    p = RawHashPredicate(values=(_VALID_HASH,))
    assert p.values == (_VALID_HASH,)


def test_raw_hash_predicate_normalizes_uppercase_hex_to_lowercase() -> None:
    p = RawHashPredicate(values=(_VALID_HASH_UPPER,))
    assert p.values == (_VALID_HASH,)


def test_raw_hash_predicate_accepts_multiple_values() -> None:
    p = RawHashPredicate(values=(_VALID_HASH, _OTHER_HASH))
    assert p.values == (_VALID_HASH, _OTHER_HASH)


def test_raw_hash_predicate_rejects_empty_values() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        RawHashPredicate(values=())


def test_raw_hash_predicate_rejects_short_hex() -> None:
    with pytest.raises(ValidationError, match="64-char"):
        RawHashPredicate(values=("a" * 32,))


def test_raw_hash_predicate_rejects_non_hex() -> None:
    with pytest.raises(ValidationError, match="64-char"):
        RawHashPredicate(values=("g" * 64,))


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------


def test_matcher_accepts_single_predicate() -> None:
    m = Matcher(guid=GuidPredicate(values=(_VALID_UUID,)))
    assert m.guid is not None
    assert m.name is None


def test_matcher_accepts_all_predicates() -> None:
    m = Matcher(
        guid=GuidPredicate(values=(_VALID_UUID,)),
        name=NamePredicate(op="prefix", value="AMI"),
        component_type_hint=TypeHintPredicate(values=("dxe_driver",)),
        size=SizePredicate(min=1024),
        raw_hash=RawHashPredicate(values=(_VALID_HASH,)),
    )
    assert m.guid is not None
    assert m.name is not None
    assert m.component_type_hint is not None
    assert m.size is not None
    assert m.raw_hash is not None


def test_matcher_rejects_empty_matcher() -> None:
    with pytest.raises(ValidationError, match="at least one populated predicate"):
        Matcher()


def test_matcher_rejects_extra_keys() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        Matcher.model_validate({"guid": _VALID_UUID, "unknown_predicate": "foo"})


def test_matcher_is_frozen() -> None:
    m = Matcher(guid=GuidPredicate(values=(_VALID_UUID,)))
    with pytest.raises(ValidationError):
        m.guid = None  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Effect
# ---------------------------------------------------------------------------


def test_effect_accepts_documented_keys() -> None:
    e = Effect(
        label="UEFI_DRIVER",
        confidence=0.95,
        method=ClassificationMethod.RULE,
        evidence="GUID match",
    )
    assert e.label == "UEFI_DRIVER"
    assert e.confidence == 0.95
    assert e.method == ClassificationMethod.RULE
    assert e.evidence == "GUID match"


def test_effect_evidence_is_optional() -> None:
    e = Effect(label="UNKNOWN", confidence=0.0, method=ClassificationMethod.HEURISTIC)
    assert e.evidence is None


def test_effect_rejects_extra_keys() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        Effect.model_validate(
            {
                "label": "UEFI_DRIVER",
                "confidence": 0.5,
                "method": "RULE",
                "cve_matches": [],  # not allowed
            }
        )


def test_effect_rejects_negative_confidence() -> None:
    with pytest.raises(ValidationError):
        Effect(label="UEFI_DRIVER", confidence=-0.1, method=ClassificationMethod.RULE)


def test_effect_rejects_confidence_above_one() -> None:
    with pytest.raises(ValidationError):
        Effect(label="UEFI_DRIVER", confidence=1.5, method=ClassificationMethod.RULE)


def test_effect_accepts_zero_and_one_confidence() -> None:
    e0 = Effect(label="UNKNOWN", confidence=0.0, method=ClassificationMethod.HEURISTIC)
    e1 = Effect(label="UEFI_DRIVER", confidence=1.0, method=ClassificationMethod.RULE)
    assert e0.confidence == 0.0
    assert e1.confidence == 1.0


def test_effect_rejects_empty_evidence() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        Effect(
            label="UEFI_DRIVER",
            confidence=0.5,
            method=ClassificationMethod.RULE,
            evidence="",
        )


def test_effect_rejects_whitespace_only_evidence() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        Effect(
            label="UEFI_DRIVER",
            confidence=0.5,
            method=ClassificationMethod.RULE,
            evidence="   \t  ",
        )


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


def _basic_rule(rule_id: str = "intel.me.firmware") -> Rule:
    return Rule(
        rule_id=rule_id,
        axis="type",
        matcher=Matcher(guid=GuidPredicate(values=(_VALID_UUID,))),
        effect=Effect(
            label="UEFI_DRIVER",
            confidence=0.9,
            method=ClassificationMethod.RULE,
        ),
    )


def test_rule_accepts_documented_axes() -> None:
    for axis in ["type", "vendor", "security_posture", "mutability"]:
        r = Rule(
            rule_id="test.rule",
            axis=axis,  # type: ignore[arg-type]
            matcher=Matcher(guid=GuidPredicate(values=(_VALID_UUID,))),
            effect=Effect(
                label="UEFI_DRIVER",
                confidence=0.5,
                method=ClassificationMethod.RULE,
            ),
        )
        assert r.axis == axis


def test_rule_rejects_unknown_axis() -> None:
    with pytest.raises(ValidationError):
        Rule(
            rule_id="test.rule",
            axis="brand_new_axis",  # type: ignore[arg-type]
            matcher=Matcher(guid=GuidPredicate(values=(_VALID_UUID,))),
            effect=Effect(
                label="X",
                confidence=0.5,
                method=ClassificationMethod.RULE,
            ),
        )


def test_rule_accepts_well_formed_rule_id() -> None:
    for rule_id in [
        "a",
        "intel.me.firmware",
        "ami.aptio.dxe-driver",
        "synthetic.type.001",
        "0starts-with-digit-allowed",
        "x" * 128,
    ]:
        r = _basic_rule(rule_id)
        assert r.rule_id == rule_id


def test_rule_rejects_uppercase_rule_id() -> None:
    with pytest.raises(ValidationError):
        _basic_rule("Intel.Me.Firmware")


def test_rule_rejects_empty_rule_id() -> None:
    with pytest.raises(ValidationError):
        _basic_rule("")


def test_rule_rejects_rule_id_starting_with_dot() -> None:
    with pytest.raises(ValidationError):
        _basic_rule(".starts-with-dot")


def test_rule_rejects_rule_id_too_long() -> None:
    # Charset constraint allows up to 128 chars total (1 leading + 127 trailing).
    with pytest.raises(ValidationError):
        _basic_rule("a" * 129)


def test_rule_rejects_extra_keys() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        Rule.model_validate(
            {
                "rule_id": "intel.me.firmware",
                "axis": "type",
                "matcher": {"guid": _VALID_UUID},
                "effect": {
                    "label": "UEFI_DRIVER",
                    "confidence": 0.5,
                    "method": "RULE",
                },
                "comment": "this would be sneaky if allowed",
            }
        )


def test_rule_is_frozen() -> None:
    r = _basic_rule()
    with pytest.raises(ValidationError):
        r.rule_id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# RuleSet
# ---------------------------------------------------------------------------


def test_rule_set_constructs_with_rules_and_sources() -> None:
    rule = _basic_rule()
    rs = RuleSet(
        taxonomy_version="1.0.0",
        rules=(rule,),
        sources=(Path("/rules/test.yaml"),),
    )
    assert rs.taxonomy_version == "1.0.0"
    assert rs.rules == (rule,)
    assert rs.sources == (Path("/rules/test.yaml"),)


def test_rule_set_accepts_empty_rules_and_sources() -> None:
    rs = RuleSet(taxonomy_version="1.0.0", rules=(), sources=())
    assert rs.rules == ()
    assert rs.sources == ()


def test_rule_set_is_frozen() -> None:
    rs = RuleSet(taxonomy_version="1.0.0", rules=(), sources=())
    with pytest.raises(ValidationError):
        rs.taxonomy_version = "2.0.0"  # type: ignore[misc]
