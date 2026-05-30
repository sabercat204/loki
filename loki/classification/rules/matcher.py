"""Conjunctive matcher evaluator.

Implements ``matches(rule, component)``: returns True when every
populated predicate in ``rule.matcher`` fires for ``component``,
False otherwise. Predicate-vs-``None``-field semantics return
False per R3.2-R3.4. Predicate evaluation is checked in a fixed
cheap-first order (``guid``, ``name``, ``component_type_hint``,
``size``, ``raw_hash``) to maximize short-circuit performance;
order does not affect correctness (R3.7).
"""

from __future__ import annotations

from loki.classification.rules.schema import (
    GuidPredicate,
    NamePredicate,
    RawHashPredicate,
    Rule,
    SizePredicate,
    TypeHintPredicate,
)
from loki.models import ExtractedComponent

__all__ = ["matches"]


def matches(rule: Rule, component: ExtractedComponent) -> bool:
    """Conjunctive evaluation of ``rule.matcher`` against ``component``.

    Returns True when every populated predicate in
    ``rule.matcher`` fires for ``component``, False otherwise. A
    matcher with no populated predicates is rejected at rule-load
    time, not here (R3.1's "at least one" invariant lives in the
    ``Matcher`` Pydantic validator).

    R3.2-R3.4: when a populated predicate targets a component
    field that is ``None``, the predicate does not fire and the
    matcher returns False. Empty-string fields fire as a normal
    string comparison would (which means an empty
    ``component.name`` does not match
    ``NamePredicate(op="equals", value="anything")`` but does
    match ``NamePredicate(op="equals", value="")`` if such a
    predicate were constructible — but the schema rejects empty
    predicate values, so this case cannot arise in practice).

    R3.7: predicates compose under conjunction. Order of
    evaluation is purely a performance choice; correctness is
    order-independent.
    """

    matcher = rule.matcher

    # Cheap-first short-circuit ordering. Each branch returns
    # False as soon as any populated predicate fails to fire.
    if matcher.guid is not None and not _guid_fires(matcher.guid, component.guid):
        return False
    if matcher.name is not None and not _name_fires(matcher.name, component.name):
        return False
    if matcher.component_type_hint is not None and not _type_hint_fires(
        matcher.component_type_hint, component.component_type_hint
    ):
        return False
    if matcher.size is not None and not _size_fires(matcher.size, component.size):
        return False
    if matcher.raw_hash is not None and not _raw_hash_fires(matcher.raw_hash, component.raw_hash):
        return False
    return True


def _guid_fires(predicate: GuidPredicate, component_guid: str | None) -> bool:
    """R3.2: guid match is case-insensitive against canonical predicate values.

    Returns False when ``component_guid`` is None per the
    None-field-no-fire rule.
    """
    if component_guid is None:
        return False
    # Predicate values are canonical lower-case at construction (the
    # schema validator normalizes them). Lower-case the component's
    # guid here for case-insensitive comparison.
    return component_guid.lower() in predicate.values


def _name_fires(predicate: NamePredicate, component_name: str | None) -> bool:
    """R3.3: name match is case-sensitive on the chosen operator.

    Returns False when ``component_name`` is None per the
    None-field-no-fire rule.
    """
    if component_name is None:
        return False
    op = predicate.op
    needle = predicate.value
    if op == "equals":
        return component_name == needle
    if op == "prefix":
        return component_name.startswith(needle)
    if op == "suffix":
        return component_name.endswith(needle)
    if op == "contains":
        return needle in component_name
    # Unreachable: NamePredicate.op is constrained to the four
    # values above by the schema, but mypy needs the explicit
    # exhaustive return.
    raise AssertionError(f"unknown name-predicate op: {op!r}")


def _type_hint_fires(predicate: TypeHintPredicate, component_type_hint: str | None) -> bool:
    """R3.4: component_type_hint match is case-sensitive equality / `in`.

    Returns False when ``component_type_hint`` is None per the
    None-field-no-fire rule. Mistyped predicate strings silently
    fail to fire (R3.4: v1 doesn't validate against any closed
    set of known hint values).
    """
    if component_type_hint is None:
        return False
    return component_type_hint in predicate.values


def _size_fires(predicate: SizePredicate, component_size: int) -> bool:
    """R3.5: size match enforces min and/or max bounds inclusively.

    ``ExtractedComponent.size`` is required and always positive
    (the model validator rejects ``size <= 0``), so there is no
    None-field branch here.
    """
    if predicate.min is not None and component_size < predicate.min:
        return False
    if predicate.max is not None and component_size > predicate.max:
        return False
    return True


def _raw_hash_fires(predicate: RawHashPredicate, component_raw_hash: str) -> bool:
    """R3.6: raw_hash match is exact equality on the canonical predicate values.

    ``ExtractedComponent.raw_hash`` is required and validated as
    64-character hex by the model layer. Predicate values are
    lower-cased at construction; we lower-case the component's
    raw_hash here so case-mismatched extraction outputs (which
    the model layer accepts as ``[0-9a-fA-F]{64}``) still match.
    """
    return component_raw_hash.lower() in predicate.values
