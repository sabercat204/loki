"""Pydantic typed shapes for the rule schema.

Defines the eight shapes that constitute a validated rule:
``GuidPredicate``, ``NamePredicate``, ``TypeHintPredicate``,
``SizePredicate``, ``RawHashPredicate`` (the predicate
vocabulary), ``Matcher`` (conjunctive predicate block, closed
key set), ``Effect`` (output assertion), ``Rule`` (one row), and
``RuleSet`` (immutable collection). All ``frozen=True``,
``extra="forbid"`` to enforce the closed schemas in
Requirements 2-4.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from loki.models.enums import ClassificationMethod

__all__ = [
    "Effect",
    "GuidPredicate",
    "Matcher",
    "NamePredicate",
    "RawHashPredicate",
    "Rule",
    "RuleSet",
    "SizePredicate",
    "TypeHintPredicate",
]

# Rule_id charset constraint (R2.7).
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

# 64-character lower-case hex (R3.6).
_RAW_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

# Valid axis names (R4.2).
_AXIS_VALUES: frozenset[str] = frozenset({"type", "vendor", "security_posture", "mutability"})


def _canonical_uuid(value: str) -> str:
    """Normalize ``value`` to canonical lower-case 8-4-4-4-12 UUID form.

    Raises ``ValueError`` if ``value`` is not a parseable UUID.
    """

    return str(uuid.UUID(value)).lower()


class GuidPredicate(BaseModel):
    """``guid:`` predicate (R3.2).

    Stores one or more canonical lower-case UUIDs. The matcher
    fires when ``ExtractedComponent.guid`` (case-insensitive)
    equals any element. Sugar forms (single string vs.
    ``{in: [...]}``) are normalized at load time by the loader,
    not here; this model's invariant is "non-empty tuple of
    canonical UUIDs".
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    values: tuple[str, ...]

    @field_validator("values")
    @classmethod
    def _validate_values(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("guid predicate values must be non-empty")
        normalized: list[str] = []
        for raw in v:
            if not isinstance(raw, str):
                raise TypeError(f"guid predicate values must be strings, got {type(raw).__name__}")
            try:
                normalized.append(_canonical_uuid(raw))
            except ValueError as exc:
                raise ValueError(f"guid predicate value is not a valid UUID: {raw!r}") from exc
        return tuple(normalized)


class NamePredicate(BaseModel):
    """``name:`` predicate (R3.3).

    Exactly one of ``equals`` / ``prefix`` / ``suffix`` /
    ``contains``. The matcher fires when
    ``ExtractedComponent.name`` (case-sensitive) satisfies the
    chosen operator with ``value``.
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    op: Literal["equals", "prefix", "suffix", "contains"]
    value: str

    @field_validator("value")
    @classmethod
    def _validate_value(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("name predicate value must be non-empty")
        return v


class TypeHintPredicate(BaseModel):
    """``component_type_hint:`` predicate (R3.4).

    Stores one or more non-empty strings. The matcher fires when
    ``ExtractedComponent.component_type_hint`` (case-sensitive)
    equals any element.
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    values: tuple[str, ...]

    @field_validator("values")
    @classmethod
    def _validate_values(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("component_type_hint predicate values must be non-empty")
        for entry in v:
            if not isinstance(entry, str):
                raise TypeError(
                    f"component_type_hint values must be strings, got {type(entry).__name__}"
                )
            if not entry or not entry.strip():
                raise ValueError("component_type_hint values must each be non-empty")
        return v


class SizePredicate(BaseModel):
    """``size:`` predicate (R3.5).

    One or both of ``min`` / ``max``. ``min`` requires
    ``ExtractedComponent.size >= min``; ``max`` requires
    ``ExtractedComponent.size <= max``. Both must be
    non-negative; if both are set, ``min <= max``.
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    min: int | None = None
    max: int | None = None

    @field_validator("min", "max")
    @classmethod
    def _non_negative(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError("size predicate values must be non-negative")
        return v

    @model_validator(mode="after")
    def _at_least_one_bound(self) -> SizePredicate:
        if self.min is None and self.max is None:
            raise ValueError("size predicate requires at least one of min or max")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError(f"size predicate min ({self.min}) must be <= max ({self.max})")
        return self


class RawHashPredicate(BaseModel):
    """``raw_hash:`` predicate (R3.6).

    Stores one or more 64-character lower-case hex strings. The
    matcher fires when ``ExtractedComponent.raw_hash`` equals any
    element.
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    values: tuple[str, ...]

    @field_validator("values")
    @classmethod
    def _validate_values(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("raw_hash predicate values must be non-empty")
        normalized: list[str] = []
        for raw in v:
            if not isinstance(raw, str):
                raise TypeError(
                    f"raw_hash predicate values must be strings, got {type(raw).__name__}"
                )
            lowered = raw.lower()
            if not _RAW_HASH_RE.match(lowered):
                raise ValueError(f"raw_hash predicate value must be 64-char lowercase hex: {raw!r}")
            normalized.append(lowered)
        return tuple(normalized)


class Matcher(BaseModel):
    """Conjunctive Matcher (R3.1, R3.7-R3.8).

    Closed key set: any combination of ``guid`` / ``name`` /
    ``component_type_hint`` / ``size`` / ``raw_hash``, but at
    least one must be set. Conjunctive semantics: every populated
    predicate must fire for the rule to fire. Predicates targeting
    ``None`` component fields do not fire (R3.2-R3.4).
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    guid: GuidPredicate | None = None
    name: NamePredicate | None = None
    component_type_hint: TypeHintPredicate | None = None
    size: SizePredicate | None = None
    raw_hash: RawHashPredicate | None = None

    @model_validator(mode="after")
    def _at_least_one_predicate(self) -> Matcher:
        if (
            self.guid is None
            and self.name is None
            and self.component_type_hint is None
            and self.size is None
            and self.raw_hash is None
        ):
            raise ValueError("Matcher requires at least one populated predicate")
        return self


class Effect(BaseModel):
    """Effect block (R4.1, R4.2, R4.7).

    The output assertion that fires when the rule's matcher
    fires. ``label`` is validated against the axis enum at
    rule-load time (in the loader, where the axis context is
    available) rather than here. ``confidence`` is bounded to
    ``[0.0, 1.0]``. ``method`` is one of ``ClassificationMethod``.
    ``evidence``, when present, must be non-empty after
    stripping (so an empty-string evidence yields
    ``AxisClassification.evidence = None`` per R4.7's
    "carry vs not carry" distinction; stripped-empty values
    are rejected at load time rather than silently coerced).
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    label: str
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    method: ClassificationMethod
    evidence: str | None = None

    @field_validator("evidence")
    @classmethod
    def _validate_evidence(cls, v: str | None) -> str | None:
        if v is not None and (not v or not v.strip()):
            raise ValueError("evidence, when present, must be non-empty")
        return v


class Rule(BaseModel):
    """A single Rule (R2.7, R4)."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    rule_id: str
    axis: Literal["type", "vendor", "security_posture", "mutability"]
    matcher: Matcher
    effect: Effect

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, v: str) -> str:
        if not _RULE_ID_RE.match(v):
            raise ValueError("rule_id must match ^[a-z0-9][a-z0-9._-]{0,127}$")
        return v


class RuleSet(BaseModel):
    """Validated, immutable Rule_Set (R2.3).

    Holds the loaded rules as a tuple plus the absolute paths of
    the source rule files (in lexicographic order). Constructed by
    the loader after every per-file and cross-file check has
    passed; once constructed, never mutated for the lifetime of
    the pipeline instance.
    """

    model_config = ConfigDict(strict=True, frozen=True)
    taxonomy_version: str
    rules: tuple[Rule, ...]
    sources: tuple[Path, ...]
