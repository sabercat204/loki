"""YAML rule-file loader.

Implements ``load_rule_set(config)``: enumerates ``*.yaml`` /
``*.yml`` files at depth 1 inside ``config.rules_path``, parses
each via ``yaml.safe_load``, validates the top-level
``{taxonomy_version, rules}`` shape, normalizes predicate sugar
forms, and produces an immutable ``RuleSet`` (R2). Errors raise
``ClassificationConfigError`` / ``ClassificationRuleError``;
nothing reaches per-component classification with a partial
Rule_Set.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from loki.classification.errors import (
    ClassificationConfigError,
    ClassificationRuleError,
)
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
from loki.models.config import ClassificationConfig
from loki.models.enums import (
    ClassificationMethod,
    ComponentTypeLabel,
    MutabilityLabel,
    SecurityPostureLabel,
    VendorLabel,
)

__all__ = ["load_rule_set"]

# The exact set of top-level keys allowed in a rule file (R2.5).
_RULE_FILE_KEYS: frozenset[str] = frozenset({"taxonomy_version", "rules"})

# The exact set of keys allowed inside a Rule entry (R2.7).
_RULE_ENTRY_KEYS: frozenset[str] = frozenset({"rule_id", "axis", "matcher", "effect"})

# The exact set of keys allowed inside an Effect entry (R4.1).
_EFFECT_KEYS: frozenset[str] = frozenset({"label", "confidence", "method", "evidence"})

# The closed predicate vocabulary (R3.1).
_MATCHER_PREDICATE_KEYS: frozenset[str] = frozenset(
    {"guid", "name", "component_type_hint", "size", "raw_hash"}
)

# Per-axis label enum lookup (R4.2). Each entry maps an axis
# string to the set of valid label string values for that axis.
_AXIS_LABEL_VALUES: dict[str, frozenset[str]] = {
    "type": frozenset(member.value for member in ComponentTypeLabel),
    "vendor": frozenset(member.value for member in VendorLabel),
    "security_posture": frozenset(member.value for member in SecurityPostureLabel),
    "mutability": frozenset(member.value for member in MutabilityLabel),
}


def load_rule_set(config: ClassificationConfig) -> RuleSet:
    """Load and validate the full Rule_Set.

    Implements Requirement 2 in full plus the cross-cutting
    R3 / R4 validators that need axis context.

    Args:
        config: Caller-supplied ``ClassificationConfig``.
            ``config.rules_path`` resolves to the directory
            containing rule files; ``config.taxonomy_version``
            is matched against each file's
            ``taxonomy_version`` key.

    Returns:
        A validated, immutable ``RuleSet`` carrying every rule
        loaded across every YAML file, along with the absolute
        source paths in lexicographic order.

    Raises:
        ClassificationConfigError: Whole-directory or
            whole-file failure (missing dir, not a directory,
            unreadable, malformed YAML, top-level shape
            mismatch, taxonomy_version mismatch, duplicate
            ``rule_id``).
        ClassificationRuleError: Per-rule schema / matcher /
            effect validation failure.
    """

    rules_path = Path(config.rules_path).resolve()

    # 1. Resolve and validate the rules directory (R2.4).
    if not rules_path.exists():
        raise ClassificationConfigError(rules_path, "rules directory does not exist")
    if not rules_path.is_dir():
        raise ClassificationConfigError(rules_path, "rules path is not a directory")
    if not os.access(rules_path, os.R_OK | os.X_OK):
        raise ClassificationConfigError(rules_path, "rules directory is not readable")

    # 2-3. Enumerate depth-1 YAML files in lexicographic order (R2.2).
    candidates = sorted(
        entry
        for entry in rules_path.iterdir()
        if entry.is_file() and entry.suffix.lower() in {".yaml", ".yml"}
    )

    accumulated_rules: list[Rule] = []
    rule_id_to_path: dict[str, Path] = {}
    sources: list[Path] = []

    for path in candidates:
        # 4a. Parse YAML.
        try:
            with path.open("r", encoding="utf-8") as fh:
                payload = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ClassificationConfigError(path, f"malformed YAML: {exc}") from exc
        except OSError as exc:
            raise ClassificationConfigError(path, f"could not read rule file: {exc}") from exc

        # 4b. Validate top-level shape (R2.5).
        if not isinstance(payload, dict):
            raise ClassificationConfigError(
                path,
                f"rule file top level must be a mapping, got {type(payload).__name__}",
            )
        actual_keys = frozenset(payload.keys())
        if actual_keys != _RULE_FILE_KEYS:
            extra = actual_keys - _RULE_FILE_KEYS
            missing = _RULE_FILE_KEYS - actual_keys
            details: list[str] = []
            if missing:
                details.append(f"missing keys {sorted(missing)}")
            if extra:
                details.append(f"unexpected keys {sorted(extra)}")
            raise ClassificationConfigError(
                path,
                "rule file top-level shape must be "
                "{taxonomy_version, rules}: " + ", ".join(details),
            )

        # 4c. Compare taxonomy_version (R2.6).
        observed_taxonomy_version = payload["taxonomy_version"]
        if not isinstance(observed_taxonomy_version, str):
            raise ClassificationConfigError(
                path,
                "taxonomy_version must be a string, got "
                + type(observed_taxonomy_version).__name__,
            )
        if observed_taxonomy_version != config.taxonomy_version:
            raise ClassificationConfigError(
                path,
                f"taxonomy_version mismatch: expected "
                f"{config.taxonomy_version!r}, got "
                f"{observed_taxonomy_version!r}",
            )

        # 4d. Build each Rule.
        rules_list = payload["rules"]
        if not isinstance(rules_list, list):
            raise ClassificationConfigError(
                path,
                f"`rules` key must be a list, got {type(rules_list).__name__}",
            )
        for entry in rules_list:
            rule = _build_rule(entry, path)
            # 5. Duplicate rule_id detection across files (R2.8).
            existing = rule_id_to_path.get(rule.rule_id)
            if existing is not None:
                raise ClassificationConfigError(
                    path,
                    f"duplicate rule_id {rule.rule_id!r}: also defined in {existing}",
                )
            rule_id_to_path[rule.rule_id] = path
            accumulated_rules.append(rule)

        sources.append(path)

    # 6. Build the immutable RuleSet.
    return RuleSet(
        taxonomy_version=config.taxonomy_version,
        rules=tuple(accumulated_rules),
        sources=tuple(sources),
    )


def _build_rule(entry: object, path: Path) -> Rule:
    """Validate a single rule entry and produce a ``Rule`` instance.

    Implements R2.7 (closed key set on each Rule), R3 (predicate
    schema), R4 (Effect schema + axis-label enum membership).
    On any failure raises ``ClassificationRuleError`` carrying
    ``path`` and the offending entry's ``rule_id`` (or ``None``
    when the rule_id itself is unparseable).
    """

    if not isinstance(entry, dict):
        raise ClassificationRuleError(
            path, None, f"rule entry must be a mapping, got {type(entry).__name__}"
        )

    rule_id_raw = entry.get("rule_id")
    rule_id = rule_id_raw if isinstance(rule_id_raw, str) else None

    actual_keys = frozenset(entry.keys())
    if actual_keys != _RULE_ENTRY_KEYS:
        extra = actual_keys - _RULE_ENTRY_KEYS
        missing = _RULE_ENTRY_KEYS - actual_keys
        details: list[str] = []
        if missing:
            details.append(f"missing keys {sorted(missing)}")
        if extra:
            details.append(f"unexpected keys {sorted(extra)}")
        raise ClassificationRuleError(
            path,
            rule_id,
            "rule entry shape must be {rule_id, axis, matcher, effect}: " + ", ".join(details),
        )

    axis = entry["axis"]
    if not isinstance(axis, str) or axis not in _AXIS_LABEL_VALUES:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"axis must be one of {sorted(_AXIS_LABEL_VALUES)}, got {axis!r}",
        )

    matcher_raw = entry["matcher"]
    if not isinstance(matcher_raw, dict):
        raise ClassificationRuleError(
            path,
            rule_id,
            f"matcher must be a mapping, got {type(matcher_raw).__name__}",
        )
    matcher = _build_matcher(matcher_raw, path, rule_id)

    effect_raw = entry["effect"]
    if not isinstance(effect_raw, dict):
        raise ClassificationRuleError(
            path,
            rule_id,
            f"effect must be a mapping, got {type(effect_raw).__name__}",
        )
    effect = _build_effect(effect_raw, axis, path, rule_id)

    # Construct the Rule (which re-validates rule_id charset and
    # axis Literal via the schema's field validators). Pydantic
    # ValidationError gets converted to ClassificationRuleError
    # for a uniform error type.
    try:
        return Rule(
            rule_id=str(rule_id_raw),
            axis=axis,  # type: ignore[arg-type]
            matcher=matcher,
            effect=effect,
        )
    except Exception as exc:  # pragma: no cover - schema-side rejection paths
        raise ClassificationRuleError(
            path,
            rule_id,
            f"rule validation failed: {exc}",
        ) from exc


def _build_matcher(matcher_raw: dict[str, Any], path: Path, rule_id: str | None) -> Matcher:
    """Normalize sugar forms and construct a ``Matcher``."""

    actual_keys = frozenset(matcher_raw.keys())
    extra = actual_keys - _MATCHER_PREDICATE_KEYS
    if extra:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"matcher contains unknown predicate keys: {sorted(extra)}",
        )

    guid_predicate: GuidPredicate | None = None
    name_predicate: NamePredicate | None = None
    type_hint_predicate: TypeHintPredicate | None = None
    size_predicate: SizePredicate | None = None
    raw_hash_predicate: RawHashPredicate | None = None
    if "guid" in matcher_raw:
        guid_predicate = _build_guid_predicate(matcher_raw["guid"], path, rule_id)
    if "name" in matcher_raw:
        name_predicate = _build_name_predicate(matcher_raw["name"], path, rule_id)
    if "component_type_hint" in matcher_raw:
        type_hint_predicate = _build_type_hint_predicate(
            matcher_raw["component_type_hint"], path, rule_id
        )
    if "size" in matcher_raw:
        size_predicate = _build_size_predicate(matcher_raw["size"], path, rule_id)
    if "raw_hash" in matcher_raw:
        raw_hash_predicate = _build_raw_hash_predicate(matcher_raw["raw_hash"], path, rule_id)

    try:
        return Matcher(
            guid=guid_predicate,
            name=name_predicate,
            component_type_hint=type_hint_predicate,
            size=size_predicate,
            raw_hash=raw_hash_predicate,
        )
    except Exception as exc:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"matcher validation failed: {exc}",
        ) from exc


def _build_guid_predicate(raw: object, path: Path, rule_id: str | None) -> GuidPredicate:
    """Accept ``"<single-uuid>"`` or ``{in: [list]}`` (R3.2)."""
    values: tuple[str, ...]
    if isinstance(raw, str):
        values = (raw,)
    elif isinstance(raw, dict):
        values = _expect_in_list(raw, path, rule_id, predicate_key="guid")
    else:
        raise ClassificationRuleError(
            path,
            rule_id,
            "guid predicate must be a string or {in: [...]}, got " + type(raw).__name__,
        )
    try:
        return GuidPredicate(values=values)
    except Exception as exc:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"guid predicate value rejected: {exc}",
        ) from exc


def _build_name_predicate(raw: object, path: Path, rule_id: str | None) -> NamePredicate:
    """Accept ``{<op>: <value>}`` where op is one of equals/prefix/suffix/contains (R3.3)."""
    if not isinstance(raw, dict):
        raise ClassificationRuleError(
            path,
            rule_id,
            f"name predicate must be a mapping, got {type(raw).__name__}",
        )
    if len(raw) != 1:
        raise ClassificationRuleError(
            path,
            rule_id,
            "name predicate must contain exactly one key from "
            "{equals, prefix, suffix, contains}, got " + str(sorted(raw.keys())),
        )
    op_raw, value = next(iter(raw.items()))
    op_str = str(op_raw)
    if op_str not in {"equals", "prefix", "suffix", "contains"}:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"name predicate op must be one of "
            f"{{equals, prefix, suffix, contains}}, got {op_raw!r}",
        )
    if not isinstance(value, str):
        raise ClassificationRuleError(
            path,
            rule_id,
            f"name predicate value must be a string, got {type(value).__name__}",
        )
    try:
        return NamePredicate(op=op_str, value=value)  # type: ignore[arg-type]
    except Exception as exc:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"name predicate value rejected: {exc}",
        ) from exc


def _build_type_hint_predicate(raw: object, path: Path, rule_id: str | None) -> TypeHintPredicate:
    """Accept ``"<single>"`` or ``{in: [list]}`` (R3.4)."""
    values: tuple[str, ...]
    if isinstance(raw, str):
        values = (raw,)
    elif isinstance(raw, dict):
        values = _expect_in_list(raw, path, rule_id, predicate_key="component_type_hint")
    else:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"component_type_hint predicate must be a string or "
            f"{{in: [...]}}, got {type(raw).__name__}",
        )
    try:
        return TypeHintPredicate(values=values)
    except Exception as exc:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"component_type_hint predicate value rejected: {exc}",
        ) from exc


def _build_size_predicate(raw: object, path: Path, rule_id: str | None) -> SizePredicate:
    """Accept ``{min: int}`` and/or ``{max: int}`` (R3.5)."""
    if not isinstance(raw, dict):
        raise ClassificationRuleError(
            path,
            rule_id,
            f"size predicate must be a mapping, got {type(raw).__name__}",
        )
    extra_keys = set(raw.keys()) - {"min", "max"}
    if extra_keys:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"size predicate contains unknown keys: {sorted(extra_keys)}",
        )
    min_value = raw.get("min")
    max_value = raw.get("max")
    # Reject non-int (including bool, which is technically an int subclass in Python).
    for label, value in [("min", min_value), ("max", max_value)]:
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            raise ClassificationRuleError(
                path,
                rule_id,
                f"size predicate {label} must be an integer, got " + type(value).__name__,
            )
    try:
        return SizePredicate(min=min_value, max=max_value)
    except Exception as exc:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"size predicate rejected: {exc}",
        ) from exc


def _build_raw_hash_predicate(raw: object, path: Path, rule_id: str | None) -> RawHashPredicate:
    """Accept ``"<64-hex>"`` or ``{in: [list]}`` (R3.6)."""
    values: tuple[str, ...]
    if isinstance(raw, str):
        values = (raw,)
    elif isinstance(raw, dict):
        values = _expect_in_list(raw, path, rule_id, predicate_key="raw_hash")
    else:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"raw_hash predicate must be a string or {{in: [...]}}, got {type(raw).__name__}",
        )
    try:
        return RawHashPredicate(values=values)
    except Exception as exc:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"raw_hash predicate value rejected: {exc}",
        ) from exc


def _expect_in_list(
    raw: dict[str, Any],
    path: Path,
    rule_id: str | None,
    *,
    predicate_key: str,
) -> tuple[str, ...]:
    """Validate a ``{in: [list of strings]}`` sugar form."""
    if list(raw.keys()) != ["in"]:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"{predicate_key} mapping form must use the single key 'in', got "
            + str(sorted(raw.keys())),
        )
    values_raw = raw["in"]
    if not isinstance(values_raw, list):
        raise ClassificationRuleError(
            path,
            rule_id,
            f"{predicate_key}.in must be a list, got {type(values_raw).__name__}",
        )
    out: list[str] = []
    for v in values_raw:
        if not isinstance(v, str):
            raise ClassificationRuleError(
                path,
                rule_id,
                f"{predicate_key}.in entries must be strings, got " + type(v).__name__,
            )
        out.append(v)
    return tuple(out)


def _build_effect(effect_raw: dict[str, Any], axis: str, path: Path, rule_id: str | None) -> Effect:
    """Build an ``Effect`` and enforce R4.2 axis-label enum membership."""

    actual_keys = frozenset(effect_raw.keys())
    extra = actual_keys - _EFFECT_KEYS
    if extra:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"effect contains unknown keys: {sorted(extra)}",
        )
    missing = {"label", "confidence", "method"} - actual_keys
    if missing:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"effect missing required keys: {sorted(missing)}",
        )

    label = effect_raw["label"]
    if not isinstance(label, str):
        raise ClassificationRuleError(
            path,
            rule_id,
            f"effect.label must be a string, got {type(label).__name__}",
        )

    # R4.2: label must be a member of the axis's enum.
    if label not in _AXIS_LABEL_VALUES[axis]:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"effect.label {label!r} is not a valid {axis} label "
            f"(expected one of {sorted(_AXIS_LABEL_VALUES[axis])})",
        )

    # Coerce method to the strict-mode enum required by the Effect
    # schema. The schema rejects plain strings under strict=True,
    # so the YAML's string method name needs to be looked up here.
    method_raw = effect_raw["method"]
    if isinstance(method_raw, ClassificationMethod):
        method = method_raw
    elif isinstance(method_raw, str):
        try:
            method = ClassificationMethod(method_raw)
        except ValueError as exc:
            raise ClassificationRuleError(
                path,
                rule_id,
                f"effect.method {method_raw!r} is not a valid "
                f"ClassificationMethod (expected one of "
                f"{sorted(m.value for m in ClassificationMethod)})",
            ) from exc
    else:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"effect.method must be a string, got {type(method_raw).__name__}",
        )

    try:
        return Effect(
            label=label,
            confidence=effect_raw["confidence"],
            method=method,
            evidence=effect_raw.get("evidence"),
        )
    except Exception as exc:
        raise ClassificationRuleError(
            path,
            rule_id,
            f"effect validation failed: {exc}",
        ) from exc
