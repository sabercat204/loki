"""Deterministic synthetic-rule-set fixture builder.

Writes a set of YAML rule files into a target directory and
returns the ``RuleSet`` the loader should produce when it reads
that directory back. Used by every test that needs a populated
Rule_Set: loader tests (Wave 3), classifier tests (Wave 4),
pipeline tests (Wave 5), and the Hypothesis property suite
(Wave 7).

The default axis distribution is
``{"type": 4, "vendor": 4, "security_posture": 2, "mutability": 2}``,
totalling 12 rules. Each rule's ``rule_id`` is
``synthetic.{axis}.{idx:03d}``; matchers reference the
``build_components`` fixture's GUIDs by index so each rule fires
on a known synthetic component, giving downstream tests a
predictable classification map.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import yaml

from loki.classification.rules.schema import (
    Effect,
    GuidPredicate,
    Matcher,
    Rule,
    RuleSet,
)
from loki.models import LOKI_NAMESPACE
from loki.models.enums import (
    ClassificationMethod,
    ComponentTypeLabel,
    MutabilityLabel,
    SecurityPostureLabel,
    VendorLabel,
)

__all__ = ["DEFAULT_AXIS_DISTRIBUTION", "build_rule_files"]

# Same fixture namespace used in synthetic_components.py — kept in
# sync so rule matchers and component GUIDs derive from the same
# seed family.
_FIXTURE_NAMESPACE = uuid.uuid5(LOKI_NAMESPACE, "tests.classification.fixtures")

DEFAULT_AXIS_DISTRIBUTION: dict[str, int] = {
    "type": 4,
    "vendor": 4,
    "security_posture": 2,
    "mutability": 2,
}

# Per-axis cycle of labels that synthetic rules emit. Must be
# real members of the corresponding axis enum (R4.2). Cycling
# means deterministic distribution across rule indices.
_TYPE_LABEL_CYCLE: tuple[str, ...] = (
    ComponentTypeLabel.UEFI_DRIVER.value,
    ComponentTypeLabel.PEI_MODULE.value,
    ComponentTypeLabel.DXE_DRIVER.value,
    ComponentTypeLabel.OPTION_ROM.value,
)
_VENDOR_LABEL_CYCLE: tuple[str, ...] = (
    VendorLabel.INTEL.value,
    VendorLabel.AMD.value,
    VendorLabel.AMI.value,
    VendorLabel.PHOENIX.value,
)
_SECURITY_LABEL_CYCLE: tuple[str, ...] = (
    SecurityPostureLabel.SECURE.value,
    SecurityPostureLabel.VULNERABLE.value,
)
_MUTABILITY_LABEL_CYCLE: tuple[str, ...] = (
    MutabilityLabel.READONLY.value,
    MutabilityLabel.MUTABLE.value,
)
_LABEL_CYCLES: dict[str, tuple[str, ...]] = {
    "type": _TYPE_LABEL_CYCLE,
    "vendor": _VENDOR_LABEL_CYCLE,
    "security_posture": _SECURITY_LABEL_CYCLE,
    "mutability": _MUTABILITY_LABEL_CYCLE,
}


def _component_guid(component_index: int) -> str:
    """Replicate ``synthetic_components.build_components`` GUID derivation.

    Kept in sync with the matching helper in
    ``synthetic_components.py``. If either changes, both must
    change together.
    """
    return str(uuid.uuid5(_FIXTURE_NAMESPACE, f"comp-guid-{component_index}"))


def build_rule_files(
    rules_dir: Path,
    *,
    axis_distribution: dict[str, int] | None = None,
    taxonomy_version: str = "1.0.0",
) -> RuleSet:
    """Build deterministic YAML rule files inside ``rules_dir``.

    One YAML file per axis: ``{axis}.yaml`` carrying every rule
    targeting that axis. Filename ordering is therefore
    deterministic across filesystems (``mutability.yaml`` <
    ``security_posture.yaml`` < ``type.yaml`` < ``vendor.yaml``
    in lexicographic order, which matters for the loader's
    duplicate-rule_id error reporting and for the
    ``RuleSet.sources`` ordering).

    Args:
        rules_dir: Target directory to write rule files into.
            Must already exist; the caller (typically a
            ``tmp_path`` fixture) is responsible for creation.
        axis_distribution: Number of rules per axis. Defaults to
            :data:`DEFAULT_AXIS_DISTRIBUTION`.
        taxonomy_version: Value to write into each file's
            ``taxonomy_version`` key. Must match the
            ``ClassificationConfig.taxonomy_version`` the loader
            is given (R2.6).

    Returns:
        The ``RuleSet`` instance the loader should produce when
        it reads ``rules_dir``. Rules are returned in the
        loader's documented load order: lexicographic by
        filename, then in-file order.

    Raises:
        FileNotFoundError: ``rules_dir`` does not exist.
        ValueError: ``axis_distribution`` carries a key that
            isn't a valid axis name, or a value that isn't a
            non-negative int.
    """
    if not rules_dir.exists():
        raise FileNotFoundError(f"rules_dir does not exist: {rules_dir}")
    if not rules_dir.is_dir():
        raise NotADirectoryError(f"rules_dir is not a directory: {rules_dir}")

    distribution = axis_distribution if axis_distribution is not None else DEFAULT_AXIS_DISTRIBUTION
    valid_axes = {"type", "vendor", "security_posture", "mutability"}
    for axis_name, axis_count in distribution.items():
        if axis_name not in valid_axes:
            raise ValueError(f"unknown axis: {axis_name!r}")
        if axis_count < 0:
            raise ValueError(f"axis_distribution[{axis_name!r}] must be >= 0, got {axis_count}")

    rules_by_axis: dict[str, list[Rule]] = {}
    for axis in valid_axes:
        rules_by_axis[axis] = []
        for idx in range(distribution.get(axis, 0)):
            label_cycle = _LABEL_CYCLES[axis]
            rules_by_axis[axis].append(
                Rule(
                    rule_id=f"synthetic.{axis}.{idx:03d}",
                    axis=axis,  # type: ignore[arg-type]
                    matcher=Matcher(guid=GuidPredicate(values=(_component_guid(idx),))),
                    effect=Effect(
                        label=label_cycle[idx % len(label_cycle)],
                        # Confidence cycles deterministically through
                        # five values (0.5, 0.6, 0.7, 0.8, 0.9) so the
                        # builder accepts arbitrary axis sizes without
                        # exceeding the [0.0, 1.0] bound.
                        confidence=0.5 + ((idx % 5) * 0.1),
                        method=ClassificationMethod.RULE,
                        evidence=f"synthetic match on component {idx}",
                    ),
                )
            )

    # Write one file per axis; filename order matches the loader's
    # lexicographic enumeration so RuleSet.sources is predictable.
    sources: list[Path] = []
    for axis in sorted(valid_axes):
        path = rules_dir / f"{axis}.yaml"
        payload: dict[str, Any] = {
            "taxonomy_version": taxonomy_version,
            "rules": [_rule_to_yaml_dict(r) for r in rules_by_axis[axis]],
        }
        with path.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(
                payload,
                fh,
                sort_keys=True,
                default_flow_style=False,
                allow_unicode=True,
            )
        sources.append(path)

    # The expected RuleSet's `rules` tuple matches the loader's
    # documented order: lexicographic by source path, then in-file
    # order within each file.
    flat_rules: list[Rule] = []
    for axis in sorted(valid_axes):
        flat_rules.extend(rules_by_axis[axis])
    return RuleSet(
        taxonomy_version=taxonomy_version,
        rules=tuple(flat_rules),
        sources=tuple(sources),
    )


def _rule_to_yaml_dict(rule: Rule) -> dict[str, Any]:
    """Render a ``Rule`` as a YAML-friendly dict.

    Uses the canonical (non-sugar) form: ``guid: {in: [...]}``,
    ``raw_hash: {in: [...]}``, etc. The loader normalizes both
    sugar and canonical forms to the same in-memory shape, so the
    fixture's choice of canonical form keeps the YAML readable
    and predictable.
    """
    matcher_dict: dict[str, Any] = {}
    if rule.matcher.guid is not None:
        if len(rule.matcher.guid.values) == 1:
            matcher_dict["guid"] = rule.matcher.guid.values[0]
        else:
            matcher_dict["guid"] = {"in": list(rule.matcher.guid.values)}
    if rule.matcher.name is not None:
        matcher_dict["name"] = {rule.matcher.name.op: rule.matcher.name.value}
    if rule.matcher.component_type_hint is not None:
        if len(rule.matcher.component_type_hint.values) == 1:
            matcher_dict["component_type_hint"] = rule.matcher.component_type_hint.values[0]
        else:
            matcher_dict["component_type_hint"] = {
                "in": list(rule.matcher.component_type_hint.values)
            }
    if rule.matcher.size is not None:
        size_dict: dict[str, int] = {}
        if rule.matcher.size.min is not None:
            size_dict["min"] = rule.matcher.size.min
        if rule.matcher.size.max is not None:
            size_dict["max"] = rule.matcher.size.max
        matcher_dict["size"] = size_dict
    if rule.matcher.raw_hash is not None:
        if len(rule.matcher.raw_hash.values) == 1:
            matcher_dict["raw_hash"] = rule.matcher.raw_hash.values[0]
        else:
            matcher_dict["raw_hash"] = {"in": list(rule.matcher.raw_hash.values)}

    effect_dict: dict[str, Any] = {
        "label": rule.effect.label,
        "confidence": rule.effect.confidence,
        "method": rule.effect.method.value,
    }
    if rule.effect.evidence is not None:
        effect_dict["evidence"] = rule.effect.evidence

    return {
        "rule_id": rule.rule_id,
        "axis": rule.axis,
        "matcher": matcher_dict,
        "effect": effect_dict,
    }
