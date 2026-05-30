"""Implant-rule loader and matcher."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

from loki.feeds.errors import FeedsConfigError
from loki.feeds.models import ImplantRuleLookupQuery, ImplantRuleLookupResult, ImplantRuleMatch

__all__: list[str] = [
    "ImplantRule",
    "ImplantRuleSet",
    "load_implant_rules",
    "match_implant_rules",
]

logger = logging.getLogger("loki.feeds")


@dataclass(frozen=True)
class ImplantRule:
    """A single implant detection rule."""

    rule_id: str  # prefixed: "implant:<slug>"
    threat_family: str  # e.g. "BlackLotus"
    content_hash: str | None
    firmware_guid: str | None


@dataclass(frozen=True)
class ImplantRuleSet:
    """Collection of loaded implant rules."""

    rules: tuple[ImplantRule, ...]


def _load_rules_from_dir(directory: Path) -> dict[str, ImplantRule]:
    """Load all YAML rule files from a directory.

    Returns a dict keyed by rule_id for easy merging.
    Raises FeedsConfigError on invalid files.
    """
    rules: dict[str, ImplantRule] = {}

    if not directory.exists() or not directory.is_dir():
        return rules

    for yaml_file in sorted(directory.glob("*.yaml")):
        try:
            text = yaml_file.read_text(encoding="utf-8")
            data = yaml.safe_load(text)
        except (OSError, yaml.YAMLError) as exc:
            raise FeedsConfigError(f"Failed to parse implant rule file {yaml_file}: {exc}") from exc

        if data is None:
            # Empty file — skip.
            continue

        if not isinstance(data, dict):
            raise FeedsConfigError(
                f"Implant rule file {yaml_file} must contain a mapping at the top level"
            )

        rule_id = data.get("rule_id")
        if not rule_id or not isinstance(rule_id, str):
            raise FeedsConfigError(f"Implant rule file {yaml_file} missing or invalid 'rule_id'")

        # Ensure prefix.
        if not rule_id.startswith("implant:"):
            rule_id = f"implant:{rule_id}"

        threat_family = data.get("threat_family")
        if not threat_family or not isinstance(threat_family, str):
            raise FeedsConfigError(
                f"Implant rule file {yaml_file} missing or invalid 'threat_family'"
            )

        ioc = data.get("ioc")
        if not isinstance(ioc, dict):
            raise FeedsConfigError(
                f"Implant rule file {yaml_file} missing or invalid 'ioc' mapping"
            )

        content_hash_raw = ioc.get("content_hash")
        firmware_guid_raw = ioc.get("firmware_guid")

        content_hash: str | None = str(content_hash_raw) if content_hash_raw is not None else None
        firmware_guid: str | None = (
            str(firmware_guid_raw) if firmware_guid_raw is not None else None
        )

        if content_hash is None and firmware_guid is None:
            raise FeedsConfigError(
                f"Implant rule file {yaml_file}: at least one of "
                f"'content_hash' or 'firmware_guid' must be non-null"
            )

        rule = ImplantRule(
            rule_id=rule_id,
            threat_family=threat_family,
            content_hash=content_hash,
            firmware_guid=firmware_guid,
        )
        rules[rule_id] = rule

    return rules


def load_implant_rules(builtin_dir: Path, operator_dir: Path | None) -> ImplantRuleSet:
    """Load and merge built-in + operator-extension implant rules.

    Operator rules shadow built-in rules on rule_id collision (R7.2).
    Logs a single INFO record per shadowed rule on first load.
    Raises FeedsConfigError on invalid rule files.
    """
    builtin_rules = _load_rules_from_dir(builtin_dir)

    if operator_dir is not None:
        operator_rules = _load_rules_from_dir(operator_dir)
    else:
        operator_rules = {}

    # Merge: operator shadows built-in.
    merged: dict[str, ImplantRule] = dict(builtin_rules)
    for rule_id, rule in operator_rules.items():
        if rule_id in merged:
            logger.info(
                "Operator rule %r shadows built-in rule for threat family %r",
                rule_id,
                merged[rule_id].threat_family,
            )
        merged[rule_id] = rule

    return ImplantRuleSet(rules=tuple(merged.values()))


def match_implant_rules(
    query: ImplantRuleLookupQuery, rule_set: ImplantRuleSet
) -> ImplantRuleLookupResult:
    """Match a query against the loaded implant rule set.

    Exact match on content_hash and/or firmware_guid.
    Results sorted lexicographically ascending by rule_id.
    Does NOT echo the matched value back in the result (no-leakage discipline).
    """
    matches: list[ImplantRuleMatch] = []

    for rule in rule_set.rules:
        matched_field: str | None = None

        # Check content_hash first (wins on tie).
        if (
            rule.content_hash is not None
            and query.content_hash
            and rule.content_hash.lower() == query.content_hash.lower()
        ):
            matched_field = "content_hash"
        elif (
            rule.firmware_guid is not None
            and query.firmware_guid is not None
            and rule.firmware_guid.lower() == query.firmware_guid.lower()
        ):
            matched_field = "firmware_guid"

        if matched_field is not None:
            matches.append(
                ImplantRuleMatch(
                    rule_id=rule.rule_id,
                    ioc_field=matched_field,
                    threat_family=rule.threat_family,
                )
            )

    # Sort lexicographically by rule_id for determinism.
    matches.sort(key=lambda m: m.rule_id)

    return ImplantRuleLookupResult(matches=matches)
