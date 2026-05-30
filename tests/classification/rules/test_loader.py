"""Tests for the rule-set loader.

Covers Requirement 2 (file enumeration, taxonomy version,
duplicate rule_id detection, top-level shape validation), R3
(matcher predicate validation), R4 (effect schema +
axis-label-vs-enum membership). Per-rule failures surface as
``ClassificationRuleError``; whole-directory or whole-file
failures surface as ``ClassificationConfigError``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml

from loki.classification.errors import (
    ClassificationConfigError,
    ClassificationRuleError,
)
from loki.classification.rules.loader import load_rule_set
from loki.classification.rules.schema import RuleSet
from loki.models.config import ClassificationConfig
from tests.classification.fixtures import build_rule_files

_VALID_UUID = "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
_VALID_HASH = "a" * 64


def _config(rules_dir: Path, *, taxonomy_version: str = "1.0.0") -> ClassificationConfig:
    """Build a ClassificationConfig pointing at ``rules_dir``."""
    return ClassificationConfig(
        taxonomy_version=taxonomy_version,
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


def _write_yaml(path: Path, data: object) -> None:
    """Write a YAML file with sorted keys for deterministic output."""
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=True, default_flow_style=False)


# ---------------------------------------------------------------------------
# Directory-level failures (R2.4)
# ---------------------------------------------------------------------------


def test_missing_directory_raises_config_error(tmp_path: Path) -> None:
    nonexistent = tmp_path / "nope"
    with pytest.raises(ClassificationConfigError, match="does not exist"):
        load_rule_set(_config(nonexistent))


def test_not_a_directory_raises_config_error(tmp_path: Path) -> None:
    file_path = tmp_path / "rules-not-a-dir"
    file_path.write_text("not a directory")
    with pytest.raises(ClassificationConfigError, match="not a directory"):
        load_rule_set(_config(file_path))


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="POSIX permission semantics; root bypasses read permissions",
)
def test_unreadable_directory_raises_config_error(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rules_dir.chmod(0o000)
    try:
        with pytest.raises(ClassificationConfigError, match="not readable"):
            load_rule_set(_config(rules_dir))
    finally:
        rules_dir.chmod(0o755)  # let pytest clean up


def test_empty_directory_returns_empty_ruleset(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rs = load_rule_set(_config(rules_dir))
    assert isinstance(rs, RuleSet)
    assert rs.rules == ()
    assert rs.sources == ()


# ---------------------------------------------------------------------------
# File enumeration (R2.1, R2.2)
# ---------------------------------------------------------------------------


def test_loader_ignores_non_yaml_files(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    # A valid YAML file
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "type",
                    "matcher": {"guid": _VALID_UUID},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    # Foreign files that should be ignored
    (rules_dir / "README.md").write_text("# rules notes")
    (rules_dir / "rules.json").write_text("{}")
    (rules_dir / ".hidden.txt").write_text("ignored")
    # A subdirectory should also be ignored (depth-1 enumeration only)
    nested = rules_dir / "nested"
    nested.mkdir()
    _write_yaml(
        nested / "ignored.yaml",
        {"taxonomy_version": "1.0.0", "rules": []},
    )

    rs = load_rule_set(_config(rules_dir))
    assert len(rs.rules) == 1
    assert len(rs.sources) == 1
    assert rs.sources[0] == (rules_dir / "rules.yaml").resolve()


def test_loader_accepts_yml_and_yaml_extensions(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "a.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "rule.a",
                    "axis": "type",
                    "matcher": {"guid": _VALID_UUID},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    _write_yaml(
        rules_dir / "b.yml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "rule.b",
                    "axis": "vendor",
                    "matcher": {"guid": _VALID_UUID},
                    "effect": {
                        "label": "INTEL",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    rs = load_rule_set(_config(rules_dir))
    assert len(rs.rules) == 2


def test_files_load_in_lexicographic_order(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    # Write in deliberately reversed creation order; loader should
    # still report them in lexicographic order.
    for filename, rule_id in [
        ("z.yaml", "rule.z"),
        ("a.yaml", "rule.a"),
        ("m.yaml", "rule.m"),
    ]:
        _write_yaml(
            rules_dir / filename,
            {
                "taxonomy_version": "1.0.0",
                "rules": [
                    {
                        "rule_id": rule_id,
                        "axis": "type",
                        "matcher": {"guid": _VALID_UUID},
                        "effect": {
                            "label": "UEFI_DRIVER",
                            "confidence": 0.5,
                            "method": "RULE",
                        },
                    }
                ],
            },
        )
    rs = load_rule_set(_config(rules_dir))
    assert [s.name for s in rs.sources] == ["a.yaml", "m.yaml", "z.yaml"]
    assert [r.rule_id for r in rs.rules] == ["rule.a", "rule.m", "rule.z"]


# ---------------------------------------------------------------------------
# Top-level file shape (R2.5)
# ---------------------------------------------------------------------------


def test_top_level_must_be_a_mapping(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rules.yaml").write_text("- not a mapping\n")
    with pytest.raises(ClassificationConfigError, match="top level must be a mapping"):
        load_rule_set(_config(rules_dir))


def test_top_level_missing_rules_key_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(rules_dir / "rules.yaml", {"taxonomy_version": "1.0.0"})
    with pytest.raises(ClassificationConfigError, match="missing keys"):
        load_rule_set(_config(rules_dir))


def test_top_level_missing_taxonomy_version_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(rules_dir / "rules.yaml", {"rules": []})
    with pytest.raises(ClassificationConfigError, match="missing keys"):
        load_rule_set(_config(rules_dir))


def test_top_level_extra_keys_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {"taxonomy_version": "1.0.0", "rules": [], "extra": "not allowed"},
    )
    with pytest.raises(ClassificationConfigError, match="unexpected keys"):
        load_rule_set(_config(rules_dir))


def test_malformed_yaml_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rules.yaml").write_text(":\n  not: valid: yaml: at: all\n")
    with pytest.raises(ClassificationConfigError, match="malformed YAML"):
        load_rule_set(_config(rules_dir))


# ---------------------------------------------------------------------------
# taxonomy_version (R2.6)
# ---------------------------------------------------------------------------


def test_taxonomy_version_mismatch_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "9.9.9",
            "rules": [],
        },
    )
    with pytest.raises(ClassificationConfigError, match="taxonomy_version mismatch"):
        load_rule_set(_config(rules_dir, taxonomy_version="1.0.0"))


def test_taxonomy_version_must_be_a_string(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": 1,  # int, not string
            "rules": [],
        },
    )
    with pytest.raises(ClassificationConfigError, match="must be a string"):
        load_rule_set(_config(rules_dir))


# ---------------------------------------------------------------------------
# Duplicate rule_id (R2.8)
# ---------------------------------------------------------------------------


def test_duplicate_rule_id_across_files_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_entry = {
        "rule_id": "dupe.rule",
        "axis": "type",
        "matcher": {"guid": _VALID_UUID},
        "effect": {
            "label": "UEFI_DRIVER",
            "confidence": 0.5,
            "method": "RULE",
        },
    }
    _write_yaml(
        rules_dir / "first.yaml",
        {"taxonomy_version": "1.0.0", "rules": [rule_entry]},
    )
    _write_yaml(
        rules_dir / "second.yaml",
        {"taxonomy_version": "1.0.0", "rules": [rule_entry]},
    )
    with pytest.raises(ClassificationConfigError) as excinfo:
        load_rule_set(_config(rules_dir))
    rendered = str(excinfo.value)
    # The error must mention both source files (R2.8) and the
    # duplicated rule_id.
    assert "dupe.rule" in rendered
    assert "first.yaml" in rendered
    assert "second.yaml" in rendered


def test_duplicate_rule_id_within_same_file_rejected(tmp_path: Path) -> None:
    """Duplicate detection runs across the accumulated rule list,
    so within-file duplicates are caught the same way as
    across-file duplicates."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_entry = {
        "rule_id": "same.id",
        "axis": "type",
        "matcher": {"guid": _VALID_UUID},
        "effect": {
            "label": "UEFI_DRIVER",
            "confidence": 0.5,
            "method": "RULE",
        },
    }
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [rule_entry, rule_entry],
        },
    )
    with pytest.raises(ClassificationConfigError, match="duplicate rule_id"):
        load_rule_set(_config(rules_dir))


# ---------------------------------------------------------------------------
# Per-rule schema (R2.7, R3, R4)
# ---------------------------------------------------------------------------


def test_rule_entry_must_be_a_mapping(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {"taxonomy_version": "1.0.0", "rules": ["not a mapping"]},
    )
    with pytest.raises(ClassificationRuleError, match="must be a mapping"):
        load_rule_set(_config(rules_dir))


def test_rule_entry_missing_keys_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [{"rule_id": "incomplete"}],  # missing axis, matcher, effect
        },
    )
    with pytest.raises(ClassificationRuleError, match="missing keys"):
        load_rule_set(_config(rules_dir))


def test_rule_entry_extra_keys_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "type",
                    "matcher": {"guid": _VALID_UUID},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                    "extra": "not allowed",
                }
            ],
        },
    )
    with pytest.raises(ClassificationRuleError, match="unexpected keys"):
        load_rule_set(_config(rules_dir))


def test_unknown_axis_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "brand_new_axis",
                    "matcher": {"guid": _VALID_UUID},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    with pytest.raises(ClassificationRuleError, match="axis must be one of"):
        load_rule_set(_config(rules_dir))


def test_axis_label_must_be_member_of_axis_enum(tmp_path: Path) -> None:
    """R4.2: a Rule with axis=vendor must use a VendorLabel value."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "wrong.label.for.axis",
                    "axis": "vendor",
                    "matcher": {"guid": _VALID_UUID},
                    "effect": {
                        # UEFI_DRIVER is a ComponentTypeLabel, not a VendorLabel.
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    with pytest.raises(ClassificationRuleError, match="not a valid vendor label"):
        load_rule_set(_config(rules_dir))


def test_invalid_rule_id_charset_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "Invalid.Uppercase.RuleID",
                    "axis": "type",
                    "matcher": {"guid": _VALID_UUID},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    with pytest.raises(ClassificationRuleError, match="rule validation failed"):
        load_rule_set(_config(rules_dir))


def test_matcher_with_unknown_predicate_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "type",
                    "matcher": {"unknown_predicate": "value"},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    with pytest.raises(ClassificationRuleError, match="unknown predicate keys"):
        load_rule_set(_config(rules_dir))


def test_empty_matcher_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "type",
                    "matcher": {},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    with pytest.raises(ClassificationRuleError, match="matcher validation failed"):
        load_rule_set(_config(rules_dir))


def test_invalid_uuid_in_guid_predicate_rejected(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_yaml(
        rules_dir / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "type",
                    "matcher": {"guid": "not-a-uuid"},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    with pytest.raises(ClassificationRuleError, match="guid predicate"):
        load_rule_set(_config(rules_dir))


# ---------------------------------------------------------------------------
# Sugar form normalization (R3.2-R3.6)
# ---------------------------------------------------------------------------


def test_guid_single_string_and_in_list_normalize_to_same_predicate(
    tmp_path: Path,
) -> None:
    """A `guid: "<uuid>"` rule should produce a RuleSet equivalent
    to `guid: {in: ["<uuid>"]}`."""
    dir_a = tmp_path / "a"
    dir_a.mkdir()
    _write_yaml(
        dir_a / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "type",
                    "matcher": {"guid": _VALID_UUID},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    dir_b = tmp_path / "b"
    dir_b.mkdir()
    _write_yaml(
        dir_b / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "type",
                    "matcher": {"guid": {"in": [_VALID_UUID]}},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    rs_a = load_rule_set(_config(dir_a))
    rs_b = load_rule_set(_config(dir_b))
    # Compare the predicate values directly (sources differ; rules
    # should not).
    assert rs_a.rules[0].matcher.guid == rs_b.rules[0].matcher.guid


def test_raw_hash_single_and_in_list_normalize(tmp_path: Path) -> None:
    """Same sugar-form normalization for raw_hash."""
    dir_a = tmp_path / "a"
    dir_a.mkdir()
    _write_yaml(
        dir_a / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "type",
                    "matcher": {"raw_hash": _VALID_HASH},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    dir_b = tmp_path / "b"
    dir_b.mkdir()
    _write_yaml(
        dir_b / "rules.yaml",
        {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": "test.rule",
                    "axis": "type",
                    "matcher": {"raw_hash": {"in": [_VALID_HASH]}},
                    "effect": {
                        "label": "UEFI_DRIVER",
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
            ],
        },
    )
    rs_a = load_rule_set(_config(dir_a))
    rs_b = load_rule_set(_config(dir_b))
    assert rs_a.rules[0].matcher.raw_hash == rs_b.rules[0].matcher.raw_hash


# ---------------------------------------------------------------------------
# Integration with the synthetic-rules fixture (round-trip)
# ---------------------------------------------------------------------------


def test_synthetic_rules_fixture_round_trips_through_loader(
    tmp_path: Path,
) -> None:
    """The deterministic fixture writes YAML; the loader reads it
    back; the resulting RuleSet matches the fixture's expected
    output. This is the round-trip test deferred from Wave 2's
    test_rules_fixture.py."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    expected = build_rule_files(rules_dir)
    loaded = load_rule_set(_config(rules_dir))
    # Compare rule sets as JSON-shaped dicts so frozen-tuple
    # comparison details don't trip the assertion.
    assert loaded.taxonomy_version == expected.taxonomy_version
    assert len(loaded.rules) == len(expected.rules)
    assert {r.rule_id for r in loaded.rules} == {r.rule_id for r in expected.rules}
    # Sources should match in lexicographic order.
    assert [s.name for s in loaded.sources] == [s.name for s in expected.sources]


# ---------------------------------------------------------------------------
# Reproducibility (R2.3 + determinism)
# ---------------------------------------------------------------------------


def test_loader_is_reproducible_across_two_invocations(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir)
    rs1 = load_rule_set(_config(rules_dir))
    rs2 = load_rule_set(_config(rules_dir))
    assert rs1.taxonomy_version == rs2.taxonomy_version
    assert [r.rule_id for r in rs1.rules] == [r.rule_id for r in rs2.rules]
    # Stronger: every rule's full dump matches.
    assert [r.model_dump() for r in rs1.rules] == [r.model_dump() for r in rs2.rules]
