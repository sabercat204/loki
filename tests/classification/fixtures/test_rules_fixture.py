"""Smoke tests for the synthetic-rule-set fixture.

Per task 11: confirms the fixture writes valid YAML rule files
that can be parsed and that the returned ``RuleSet`` matches the
on-disk content. The full loader-round-trip test (parsing the
YAML through ``load_rule_set`` and asserting equality) lives in
Wave 3 once the loader exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from loki.classification.rules.schema import RuleSet
from tests.classification.fixtures import build_rule_files
from tests.classification.fixtures.synthetic_rules import DEFAULT_AXIS_DISTRIBUTION


def test_default_distribution_produces_twelve_rules(tmp_path: Path) -> None:
    rs = build_rule_files(tmp_path)
    assert sum(DEFAULT_AXIS_DISTRIBUTION.values()) == 12
    assert len(rs.rules) == 12


def test_returns_rule_set_instance(tmp_path: Path) -> None:
    rs = build_rule_files(tmp_path)
    assert isinstance(rs, RuleSet)


def test_writes_one_yaml_file_per_axis(tmp_path: Path) -> None:
    build_rule_files(tmp_path)
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == [
        "mutability.yaml",
        "security_posture.yaml",
        "type.yaml",
        "vendor.yaml",
    ]


def test_yaml_files_round_trip_through_safe_load(tmp_path: Path) -> None:
    """Each file is parseable as a ``{taxonomy_version, rules}`` mapping."""
    build_rule_files(tmp_path)
    for path in tmp_path.iterdir():
        with path.open("r", encoding="utf-8") as fh:
            payload = yaml.safe_load(fh)
        assert isinstance(payload, dict)
        assert set(payload.keys()) == {"taxonomy_version", "rules"}
        assert payload["taxonomy_version"] == "1.0.0"
        assert isinstance(payload["rules"], list)


def test_rule_ids_match_synthetic_pattern(tmp_path: Path) -> None:
    rs = build_rule_files(tmp_path)
    for rule in rs.rules:
        assert rule.rule_id.startswith("synthetic.")
        # Format: synthetic.{axis}.{idx:03d}
        parts = rule.rule_id.split(".")
        assert len(parts) == 3
        assert parts[0] == "synthetic"
        assert parts[1] in {"type", "vendor", "security_posture", "mutability"}
        assert parts[2].isdigit()
        assert len(parts[2]) == 3


def test_rule_ids_are_unique(tmp_path: Path) -> None:
    rs = build_rule_files(tmp_path)
    ids = [r.rule_id for r in rs.rules]
    assert len(set(ids)) == len(ids)


def test_sources_are_lexicographically_ordered(tmp_path: Path) -> None:
    rs = build_rule_files(tmp_path)
    sources = list(rs.sources)
    assert sources == sorted(sources)


def test_rule_set_taxonomy_version_propagates(tmp_path: Path) -> None:
    rs = build_rule_files(tmp_path, taxonomy_version="2.5.0")
    assert rs.taxonomy_version == "2.5.0"
    # And the YAML files match.
    for path in tmp_path.iterdir():
        with path.open("r", encoding="utf-8") as fh:
            payload = yaml.safe_load(fh)
        assert payload["taxonomy_version"] == "2.5.0"


def test_custom_distribution_controls_rule_count(tmp_path: Path) -> None:
    rs = build_rule_files(
        tmp_path,
        axis_distribution={
            "type": 2,
            "vendor": 1,
            "security_posture": 1,
            "mutability": 0,
        },
    )
    assert len(rs.rules) == 4
    axes = [r.axis for r in rs.rules]
    assert axes.count("type") == 2
    assert axes.count("vendor") == 1
    assert axes.count("security_posture") == 1
    assert axes.count("mutability") == 0


def test_unknown_axis_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown axis"):
        build_rule_files(tmp_path, axis_distribution={"unknown_axis": 1})


def test_negative_count_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=">= 0"):
        build_rule_files(tmp_path, axis_distribution={"type": -1})


def test_missing_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="does not exist"):
        build_rule_files(tmp_path / "nonexistent")


def test_path_is_a_file_raises(tmp_path: Path) -> None:
    file_path = tmp_path / "not_a_dir"
    file_path.write_text("hello")
    with pytest.raises(NotADirectoryError, match="not a directory"):
        build_rule_files(file_path)


def test_same_inputs_produce_byte_identical_yaml(tmp_path: Path) -> None:
    """Determinism: writing twice into separate dirs produces the same bytes."""
    dir_a = tmp_path / "a"
    dir_a.mkdir()
    build_rule_files(dir_a)
    dir_b = tmp_path / "b"
    dir_b.mkdir()
    build_rule_files(dir_b)
    for filename in ["type.yaml", "vendor.yaml", "security_posture.yaml", "mutability.yaml"]:
        a_bytes = (dir_a / filename).read_bytes()
        b_bytes = (dir_b / filename).read_bytes()
        assert a_bytes == b_bytes


def test_synthetic_rules_dir_fixture_has_files(synthetic_rules_dir: Path) -> None:
    """The ``synthetic_rules_dir`` pytest fixture should contain rule files."""
    files = list(synthetic_rules_dir.iterdir())
    assert len(files) == 4


def test_synthetic_rule_set_fixture_returns_rule_set(
    synthetic_rule_set: RuleSet,
) -> None:
    assert isinstance(synthetic_rule_set, RuleSet)
    assert len(synthetic_rule_set.rules) == 12
