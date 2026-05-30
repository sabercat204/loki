"""Tests for loki.feeds.implants — rule loading."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from loki.feeds.errors import FeedsConfigError
from loki.feeds.implants import ImplantRuleSet, load_implant_rules


@pytest.fixture()
def builtin_dir(tmp_path: Path) -> Path:
    """Create a builtin directory with a valid rule file."""
    d = tmp_path / "builtin"
    d.mkdir()
    (d / "test_rule.yaml").write_text(
        'rule_id: "implant:test.rule1"\n'
        'threat_family: "TestFamily"\n'
        "ioc:\n"
        '  content_hash: "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"\n'
        "  firmware_guid: null\n",
        encoding="utf-8",
    )
    return d


@pytest.fixture()
def operator_dir(tmp_path: Path) -> Path:
    """Create an operator directory with a valid rule file."""
    d = tmp_path / "operator"
    d.mkdir()
    (d / "op_rule.yaml").write_text(
        'rule_id: "implant:operator.rule1"\n'
        'threat_family: "OperatorThreat"\n'
        "ioc:\n"
        "  content_hash: null\n"
        '  firmware_guid: "11111111-2222-3333-4444-555555555555"\n',
        encoding="utf-8",
    )
    return d


class TestLoadBuiltinOnly:
    """Test loading built-in rules without operator dir."""

    def test_loads_builtin_rules(self, builtin_dir: Path) -> None:
        result = load_implant_rules(builtin_dir, None)
        assert isinstance(result, ImplantRuleSet)
        assert len(result.rules) == 1
        assert result.rules[0].rule_id == "implant:test.rule1"
        assert result.rules[0].threat_family == "TestFamily"

    def test_empty_directory_returns_empty_set(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = load_implant_rules(empty_dir, None)
        assert result.rules == ()

    def test_nonexistent_directory_returns_empty_set(self, tmp_path: Path) -> None:
        result = load_implant_rules(tmp_path / "nonexistent", None)
        assert result.rules == ()


class TestLoadWithOperator:
    """Test loading with operator extension directory."""

    def test_merges_builtin_and_operator(self, builtin_dir: Path, operator_dir: Path) -> None:
        result = load_implant_rules(builtin_dir, operator_dir)
        assert len(result.rules) == 2
        rule_ids = {r.rule_id for r in result.rules}
        assert "implant:test.rule1" in rule_ids
        assert "implant:operator.rule1" in rule_ids

    def test_operator_shadows_builtin(
        self, builtin_dir: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Create operator dir with same rule_id as builtin.
        op_dir = tmp_path / "shadow_operator"
        op_dir.mkdir()
        (op_dir / "shadow.yaml").write_text(
            'rule_id: "implant:test.rule1"\n'
            'threat_family: "OperatorOverride"\n'
            "ioc:\n"
            '  content_hash: "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333"\n'
            "  firmware_guid: null\n",
            encoding="utf-8",
        )
        with caplog.at_level(logging.INFO, logger="loki.feeds"):
            result = load_implant_rules(builtin_dir, op_dir)

        # Operator wins.
        assert len(result.rules) == 1
        assert result.rules[0].threat_family == "OperatorOverride"

        # INFO logged about shadowing.
        assert any("shadows" in record.message for record in caplog.records)


class TestRuleIdPrefix:
    """Rules without 'implant:' prefix get it prepended."""

    def test_prefix_prepended(self, tmp_path: Path) -> None:
        d = tmp_path / "prefix_test"
        d.mkdir()
        (d / "no_prefix.yaml").write_text(
            'rule_id: "my.rule"\n'
            'threat_family: "TestFamily"\n'
            "ioc:\n"
            '  content_hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"\n'
            "  firmware_guid: null\n",
            encoding="utf-8",
        )
        result = load_implant_rules(d, None)
        assert result.rules[0].rule_id == "implant:my.rule"


class TestInvalidRuleFiles:
    """Error handling for malformed rule files."""

    def test_invalid_yaml_raises_config_error(self, tmp_path: Path) -> None:
        d = tmp_path / "bad_yaml"
        d.mkdir()
        (d / "bad.yaml").write_text("{{{{invalid yaml", encoding="utf-8")
        with pytest.raises(FeedsConfigError, match="Failed to parse"):
            load_implant_rules(d, None)

    def test_missing_both_ioc_fields_raises_config_error(self, tmp_path: Path) -> None:
        d = tmp_path / "no_ioc"
        d.mkdir()
        (d / "nope.yaml").write_text(
            'rule_id: "implant:bad.rule"\n'
            'threat_family: "Bad"\n'
            "ioc:\n"
            "  content_hash: null\n"
            "  firmware_guid: null\n",
            encoding="utf-8",
        )
        with pytest.raises(FeedsConfigError, match="at least one"):
            load_implant_rules(d, None)

    def test_missing_rule_id_raises_config_error(self, tmp_path: Path) -> None:
        d = tmp_path / "no_id"
        d.mkdir()
        (d / "noid.yaml").write_text(
            'threat_family: "NoId"\nioc:\n  content_hash: "abcd" \n  firmware_guid: null\n',
            encoding="utf-8",
        )
        with pytest.raises(FeedsConfigError, match="rule_id"):
            load_implant_rules(d, None)

    def test_missing_threat_family_raises_config_error(self, tmp_path: Path) -> None:
        d = tmp_path / "no_family"
        d.mkdir()
        (d / "nofam.yaml").write_text(
            'rule_id: "implant:x"\nioc:\n  content_hash: "abcd"\n  firmware_guid: null\n',
            encoding="utf-8",
        )
        with pytest.raises(FeedsConfigError, match="threat_family"):
            load_implant_rules(d, None)

    def test_non_mapping_raises_config_error(self, tmp_path: Path) -> None:
        d = tmp_path / "not_map"
        d.mkdir()
        (d / "list.yaml").write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(FeedsConfigError, match="mapping"):
            load_implant_rules(d, None)


class TestBuiltinRulesLoad:
    """Verify that the actual package built-in rules load correctly."""

    def test_load_package_builtins(self) -> None:
        builtin_path = Path(__file__).resolve().parents[2] / "loki" / "feeds" / "builtin_implants"
        result = load_implant_rules(builtin_path, None)
        assert len(result.rules) == 3
        families = {r.threat_family for r in result.rules}
        assert "BlackLotus" in families
        assert "MosaicRegressor" in families
        assert "LoJax" in families
        # All have implant: prefix.
        for rule in result.rules:
            assert rule.rule_id.startswith("implant:")
