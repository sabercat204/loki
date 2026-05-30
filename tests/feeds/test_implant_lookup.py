"""Tests for loki.feeds.implants — rule matching/lookup."""

from __future__ import annotations

from loki.feeds.implants import ImplantRule, ImplantRuleSet, match_implant_rules
from loki.feeds.models import ImplantRuleLookupQuery


def _make_rule_set() -> ImplantRuleSet:
    """Create a test rule set with multiple rules."""
    return ImplantRuleSet(
        rules=(
            ImplantRule(
                rule_id="implant:alpha",
                threat_family="AlphaFamily",
                content_hash="aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222",
                firmware_guid=None,
            ),
            ImplantRule(
                rule_id="implant:beta",
                threat_family="BetaFamily",
                content_hash=None,
                firmware_guid="11111111-2222-3333-4444-555555555555",
            ),
            ImplantRule(
                rule_id="implant:gamma",
                threat_family="GammaFamily",
                content_hash="deadbeefcafeface0123456789abcdef0123456789abcdef0123456789abcdef",
                firmware_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ),
        )
    )


class TestHashMatch:
    """Content hash matching."""

    def test_exact_hash_match(self) -> None:
        rule_set = _make_rule_set()
        query = ImplantRuleLookupQuery(
            content_hash="aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
        )
        result = match_implant_rules(query, rule_set)
        assert len(result.matches) == 1
        assert result.matches[0].rule_id == "implant:alpha"
        assert result.matches[0].ioc_field == "content_hash"
        assert result.matches[0].threat_family == "AlphaFamily"

    def test_case_insensitive_hash_match(self) -> None:
        rule_set = _make_rule_set()
        query = ImplantRuleLookupQuery(
            content_hash="AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666AAAA1111BBBB2222"
        )
        result = match_implant_rules(query, rule_set)
        assert len(result.matches) == 1
        assert result.matches[0].rule_id == "implant:alpha"


class TestGuidMatch:
    """Firmware GUID matching."""

    def test_exact_guid_match(self) -> None:
        rule_set = _make_rule_set()
        query = ImplantRuleLookupQuery(
            content_hash="0000000000000000000000000000000000000000000000000000000000000000",
            firmware_guid="11111111-2222-3333-4444-555555555555",
        )
        result = match_implant_rules(query, rule_set)
        assert len(result.matches) == 1
        assert result.matches[0].rule_id == "implant:beta"
        assert result.matches[0].ioc_field == "firmware_guid"

    def test_case_insensitive_guid_match(self) -> None:
        rule_set = _make_rule_set()
        query = ImplantRuleLookupQuery(
            content_hash="0000000000000000000000000000000000000000000000000000000000000000",
            firmware_guid="11111111-2222-3333-4444-555555555555".upper(),
        )
        result = match_implant_rules(query, rule_set)
        assert len(result.matches) == 1
        assert result.matches[0].rule_id == "implant:beta"


class TestNoMatch:
    """No match scenarios."""

    def test_no_match_returns_empty(self) -> None:
        rule_set = _make_rule_set()
        query = ImplantRuleLookupQuery(
            content_hash="0000000000000000000000000000000000000000000000000000000000000000",
            firmware_guid="99999999-9999-9999-9999-999999999999",
        )
        result = match_implant_rules(query, rule_set)
        assert result.matches == []

    def test_empty_rule_set_returns_empty(self) -> None:
        rule_set = ImplantRuleSet(rules=())
        query = ImplantRuleLookupQuery(
            content_hash="aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
        )
        result = match_implant_rules(query, rule_set)
        assert result.matches == []


class TestSortOrder:
    """Results sorted by rule_id ascending."""

    def test_multiple_matches_sorted(self) -> None:
        rule_set = ImplantRuleSet(
            rules=(
                ImplantRule(
                    rule_id="implant:zebra",
                    threat_family="Zebra",
                    content_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    firmware_guid=None,
                ),
                ImplantRule(
                    rule_id="implant:alpha",
                    threat_family="Alpha",
                    content_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    firmware_guid=None,
                ),
            )
        )
        query = ImplantRuleLookupQuery(
            content_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        result = match_implant_rules(query, rule_set)
        assert len(result.matches) == 2
        assert result.matches[0].rule_id == "implant:alpha"
        assert result.matches[1].rule_id == "implant:zebra"


class TestDeterminism:
    """Two calls with same inputs produce same results."""

    def test_deterministic_results(self) -> None:
        rule_set = _make_rule_set()
        query = ImplantRuleLookupQuery(
            content_hash="deadbeefcafeface0123456789abcdef0123456789abcdef0123456789abcdef",
            firmware_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        result1 = match_implant_rules(query, rule_set)
        result2 = match_implant_rules(query, rule_set)
        assert result1 == result2


class TestContentHashPriority:
    """When both fields match same rule, content_hash wins."""

    def test_content_hash_wins_on_tie(self) -> None:
        rule_set = _make_rule_set()
        # gamma has both content_hash and firmware_guid.
        query = ImplantRuleLookupQuery(
            content_hash="deadbeefcafeface0123456789abcdef0123456789abcdef0123456789abcdef",
            firmware_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        result = match_implant_rules(query, rule_set)
        assert len(result.matches) == 1
        assert result.matches[0].rule_id == "implant:gamma"
        assert result.matches[0].ioc_field == "content_hash"


class TestNoLeakage:
    """Result must NOT contain the matched hash/GUID value."""

    def test_no_hash_in_result(self) -> None:
        rule_set = _make_rule_set()
        query = ImplantRuleLookupQuery(
            content_hash="aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
        )
        result = match_implant_rules(query, rule_set)
        match = result.matches[0]
        # The ImplantRuleMatch dataclass should not have a 'value' or 'hash' field.
        assert not hasattr(match, "matched_value")
        assert not hasattr(match, "content_hash")
        assert not hasattr(match, "firmware_guid")
        # Only has rule_id, ioc_field, threat_family.
        field_names = {f for f in match.__dataclass_fields__}
        assert field_names == {"rule_id", "ioc_field", "threat_family"}
