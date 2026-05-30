"""Tests for the ``MatchStrategy`` StrEnum.

Covers task 3 acceptance: the three values exist, serialize to the
documented string forms, are imported from both ``loki.models`` and
``loki.models.enums``, and round-trip through Pydantic when consumed by
``AnalysisConfig`` (the AnalysisConfig integration is exercised in
task 4's test file; this file covers the enum in isolation).
"""

from __future__ import annotations

from loki.models import MatchStrategy as MatchStrategyTopLevel
from loki.models.enums import MatchStrategy


def test_match_strategy_has_three_values() -> None:
    assert {m.value for m in MatchStrategy} == {"EXPLICIT", "AUTO", "EXPLICIT_OR_AUTO"}


def test_match_strategy_explicit_value() -> None:
    assert MatchStrategy.EXPLICIT.value == "EXPLICIT"
    assert MatchStrategy.EXPLICIT == "EXPLICIT"


def test_match_strategy_auto_value() -> None:
    assert MatchStrategy.AUTO.value == "AUTO"
    assert MatchStrategy.AUTO == "AUTO"


def test_match_strategy_explicit_or_auto_value() -> None:
    assert MatchStrategy.EXPLICIT_OR_AUTO.value == "EXPLICIT_OR_AUTO"
    assert MatchStrategy.EXPLICIT_OR_AUTO == "EXPLICIT_OR_AUTO"


def test_match_strategy_re_exported_from_top_level_models() -> None:
    assert MatchStrategy is MatchStrategyTopLevel


def test_match_strategy_serializes_as_plain_string() -> None:
    # StrEnum members serialize as their string value in JSON / YAML.
    assert str(MatchStrategy.AUTO) == "AUTO"
    assert f"{MatchStrategy.EXPLICIT}" == "EXPLICIT"


def test_match_strategy_constructor_from_string() -> None:
    assert MatchStrategy("AUTO") is MatchStrategy.AUTO
    assert MatchStrategy("EXPLICIT") is MatchStrategy.EXPLICIT
    assert MatchStrategy("EXPLICIT_OR_AUTO") is MatchStrategy.EXPLICIT_OR_AUTO
