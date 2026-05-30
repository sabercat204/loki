"""Tests for the analysis-engine extension fields on ``AnalysisConfig``.

Covers task 4 acceptance: the three new fields (``match_strategy``,
``confidence_gap_threshold``, ``baseline_id``) are present, have the
documented defaults, are validated within their declared ranges, and
round-trip through both Pydantic and YAML.

The four-key set check on ``severity_weights`` is intentionally NOT
covered here; that check is engine-side per R14.1 and lives in the
matching module's tests (task 8).
"""

from __future__ import annotations

import math
import uuid
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from loki.models import AnalysisConfig, MatchStrategy, SeverityLevel
from loki.models.config import LokiConfig

_VALID_WEIGHTS = {
    "critical": 0.5,
    "high": 0.3,
    "medium": 0.15,
    "low": 0.05,
}


def _make_config(**overrides: Any) -> AnalysisConfig:
    """Build a valid ``AnalysisConfig`` with optional field overrides."""
    base: dict[str, Any] = {
        "severity_weights": _VALID_WEIGHTS,
        "default_severity_threshold": SeverityLevel.MEDIUM,
    }
    base.update(overrides)
    return AnalysisConfig(**base)


def test_match_strategy_default_is_auto() -> None:
    cfg = _make_config()
    assert cfg.match_strategy is MatchStrategy.AUTO


def test_match_strategy_explicit_accepts() -> None:
    cfg = _make_config(match_strategy=MatchStrategy.EXPLICIT)
    assert cfg.match_strategy is MatchStrategy.EXPLICIT


def test_match_strategy_explicit_or_auto_accepts() -> None:
    cfg = _make_config(match_strategy=MatchStrategy.EXPLICIT_OR_AUTO)
    assert cfg.match_strategy is MatchStrategy.EXPLICIT_OR_AUTO


def test_confidence_gap_threshold_default_is_0_6() -> None:
    cfg = _make_config()
    assert math.isclose(cfg.confidence_gap_threshold, 0.6)


def test_confidence_gap_threshold_accepts_0_0() -> None:
    cfg = _make_config(confidence_gap_threshold=0.0)
    assert cfg.confidence_gap_threshold == 0.0


def test_confidence_gap_threshold_accepts_1_0() -> None:
    cfg = _make_config(confidence_gap_threshold=1.0)
    assert cfg.confidence_gap_threshold == 1.0


def test_confidence_gap_threshold_rejects_negative() -> None:
    with pytest.raises(ValidationError):
        _make_config(confidence_gap_threshold=-0.1)


def test_confidence_gap_threshold_rejects_above_one() -> None:
    with pytest.raises(ValidationError):
        _make_config(confidence_gap_threshold=1.1)


def test_baseline_id_default_is_none() -> None:
    cfg = _make_config()
    assert cfg.baseline_id is None


def test_baseline_id_accepts_valid_uuid() -> None:
    target = uuid.uuid4()
    cfg = _make_config(baseline_id=target)
    assert cfg.baseline_id == target


def test_baseline_id_accepts_explicit_none() -> None:
    cfg = _make_config(baseline_id=None)
    assert cfg.baseline_id is None


def test_cve_score_bump_default_is_0_5() -> None:
    cfg = _make_config()
    assert math.isclose(cfg.cve_score_bump, 0.5)


def test_cve_score_bump_accepts_0_0() -> None:
    cfg = _make_config(cve_score_bump=0.0)
    assert cfg.cve_score_bump == 0.0


def test_cve_score_bump_accepts_5_0() -> None:
    cfg = _make_config(cve_score_bump=5.0)
    assert cfg.cve_score_bump == 5.0


def test_cve_score_bump_rejects_negative() -> None:
    with pytest.raises(ValidationError):
        _make_config(cve_score_bump=-0.1)


def test_cve_score_bump_rejects_above_five() -> None:
    with pytest.raises(ValidationError):
        _make_config(cve_score_bump=5.1)


def test_existing_fields_unchanged() -> None:
    """The pre-existing fields keep their contracts (defensive regression)."""
    cfg = _make_config()
    assert cfg.default_severity_threshold is SeverityLevel.MEDIUM
    assert cfg.report_template is None
    assert cfg.severity_weights == _VALID_WEIGHTS


def test_severity_weights_sum_validator_still_fires() -> None:
    """The pre-existing sum-to-1.0 validator must still reject bad weights."""
    with pytest.raises(ValidationError):
        AnalysisConfig(
            severity_weights={"a": 0.5, "b": 0.6},  # sums to 1.1
            default_severity_threshold=SeverityLevel.MEDIUM,
        )


def test_pydantic_round_trip_preserves_new_fields() -> None:
    target = uuid.uuid4()
    original = _make_config(
        match_strategy=MatchStrategy.EXPLICIT_OR_AUTO,
        confidence_gap_threshold=0.42,
        baseline_id=target,
        cve_score_bump=1.5,
    )
    # JSON round-trip: model_validate_json natively decodes enums + UUIDs.
    restored = AnalysisConfig.model_validate_json(original.model_dump_json())
    assert restored.match_strategy is MatchStrategy.EXPLICIT_OR_AUTO
    assert math.isclose(restored.confidence_gap_threshold, 0.42)
    assert restored.baseline_id == target
    assert math.isclose(restored.cve_score_bump, 1.5)


def test_dict_round_trip_with_strict_false_preserves_new_fields() -> None:
    """Mirror ``LokiConfig.from_yaml``'s relaxed-mode coercion path."""
    target = uuid.uuid4()
    original = _make_config(
        match_strategy=MatchStrategy.AUTO,
        confidence_gap_threshold=0.7,
        baseline_id=target,
    )
    serialized = original.model_dump(mode="json")
    restored = AnalysisConfig.model_validate(serialized, strict=False)
    assert restored.match_strategy is MatchStrategy.AUTO
    assert math.isclose(restored.confidence_gap_threshold, 0.7)
    assert restored.baseline_id == target


def test_yaml_round_trip_preserves_new_fields(tmp_path: Path) -> None:
    target = uuid.uuid4()
    raw: dict[str, Any] = {
        "general": {
            "default_output_format": "JSON",
            "color": "AUTO",
            "verbosity": 0,
            "log_level": "INFO",
        },
        "extraction": {
            "default_output_dir": "/tmp/x",
            "max_component_size": 1_000_000,
            "timeout_per_component": 30,
        },
        "classification": {
            "taxonomy_version": "1.0.0",
            "confidence_threshold": 0.6,
            "rules_path": "/tmp/r",
        },
        "analysis": {
            "severity_weights": _VALID_WEIGHTS,
            "default_severity_threshold": "MEDIUM",
            "report_template": None,
            "match_strategy": "EXPLICIT_OR_AUTO",
            "confidence_gap_threshold": 0.42,
            "baseline_id": str(target),
        },
        "baseline": {
            "storage_path": "/tmp/b",
            "auto_match": True,
        },
        "feeds": {
            "nvd_url": "https://example/feed",
            "update_interval": 3600,
            "cache_path": "/tmp/c",
            "implant_rules_path": "/tmp/i",
        },
        "fleet": {
            "default_severity_threshold": "MEDIUM",
            "storage_path": "/tmp/f",
        },
    }
    config_path = tmp_path / "loki.yaml"
    config_path.write_text(yaml.safe_dump(raw))
    cfg = LokiConfig.from_yaml(config_path)
    assert cfg.analysis.match_strategy is MatchStrategy.EXPLICIT_OR_AUTO
    assert math.isclose(cfg.analysis.confidence_gap_threshold, 0.42)
    assert cfg.analysis.baseline_id == target


def test_yaml_round_trip_with_defaults_omitted(tmp_path: Path) -> None:
    """A YAML config that omits the three new fields uses the defaults."""
    raw: dict[str, Any] = {
        "general": {
            "default_output_format": "JSON",
            "color": "AUTO",
            "verbosity": 0,
            "log_level": "INFO",
        },
        "extraction": {
            "default_output_dir": "/tmp/x",
            "max_component_size": 1_000_000,
            "timeout_per_component": 30,
        },
        "classification": {
            "taxonomy_version": "1.0.0",
            "confidence_threshold": 0.6,
            "rules_path": "/tmp/r",
        },
        "analysis": {
            "severity_weights": _VALID_WEIGHTS,
            "default_severity_threshold": "MEDIUM",
            "report_template": None,
        },
        "baseline": {
            "storage_path": "/tmp/b",
            "auto_match": True,
        },
        "feeds": {
            "nvd_url": "https://example/feed",
            "update_interval": 3600,
            "cache_path": "/tmp/c",
            "implant_rules_path": "/tmp/i",
        },
        "fleet": {
            "default_severity_threshold": "MEDIUM",
            "storage_path": "/tmp/f",
        },
    }
    config_path = tmp_path / "loki.yaml"
    config_path.write_text(yaml.safe_dump(raw))
    cfg = LokiConfig.from_yaml(config_path)
    assert cfg.analysis.match_strategy is MatchStrategy.AUTO
    assert math.isclose(cfg.analysis.confidence_gap_threshold, 0.6)
    assert cfg.analysis.baseline_id is None
    assert math.isclose(cfg.analysis.cve_score_bump, 0.5)
