"""Tests for the analysis-engine extension on ``FindingEvidence``.

Covers task 5 acceptance: the new optional ``deviation_score`` field
defaults to ``None``, accepts a valid ``DeviationScore``, round-trips
through Pydantic JSON / YAML, and is serialized in a stable position.
"""

from __future__ import annotations

import yaml

from loki.models import (
    DeviationScore,
    FindingEvidence,
    MutabilityChange,
    SecurityDirection,
    SeverityLevel,
    SignatureDelta,
)


def _make_score(*, composite: float = 6.4, rank: int = 1) -> DeviationScore:
    return DeviationScore(
        base_severity=SeverityLevel.HIGH,
        component_criticality=0.85,
        security_direction=SecurityDirection.DEGRADED,
        signature_delta=SignatureDelta.NONE,
        cve_introduced=False,
        mutability_change=MutabilityChange.NONE,
        composite_score=composite,
        priority_rank=rank,
    )


def test_deviation_score_default_is_none() -> None:
    evidence = FindingEvidence()
    assert evidence.deviation_score is None


def test_deviation_score_accepts_populated_value() -> None:
    score = _make_score()
    evidence = FindingEvidence(deviation_score=score)
    assert evidence.deviation_score is score


def test_existing_fields_preserved_with_default_deviation_score() -> None:
    """Existing call shape (no deviation_score) keeps old field defaults."""
    evidence = FindingEvidence()
    assert evidence.classification_record is None
    assert evidence.matched_rule is None
    assert evidence.matched_cve is None
    assert evidence.matched_signature is None
    assert evidence.raw_indicators == []
    assert evidence.deviation_score is None


def test_pydantic_round_trip_with_score() -> None:
    score = _make_score(composite=4.2, rank=3)
    original = FindingEvidence(deviation_score=score)
    # JSON round-trip: model_validate_json natively decodes enums.
    restored = FindingEvidence.model_validate_json(original.model_dump_json())
    assert restored.deviation_score is not None
    assert restored.deviation_score.composite_score == 4.2
    assert restored.deviation_score.priority_rank == 3
    assert restored.deviation_score.base_severity is SeverityLevel.HIGH


def test_pydantic_round_trip_without_score() -> None:
    original = FindingEvidence()
    restored = FindingEvidence.model_validate_json(original.model_dump_json())
    assert restored.deviation_score is None


def test_yaml_round_trip_with_score() -> None:
    score = _make_score(composite=3.0, rank=5)
    original = FindingEvidence(deviation_score=score)
    yaml_text = yaml.safe_dump(original.model_dump(mode="json"))
    # YAML round-trip uses strict=False to coerce string-encoded enums
    # (mirrors LokiConfig.from_yaml's discipline).
    restored = FindingEvidence.model_validate(yaml.safe_load(yaml_text), strict=False)
    assert restored.deviation_score is not None
    assert restored.deviation_score.composite_score == 3.0
    assert restored.deviation_score.priority_rank == 5


def test_json_serialization_includes_deviation_score_when_populated() -> None:
    score = _make_score()
    evidence = FindingEvidence(deviation_score=score)
    payload = evidence.model_dump(mode="json")
    assert "deviation_score" in payload
    assert payload["deviation_score"]["composite_score"] == 6.4


def test_json_serialization_emits_null_for_default_deviation_score() -> None:
    evidence = FindingEvidence()
    payload = evidence.model_dump(mode="json")
    assert payload["deviation_score"] is None
