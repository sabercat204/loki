"""Analysis models for the LOKI platform.

This module defines the analysis output models:
- ``DeviationScore`` — composite risk score for a deviation
- ``FindingEvidence`` — structured evidence for a finding
- ``FindingRecord`` — a single analysis finding
- ``ActionRecord`` — recommended remediation action linked to a finding
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, field_validator

from loki.models.classification import ClassificationRecord
from loki.models.enums import (
    MutabilityChange,
    SecurityDirection,
    SeverityLevel,
    SignatureDelta,
)

__all__ = [
    "ActionRecord",
    "DeviationScore",
    "FindingEvidence",
    "FindingRecord",
]


class DeviationScore(BaseModel):
    """Composite risk score for a deviation.

    Combines multiple risk factors into a single composite score
    with a priority ranking for triage ordering.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    base_severity: SeverityLevel
    component_criticality: float
    security_direction: SecurityDirection
    signature_delta: SignatureDelta
    cve_introduced: bool
    mutability_change: MutabilityChange
    composite_score: float
    priority_rank: int

    @field_validator("component_criticality")
    @classmethod
    def _validate_component_criticality(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("component_criticality must be between 0.0 and 1.0")
        return v

    @field_validator("composite_score")
    @classmethod
    def _validate_composite_score(cls, v: float) -> float:
        if v < 0.0 or v > 10.0:
            raise ValueError("composite_score must be between 0.0 and 10.0")
        return v

    @field_validator("priority_rank")
    @classmethod
    def _validate_priority_rank(cls, v: int) -> int:
        if v < 1:
            raise ValueError("priority_rank must be >= 1")
        return v


class FindingEvidence(BaseModel):
    """Structured evidence supporting an analysis finding.

    The optional ``deviation_score`` field is populated by the analysis
    engine for ``classification_mismatch`` findings (analysis-engine
    R9.1); every other finding category leaves it ``None`` (analysis-
    engine R9.11). Populated values carry the per-axis breakdown
    (``security_direction``, ``signature_delta``, ``mutability_change``,
    ``component_criticality``) plus the composite score and priority
    rank derived by the engine.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    classification_record: ClassificationRecord | None = None
    matched_rule: str | None = None
    matched_cve: str | None = None
    matched_signature: str | None = None
    raw_indicators: list[str] = []
    deviation_score: DeviationScore | None = None


class FindingRecord(BaseModel):
    """A single analysis finding for a firmware component."""

    model_config = ConfigDict(strict=True, frozen=False)

    finding_id: uuid.UUID
    component_id: uuid.UUID
    severity: SeverityLevel
    category: str
    title: str
    description: str
    evidence: FindingEvidence
    recommended_action: str


class ActionRecord(BaseModel):
    """Recommended remediation action linked to a finding."""

    model_config = ConfigDict(strict=True, frozen=False)

    action_id: uuid.UUID
    finding_id: uuid.UUID
    action_type: str
    description: str
    reference: str | None = None
