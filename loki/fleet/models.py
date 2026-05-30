"""Internal models for the Fleet analysis engine."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

__all__: list[str] = []


@dataclass(frozen=True)
class FleetRiskScore:
    """Per-image risk score used internally by compute_risk_ranking."""

    image_id: uuid.UUID
    risk_score: float
    finding_count: int
