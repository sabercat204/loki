"""Report models for the LOKI platform.

This module defines the report output models:
- ``ReportSummary`` — summary counts for an analysis report
- ``ImageAnalysisReport`` — full report for a single firmware image
- ``FleetAnalysisReport`` — aggregate report across multiple images
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from loki.models.analysis import ActionRecord, FindingRecord
from loki.models.baseline import BaselineComparison
from loki.models.enums import PostureRating, SeverityLevel
from loki.models.firmware import FirmwareImage

__all__ = [
    "FleetAnalysisReport",
    "ImageAnalysisReport",
    "ReportSummary",
]


class ReportSummary(BaseModel):
    """Summary counts for an analysis report."""

    model_config = ConfigDict(strict=True, frozen=False)

    total_components: int
    findings_by_severity: dict[SeverityLevel, int]

    @field_validator("total_components")
    @classmethod
    def _validate_total_components(cls, v: int) -> int:
        if v < 0:
            raise ValueError("total_components must be >= 0")
        return v


class ImageAnalysisReport(BaseModel):
    """Full report for a single firmware image.

    ``summary`` is auto-computed from the ``findings`` list — counting
    findings by severity level and deriving total_components from
    image_metadata.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    report_id: uuid.UUID
    timestamp: datetime
    analysis_version: str
    image_id: uuid.UUID
    image_metadata: FirmwareImage
    posture_rating: PostureRating
    summary: ReportSummary = ReportSummary(total_components=0, findings_by_severity={})
    findings: list[FindingRecord]
    recommended_actions: list[ActionRecord] = []
    baseline_comparison: BaselineComparison | None = None

    @model_validator(mode="after")
    def _compute_summary(self) -> ImageAnalysisReport:
        counts: Counter[SeverityLevel] = Counter(f.severity for f in self.findings)
        self.summary = ReportSummary(
            total_components=max(len(self.findings), 0),
            findings_by_severity=dict(counts),
        )
        return self


class FleetAnalysisReport(BaseModel):
    """Aggregate report across multiple firmware images in a fleet."""

    model_config = ConfigDict(strict=True, frozen=False)

    report_id: uuid.UUID
    timestamp: datetime
    fleet_id: str
    image_count: int
    fleet_posture: dict[PostureRating, int]
    common_findings: list[FindingRecord] = []
    outlier_images: list[uuid.UUID] = []
    systemic_risks: list[str] = []
    recommended_actions: list[ActionRecord] = []

    @field_validator("image_count")
    @classmethod
    def _validate_image_count(cls, v: int) -> int:
        if v < 0:
            raise ValueError("image_count must be >= 0")
        return v
