"""Baseline management models for the LOKI platform.

This module defines the baseline and deviation models used by the
GLEIPNIR baseline management subsystem:
- ``BaselineRecord`` — a named baseline snapshot
- ``BaselineRegistry`` — container with lookup methods
- ``DeviationRecord`` — single deviation between baseline and target
- ``BaselineComparison`` — full comparison result with auto-computed summary
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from loki.models.classification import ClassificationRecord
from loki.models.enums import DeltaType

__all__ = [
    "BaselineComparison",
    "BaselineRecord",
    "BaselineRegistry",
    "DeviationRecord",
]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class BaselineRecord(BaseModel):
    """A named baseline snapshot for a firmware vendor/model/version.

    Validates that ``baseline_version`` follows semver format and
    ``source_image_hash`` is a valid SHA-256 hex string.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    baseline_id: uuid.UUID
    name: str
    vendor: str
    model: str
    firmware_version: str
    created_timestamp: datetime
    notes: str | None = None
    component_manifest: list[ClassificationRecord]
    source_image_hash: str
    baseline_version: str

    @field_validator("source_image_hash")
    @classmethod
    def _validate_source_image_hash(cls, v: str) -> str:
        if not _SHA256_RE.match(v):
            raise ValueError(
                "source_image_hash must be exactly 64 lowercase hexadecimal characters"
            )
        return v

    @field_validator("baseline_version")
    @classmethod
    def _validate_baseline_version(cls, v: str) -> str:
        if not _SEMVER_RE.match(v):
            raise ValueError("baseline_version must match semver pattern ^\\d+\\.\\d+\\.\\d+$")
        return v


class BaselineRegistry(BaseModel):
    """Container for multiple baseline records with lookup methods.

    Provides efficient lookups by baseline ID, vendor+model, and
    vendor+model+version.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    baselines: list[BaselineRecord] = []

    def get_by_id(self, baseline_id: uuid.UUID) -> BaselineRecord | None:
        """Return the baseline record matching the given ID, or ``None``."""
        for record in self.baselines:
            if record.baseline_id == baseline_id:
                return record
        return None

    def get_by_vendor_model(self, vendor: str, model: str) -> list[BaselineRecord]:
        """Return all baseline records matching the given vendor and model."""
        return [
            record for record in self.baselines if record.vendor == vendor and record.model == model
        ]

    def get_by_vendor_model_version(
        self, vendor: str, model: str, version: str
    ) -> BaselineRecord | None:
        """Return the single baseline record matching vendor, model, and version, or ``None``."""
        for record in self.baselines:
            if (
                record.vendor == vendor
                and record.model == model
                and record.firmware_version == version
            ):
                return record
        return None


class DeviationRecord(BaseModel):
    """Single deviation between a baseline and target firmware image.

    Records the type of change and optionally the before/after
    classification states.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    deviation_id: uuid.UUID
    component_id: uuid.UUID
    delta_type: DeltaType
    baseline_state: ClassificationRecord | None = None
    target_state: ClassificationRecord | None = None
    description: str


class BaselineComparison(BaseModel):
    """Full comparison result between a baseline and a target firmware image.

    ``summary`` is auto-computed as a count of each ``DeltaType`` present
    in the ``deviations`` list.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    baseline_id: uuid.UUID
    target_image_id: uuid.UUID
    comparison_timestamp: datetime
    deviations: list[DeviationRecord]
    summary: dict[DeltaType, int] = {}

    @model_validator(mode="after")
    def _compute_summary(self) -> BaselineComparison:
        counts: Counter[DeltaType] = Counter(dev.delta_type for dev in self.deviations)
        self.summary = dict(counts)
        return self
