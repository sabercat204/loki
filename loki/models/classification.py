"""Classification models for the LOKI platform.

This module defines the classification output models:
- ``AxisClassification`` — single axis result with label, confidence, method
- ``SignatureInfo`` — code-signing metadata for a component
- ``OverrideRecord`` — analyst override of a classification axis
- ``ClassificationRecord`` — full classification output for one component
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_serializer, field_validator, model_validator

from loki.models.enums import ClassificationMethod

__all__ = [
    "AxisClassification",
    "ClassificationRecord",
    "OverrideRecord",
    "SignatureInfo",
]

_HEX_OFFSET_RE = re.compile(r"^0x[0-9a-fA-F]+$")


class AxisClassification(BaseModel):
    """Single axis classification result.

    Represents the classification of one taxonomic axis (type, vendor,
    security posture, or mutability) for a firmware component.

    The ``label`` field accepts any :class:`StrEnum` subclass on input
    and serializes to its plain string value on output. Round-tripping
    through JSON or YAML returns the string form (the original concrete
    enum class can't be recovered from a payload that doesn't carry
    type information).
    """

    model_config = ConfigDict(strict=True, frozen=False)

    label: str
    confidence: float
    method: ClassificationMethod
    rule_id: str | None = None
    evidence: list[str] | None = None

    @field_validator("label", mode="before")
    @classmethod
    def _coerce_label(cls, v: object) -> str:
        if isinstance(v, StrEnum):
            return v.value
        if isinstance(v, str):
            return v
        raise TypeError(f"label must be a str or StrEnum, got {type(v).__name__}")

    @field_serializer("label")
    def _serialize_label(self, value: str) -> str:
        return value

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v


class SignatureInfo(BaseModel):
    """Code-signing metadata for a firmware component."""

    model_config = ConfigDict(strict=True, frozen=False)

    present: bool
    verified: bool
    signer: str | None = None
    cert_expiry: datetime | None = None


class OverrideRecord(BaseModel):
    """Analyst override of a classification axis.

    Records when a human analyst overrides an automated classification,
    including the justification for the change.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    original_label: str
    override_label: str
    analyst: str
    timestamp: datetime
    justification: str

    @field_validator("justification")
    @classmethod
    def _validate_justification(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("justification must be non-empty")
        return v


class ClassificationRecord(BaseModel):
    """Full classification output for one firmware component.

    Contains four axis classifications (type, vendor, security, mutability),
    optional signature info, and auto-computed composite confidence and
    review flag.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    component_id: uuid.UUID
    source_image_id: uuid.UUID
    extraction_offset: str
    timestamp: datetime
    type_axis: AxisClassification
    vendor_axis: AxisClassification
    security_axis: AxisClassification
    mutability_axis: AxisClassification
    signature_info: SignatureInfo | None = None
    cve_matches: list[str] = []
    suspicion_triggers: list[str] = []
    composite_confidence: float = 0.0
    needs_review: bool = True
    classification_version: str
    overrides: list[OverrideRecord] = []

    @field_validator("extraction_offset")
    @classmethod
    def _validate_extraction_offset(cls, v: str) -> str:
        if not _HEX_OFFSET_RE.match(v):
            raise ValueError("extraction_offset must match ^0x[0-9a-fA-F]+$")
        return v

    @model_validator(mode="after")
    def _compute_composite_fields(self) -> ClassificationRecord:
        self.composite_confidence = min(
            self.type_axis.confidence,
            self.vendor_axis.confidence,
            self.security_axis.confidence,
            self.mutability_axis.confidence,
        )
        self.needs_review = self.composite_confidence < 0.60
        return self
