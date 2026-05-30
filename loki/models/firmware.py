"""Firmware image and extraction models for the LOKI platform.

This module defines the core identity and extraction models:
- ``FirmwareImage`` — typed representation of a firmware binary
- ``ExtractedComponent`` — single extracted component from a firmware image
- ``ExtractionError`` — error encountered during extraction
- ``ExtractionManifest`` — container for a full extraction run
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

__all__ = [
    "LOKI_NAMESPACE",
    "ExtractedComponent",
    "ExtractionError",
    "ExtractionManifest",
    "FirmwareImage",
]

LOKI_NAMESPACE: uuid.UUID = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_OFFSET_RE = re.compile(r"^0x[0-9a-fA-F]+$")


class FirmwareImage(BaseModel):
    """Core identity model for a firmware binary.

    ``image_id`` is deterministically generated from ``file_hash`` via
    ``uuid5(LOKI_NAMESPACE, file_hash)`` when not explicitly provided.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    image_id: uuid.UUID | None = None
    file_path: str
    file_hash: str
    file_size: int
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    extraction_timestamp: datetime | None = None

    @field_validator("file_hash")
    @classmethod
    def _validate_file_hash(cls, v: str) -> str:
        if not _SHA256_RE.match(v):
            raise ValueError("file_hash must be exactly 64 lowercase hexadecimal characters")
        return v

    @field_validator("file_size")
    @classmethod
    def _validate_file_size(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("file_size must be greater than 0")
        return v

    @model_validator(mode="after")
    def _auto_generate_image_id(self) -> FirmwareImage:
        if self.image_id is None:
            self.image_id = uuid.uuid5(LOKI_NAMESPACE, self.file_hash)
        return self


class ExtractedComponent(BaseModel):
    """Single extracted component from a firmware image."""

    model_config = ConfigDict(strict=True, frozen=False)

    component_id: uuid.UUID
    source_image_id: uuid.UUID
    offset: str
    size: int
    raw_hash: str
    component_type_hint: str | None = None
    guid: str | None = None
    name: str | None = None
    raw_path: str | None = None

    @field_validator("offset")
    @classmethod
    def _validate_offset(cls, v: str) -> str:
        if not _HEX_OFFSET_RE.match(v):
            raise ValueError("offset must match ^0x[0-9a-fA-F]+$")
        return v

    @field_validator("raw_hash")
    @classmethod
    def _validate_raw_hash(cls, v: str) -> str:
        if not re.match(r"^[0-9a-fA-F]{64}$", v):
            raise ValueError("raw_hash must be exactly 64 hexadecimal characters")
        return v

    @field_validator("size")
    @classmethod
    def _validate_size(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("size must be greater than 0")
        return v


class ExtractionError(BaseModel):
    """Error encountered during firmware extraction."""

    model_config = ConfigDict(strict=True, frozen=False)

    component_id: uuid.UUID | None = None
    error_message: str
    timestamp: datetime

    @field_validator("error_message")
    @classmethod
    def _validate_error_message(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("error_message must be non-empty")
        return v


class ExtractionManifest(BaseModel):
    """Container for a full extraction run.

    ``total_components`` is auto-computed as ``len(components)`` on construction.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    source_image: FirmwareImage
    components: list[ExtractedComponent]
    extraction_timestamp: datetime
    extractor_version: str
    total_components: int = 0
    extraction_errors: list[ExtractionError] = []

    @model_validator(mode="after")
    def _compute_total_components(self) -> ExtractionManifest:
        self.total_components = len(self.components)
        return self
