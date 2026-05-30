"""Configuration models for the LOKI firmware analysis platform.

Provides typed, validated configuration sections and a root ``LokiConfig``
model that can be loaded from a YAML file via ``LokiConfig.from_yaml()``.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import ClassVar

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from loki.models.enums import ColorMode, LogLevel, MatchStrategy, OutputFormat, SeverityLevel

__all__ = [
    "AnalysisConfig",
    "BaselineConfig",
    "ClassificationConfig",
    "ExtractionConfig",
    "FeedsConfig",
    "FleetConfig",
    "GeneralConfig",
    "LokiConfig",
]


class GeneralConfig(BaseModel):
    """General CLI and output configuration."""

    model_config = ConfigDict(strict=True, frozen=False)

    default_output_format: OutputFormat
    color: ColorMode
    verbosity: int = Field(ge=0)
    log_level: LogLevel


class ExtractionConfig(BaseModel):
    """Configuration for the firmware extraction pipeline."""

    model_config = ConfigDict(strict=True, frozen=False)

    default_output_dir: str
    max_component_size: int = Field(gt=0)
    timeout_per_component: int = Field(gt=0)


class ClassificationConfig(BaseModel):
    """Configuration for the classification pipeline."""

    model_config = ConfigDict(strict=True, frozen=False)

    taxonomy_version: str
    confidence_threshold: float = Field(ge=0.0, le=1.0)
    rules_path: str


class AnalysisConfig(BaseModel):
    """Configuration for the analysis engine.

    ``severity_weights`` values must sum to 1.0 within floating-point tolerance.

    The analysis-engine v1 contract (R14) extends this model with three
    fields used by the engine:

    - ``match_strategy``: how the engine resolves the Matched_Baseline
      from a ``BaselineRegistry`` (R2). Defaults to ``MatchStrategy.AUTO``
      (auto-match by ``(vendor, model, firmware_version)``).
    - ``confidence_gap_threshold``: floor on
      ``ClassificationRecord.composite_confidence`` for emitting a
      ``classification_gap`` finding (R10.1). Defaults to ``0.6`` to align
      with the model layer's ``needs_review = composite_confidence < 0.60``
      invariant on ``ClassificationRecord``.
    - ``baseline_id``: optional explicit baseline UUID, consulted when
      ``match_strategy`` is ``EXPLICIT`` or ``EXPLICIT_OR_AUTO`` (R2.2,
      R2.4). Defaults to ``None``.

    The four-key set check on ``severity_weights`` (``{"type", "vendor",
    "security_posture", "mutability"}``) is enforced engine-side at run
    time per R14.1; the model layer's existing sum-to-1.0 validator
    catches the weight total at construction.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    _WEIGHT_SUM_TOLERANCE: ClassVar[float] = 1e-6

    severity_weights: dict[str, float]
    default_severity_threshold: SeverityLevel
    report_template: str | None = None
    match_strategy: MatchStrategy = MatchStrategy.AUTO
    confidence_gap_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    baseline_id: uuid.UUID | None = None
    cve_score_bump: float = Field(default=0.5, ge=0.0, le=5.0)

    @field_validator("severity_weights")
    @classmethod
    def _weights_must_sum_to_one(cls, v: dict[str, float]) -> dict[str, float]:
        total = sum(v.values())
        if abs(total - 1.0) >= cls._WEIGHT_SUM_TOLERANCE:
            msg = f"severity_weights values must sum to 1.0, got {total}"
            raise ValueError(msg)
        return v


class BaselineConfig(BaseModel):
    """Configuration for baseline management (GLEIPNIR)."""

    model_config = ConfigDict(strict=True, frozen=False)

    storage_path: str
    auto_match: bool


class FeedsConfig(BaseModel):
    """Configuration for vulnerability feed ingestion."""

    model_config = ConfigDict(strict=True, frozen=False)

    nvd_url: str
    update_interval: int = Field(gt=0)
    cache_path: str
    implant_rules_path: str
    trust_anchor_path: str | None = None


class FleetConfig(BaseModel):
    """Configuration for fleet-level analysis."""

    model_config = ConfigDict(strict=True, frozen=False)

    default_severity_threshold: SeverityLevel
    storage_path: str


class LokiConfig(BaseModel):
    """Root configuration model composing all LOKI sub-configs.

    Use ``LokiConfig.from_yaml(path)`` to load and validate from a YAML file.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    general: GeneralConfig
    extraction: ExtractionConfig
    classification: ClassificationConfig
    analysis: AnalysisConfig
    baseline: BaselineConfig
    feeds: FeedsConfig
    fleet: FleetConfig

    @classmethod
    def from_yaml(cls, path: Path) -> LokiConfig:
        """Load and validate a ``LokiConfig`` from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            A validated ``LokiConfig`` instance.

        Raises:
            FileNotFoundError: If *path* does not exist.
            yaml.YAMLError: If the file is not valid YAML.
            pydantic.ValidationError: If the parsed data fails validation.
        """
        with open(path) as fh:
            data = yaml.safe_load(fh)
        # Use strict=False so plain strings from YAML coerce to enums.
        return cls.model_validate(data, strict=False)
