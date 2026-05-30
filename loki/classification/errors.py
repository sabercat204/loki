"""Typed exception hierarchy and per-component error model.

Defines:

- ``ClassificationPipelineError`` (root parent).
- ``ClassificationConfigError`` for whole-directory and
  whole-file failures (missing rules dir, taxonomy_version
  mismatch, duplicate ``rule_id``).
- ``ClassificationRuleError`` for individual-rule schema /
  matcher / effect validation failures.
- ``ClassificationError`` (Pydantic model) for per-component
  failures recorded inside ``ClassificationResult.errors``.

Mirrors the structure of ``loki.extraction.errors`` and
``loki.baseline.errors``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, field_validator

__all__ = [
    "ClassificationConfigError",
    "ClassificationError",
    "ClassificationPipelineError",
    "ClassificationRuleError",
]


class ClassificationPipelineError(Exception):
    """Base class for every error raised by ``loki.classification``."""


class ClassificationConfigError(ClassificationPipelineError):
    """Whole-directory or whole-file rule-loading failure.

    Used for missing rules directory (R2.4), taxonomy_version
    mismatch (R2.6), top-level shape errors (R2.5), and duplicate
    ``rule_id`` across files (R2.8).

    Carries ``path`` (the offending rules directory or rule file)
    and a free-form ``message``.
    """

    def __init__(self, path: Path | str, message: str) -> None:
        self.path = Path(path)
        self.message = message
        super().__init__(f"{message}: {self.path}")


class ClassificationRuleError(ClassificationPipelineError):
    """Individual-rule schema / matcher / effect validation failure.

    Used for per-``Rule`` failures (R2.7, R3.9, R4.1, R4.2): bad
    ``rule_id`` charset, predicate values failing type validation,
    Effect ``label`` not a member of the axis enum, etc.

    Carries ``path`` (the source rule file), ``rule_id`` (the
    offending rule's id, or ``None`` if the failure was on
    ``rule_id`` itself or the entry was unparsable enough that no
    id was readable), and a free-form ``message``.
    """

    def __init__(
        self,
        path: Path | str,
        rule_id: str | None,
        message: str,
    ) -> None:
        self.path = Path(path)
        self.rule_id = rule_id
        self.message = message
        rule_id_part = f" rule_id={rule_id}" if rule_id is not None else ""
        super().__init__(f"{message}: {self.path}{rule_id_part}")


class ClassificationError(BaseModel):
    """Per-component error record (R9.3, R9.4).

    Parallel to ``loki.models.firmware.ExtractionError``: carries
    the failed component's ``component_id`` (or ``None`` for
    whole-run failures such as cancellation), a non-empty
    ``error_message``, and a UTC ``timestamp``.

    Recorded inside ``ClassificationResult.errors`` rather than
    raised, so a single bad component never hides the rest of the
    run (R9.3).
    """

    model_config = ConfigDict(strict=True, frozen=False)

    component_id: uuid.UUID | None
    error_message: str
    timestamp: datetime

    @field_validator("error_message")
    @classmethod
    def _validate_error_message(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("error_message must be non-empty")
        return v
