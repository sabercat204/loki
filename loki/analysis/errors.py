"""Typed exception hierarchy for the analysis subsystem.

``AnalysisError`` is the only exception type that escapes the public
``analyze_image`` entry point (R16.1). The four subclasses cover the
four whole-run failure modes contracted by the requirements:

- ``AnalysisConfigError``: ``AnalysisConfig`` violates Requirement 14
  (R16.2).
- ``BaselineNotFoundError``: baseline matching fails per Requirement 2
  (R16.3).
- ``AnalysisInputError``: duplicate ``component_id`` values on either
  side of the pairing per Requirement 3 (R16.4).
- ``AnalysisReportConstructionError``: final-report Pydantic validation
  fails (R16.5).

Cooperative cancellation is a return-path, not a throw-path; per R16.6
no ``AnalysisCancelledError`` member exists in v1. The engine returns
a partial report carrying an ``analysis_cancelled`` Cancellation_Marker
finding instead of raising.

Each exception carries enough structured context to identify the
offending input without leaking any value in the
Forbidden_Leakage_Field_Set in log records (the rule applies to log
records; exception messages raised to callers are the caller's
responsibility per the project-wide pattern carried forward from
extraction / classification).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

__all__ = [
    "AnalysisConfigError",
    "AnalysisError",
    "AnalysisInputError",
    "AnalysisReportConstructionError",
    "BaselineNotFoundError",
]


class AnalysisError(Exception):
    """Root of the analysis-engine exception hierarchy (R16.1)."""


class AnalysisConfigError(AnalysisError):
    """Raised when ``AnalysisConfig`` violates Requirement 14 (R16.2).

    Carries the offending field name and a redacted message. SHALL NOT
    carry any field value derived from Target_Records or
    Matched_Baseline contents.
    """

    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(f"{field_name}: {message}")
        self.field_name = field_name


class BaselineNotFoundError(AnalysisError):
    """Raised when baseline matching fails per Requirement 2 (R16.3).

    Carries either the offending ``baseline_id`` (EXPLICIT path) or the
    offending ``(vendor, model, firmware_version)`` tuple (AUTO /
    EXPLICIT_OR_AUTO fallback path). Exactly one of the two must be set.
    """

    def __init__(
        self,
        *,
        baseline_id: uuid.UUID | None = None,
        vendor_model_version: tuple[str, str, str] | None = None,
    ) -> None:
        if baseline_id is not None and vendor_model_version is None:
            super().__init__(f"baseline not found by id: {baseline_id}")
        elif vendor_model_version is not None and baseline_id is None:
            v, m, fw = vendor_model_version
            super().__init__(f"baseline not found by vendor/model/version: ({v!r}, {m!r}, {fw!r})")
        else:
            msg = (
                "BaselineNotFoundError requires exactly one of baseline_id or vendor_model_version"
            )
            raise ValueError(msg)
        self.baseline_id = baseline_id
        self.vendor_model_version = vendor_model_version


class AnalysisInputError(AnalysisError):
    """Raised on duplicate component_id values in inputs per Requirement 3 (R16.4).

    Carries the side that has the duplicate (``"target"`` or ``"baseline"``),
    the list of duplicate component_id values, and (for the baseline
    side) the offending ``Matched_Baseline.baseline_id``.
    """

    def __init__(
        self,
        *,
        side: str,
        duplicates: Iterable[uuid.UUID],
        baseline_id: uuid.UUID | None = None,
    ) -> None:
        if side not in {"target", "baseline"}:
            msg = f"AnalysisInputError side must be 'target' or 'baseline', got {side!r}"
            raise ValueError(msg)
        duplicates_list = list(duplicates)
        ids_str = ", ".join(str(d) for d in duplicates_list)
        if side == "baseline":
            super().__init__(f"duplicate component_id in baseline {baseline_id}: [{ids_str}]")
        else:
            super().__init__(f"duplicate component_id in target_records: [{ids_str}]")
        self.side = side
        self.duplicates = duplicates_list
        self.baseline_id = baseline_id


class AnalysisReportConstructionError(AnalysisError):
    """Raised when final ``ImageAnalysisReport`` construction fails Pydantic validation (R16.5).

    Carries the offending Pydantic ``loc`` path and the Pydantic error
    message. SHALL NOT carry any value from the
    Forbidden_Leakage_Field_Set; callers that catch this and wish to log
    it should not blindly format the underlying Pydantic error.
    """

    def __init__(self, loc: tuple[int | str, ...], message: str) -> None:
        loc_str = ".".join(str(p) for p in loc)
        super().__init__(f"{loc_str}: {message}")
        self.loc = loc
