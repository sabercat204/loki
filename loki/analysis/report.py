"""``ImageAnalysisReport`` assembly + ``BaselineComparison`` construction.

Implements Requirement 17 (report construction) and the priority_rank
second pass per R9.10. Three pure functions:

- ``assign_priority_ranks`` (R9.10): in-place mutation of
  ``classification_mismatch`` findings' embedded ``DeviationScore.priority_rank``.
- ``derive_report_id`` (R15.8): deterministic UUIDv5 over
  ``(target_image_id, baseline_id, analysis_version)``.
- ``assemble_report`` (R17): constructs the final
  ``ImageAnalysisReport``, including the ``BaselineComparison`` whose
  ``comparison_timestamp`` equals ``ImageAnalysisReport.timestamp`` per
  R17.4 post-HARDEN. Wraps any ``pydantic.ValidationError`` raised
  during construction as ``AnalysisReportConstructionError`` per R16.5.

The functions are pure: ``assign_priority_ranks`` mutates only the
list it received and the embedded ``DeviationScore`` instances on
that list's findings; the other two have no side effects.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import ValidationError

from loki.analysis.errors import AnalysisReportConstructionError
from loki.models.baseline import BaselineComparison
from loki.models.firmware import LOKI_NAMESPACE
from loki.models.reports import ImageAnalysisReport

if TYPE_CHECKING:
    from loki.models.analysis import FindingRecord
    from loki.models.baseline import BaselineRecord
    from loki.models.enums import PostureRating
    from loki.models.firmware import FirmwareImage

__all__ = [
    "assemble_report",
    "assign_priority_ranks",
    "derive_report_id",
]


def assign_priority_ranks(findings: list[FindingRecord]) -> None:
    """Assign ``priority_rank`` to every ``classification_mismatch`` finding (R9.10).

    Sort the ``classification_mismatch`` findings by descending
    ``composite_score`` with ties broken by ascending ``component_id``;
    the lowest rank integer (1) corresponds to the highest-Composite_Score
    finding.

    Mutates the embedded ``DeviationScore.priority_rank`` on each
    affected finding in place. Non-``classification_mismatch`` findings
    and any classification_mismatch finding without an embedded
    ``DeviationScore`` are untouched.
    """
    mismatches = [
        finding
        for finding in findings
        if finding.category == "classification_mismatch"
        and finding.evidence.deviation_score is not None
    ]
    # Sort: descending composite_score, ascending component_id for ties.
    # The list comprehension above filtered to non-None deviation_score,
    # so the .composite_score access is safe inside the key function.
    mismatches.sort(
        key=lambda f: (
            -_safe_composite_score(f),
            f.component_id,
        )
    )
    for rank, finding in enumerate(mismatches, start=1):
        # The list comprehension filtered to non-None deviation_score,
        # so this access is also safe.
        score = finding.evidence.deviation_score
        if score is not None:
            score.priority_rank = rank


def _safe_composite_score(finding: FindingRecord) -> float:
    """Read ``finding.evidence.deviation_score.composite_score`` safely.

    Returns 0.0 when ``deviation_score`` is ``None`` (defensive; the
    caller filters these out before sorting, but the type checker
    needs the unconditional return path).
    """
    if finding.evidence.deviation_score is None:
        return 0.0
    return finding.evidence.deviation_score.composite_score


def derive_report_id(
    *,
    target_image_id: uuid.UUID,
    baseline_id: uuid.UUID,
    analysis_version: str,
) -> uuid.UUID:
    """Derive ``ImageAnalysisReport.report_id`` deterministically (R15.8).

    Returns ``uuid.uuid5(LOKI_NAMESPACE, f"{target_image_id}:{baseline_id}:{analysis_version}")``.

    Same target+baseline pair at the same engine version always
    produces the same ``report_id`` across runs and hosts. A bump
    to ``ANALYSIS_VERSION`` (e.g. v1.0.0 -> v1.1.0) changes every
    ``report_id`` while leaving ``finding_id`` values stable
    (R15.7's tuple does not include ``analysis_version``).
    """
    name = f"{target_image_id}:{baseline_id}:{analysis_version}"
    return uuid.uuid5(LOKI_NAMESPACE, name)


def assemble_report(
    *,
    target_image: FirmwareImage,
    matched_baseline: BaselineRecord,
    findings: list[FindingRecord],
    run_started_at: datetime,
    posture_rating: PostureRating,
    analysis_version: str,
) -> ImageAnalysisReport:
    """Construct the final ``ImageAnalysisReport`` (R17).

    Per R17.4 post-HARDEN, ``BaselineComparison.comparison_timestamp``
    equals ``ImageAnalysisReport.timestamp`` (both pulled from the
    single ``run_started_at`` anchor captured at run start). Per
    R17.4, ``BaselineComparison.deviations`` is the empty list ``[]``
    in v1; the analysis engine carries deviations through
    ``FindingRecord`` plus the embedded ``DeviationScore`` per R9.

    Per R17.3, ``ImageAnalysisReport.recommended_actions`` is left at
    the model default (empty list) for v1.

    The model layer's strict Pydantic v2 validators run during
    ``ImageAnalysisReport`` construction and ``BaselineComparison``
    construction. Any ``ValidationError`` raised is caught and
    re-raised as ``AnalysisReportConstructionError`` per R16.5,
    naming the offending Pydantic ``loc`` path.
    """
    # FirmwareImage's @model_validator(mode="after") guarantees image_id
    # is non-None after construction. ``or _fallback_image_id(...)`` is
    # defensive against malformed test fixtures only; production
    # callers will always carry a populated image_id.
    target_image_id = target_image.image_id or _fallback_image_id(target_image)

    try:
        baseline_comparison = BaselineComparison(
            baseline_id=matched_baseline.baseline_id,
            target_image_id=target_image_id,
            comparison_timestamp=run_started_at,
            deviations=[],
        )
    except ValidationError as exc:
        first = exc.errors()[0]
        raise AnalysisReportConstructionError(
            loc=tuple(first["loc"]),
            message=first["msg"],
        ) from exc

    try:
        report = ImageAnalysisReport(
            report_id=derive_report_id(
                target_image_id=target_image_id,
                baseline_id=matched_baseline.baseline_id,
                analysis_version=analysis_version,
            ),
            timestamp=run_started_at,
            analysis_version=analysis_version,
            image_id=target_image_id,
            image_metadata=target_image,
            posture_rating=posture_rating,
            findings=findings,
            baseline_comparison=baseline_comparison,
        )
    except ValidationError as exc:
        first = exc.errors()[0]
        raise AnalysisReportConstructionError(
            loc=tuple(first["loc"]),
            message=first["msg"],
        ) from exc

    return report


def _fallback_image_id(target_image: FirmwareImage) -> uuid.UUID:
    """Compute a deterministic image_id when target_image.image_id is None.

    The model layer auto-generates ``image_id = uuid5(LOKI_NAMESPACE,
    file_hash)`` via ``FirmwareImage._auto_generate_image_id`` at
    construction; this fallback re-derives the same value defensively
    in case the field is ``None`` at the call site (e.g. a hand-built
    test fixture that bypassed the model validator).
    """
    return uuid.uuid5(LOKI_NAMESPACE, target_image.file_hash)
