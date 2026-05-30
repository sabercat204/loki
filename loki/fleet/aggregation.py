"""Core aggregation logic for fleet analysis."""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from collections.abc import Sequence
from statistics import median_low

from loki.fleet.models import FleetRiskScore
from loki.models.analysis import ActionRecord, FindingRecord
from loki.models.enums import PostureRating, SeverityLevel
from loki.models.reports import ImageAnalysisReport

__all__: list[str] = [
    "compute_common_findings",
    "compute_cve_rollup",
    "compute_posture_distribution",
    "compute_risk_ranking",
    "detect_outliers",
]

_UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

_POSTURE_ORDINAL: dict[PostureRating, int] = {
    PostureRating.HARDENED: 0,
    PostureRating.BASELINE: 1,
    PostureRating.DEGRADED: 2,
    PostureRating.AT_RISK: 3,
    PostureRating.COMPROMISED: 4,
}

_SEVERITY_ORDINAL: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 4,
    SeverityLevel.HIGH: 3,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 1,
    SeverityLevel.INFO: 0,
}


def _normalize_title(title: str) -> str:
    """Replace UUIDs in a finding title with <component> placeholder."""
    return _UUID_PATTERN.sub("<component>", title)


def compute_posture_distribution(
    reports: Sequence[ImageAnalysisReport],
) -> dict[PostureRating, int]:
    """Count images per PostureRating, filling all enum values with 0."""
    counts: dict[PostureRating, int] = {rating: 0 for rating in PostureRating}
    for report in reports:
        counts[report.posture_rating] += 1
    return counts


def compute_common_findings(
    reports: Sequence[ImageAnalysisReport],
) -> list[FindingRecord]:
    """Identify findings that appear in 2+ images.

    Groups by (category, severity, normalized_title). Returns sorted by
    descending count, then descending severity.
    """
    groups: defaultdict[tuple[str, SeverityLevel, str], list[FindingRecord]] = defaultdict(list)

    for report in reports:
        seen_keys: set[tuple[str, SeverityLevel, str]] = set()
        for finding in report.findings:
            normalized = _normalize_title(finding.title)
            key: tuple[str, SeverityLevel, str] = (
                finding.category,
                finding.severity,
                normalized,
            )
            if key not in seen_keys:
                groups[key].append(finding)
                seen_keys.add(key)

    common: list[tuple[int, FindingRecord]] = []
    for _key, findings in groups.items():
        count = len(findings)
        if count >= 2:
            representative = findings[0]
            augmented = FindingRecord(
                finding_id=representative.finding_id,
                component_id=representative.component_id,
                severity=representative.severity,
                category=representative.category,
                title=representative.title,
                description=representative.description,
                evidence=representative.evidence.model_copy(
                    update={
                        "raw_indicators": [
                            *representative.evidence.raw_indicators,
                            f"fleet_count={count}",
                        ]
                    }
                ),
                recommended_action=representative.recommended_action,
            )
            common.append((count, augmented))

    common.sort(key=lambda t: (-t[0], -_SEVERITY_ORDINAL[t[1].severity]))
    return [finding for _, finding in common]


def compute_cve_rollup(
    reports: Sequence[ImageAnalysisReport],
) -> list[str]:
    """Aggregate CVE IDs across the fleet.

    Returns entries for CVEs appearing in 2+ images, formatted as
    "CVE-XXXX-YYYY affects N images".
    """
    cve_images: defaultdict[str, set[uuid.UUID]] = defaultdict(set)

    for report in reports:
        for finding in report.findings:
            cve = finding.evidence.matched_cve
            if cve:
                cve_images[cve].add(report.image_id)

    results: list[tuple[int, str]] = []
    for cve_id, image_ids in cve_images.items():
        count = len(image_ids)
        if count >= 2:
            results.append((count, cve_id))

    results.sort(key=lambda t: (-t[0], t[1]))
    return [f"{cve_id} affects {count} images" for count, cve_id in results]


def detect_outliers(
    reports: Sequence[ImageAnalysisReport],
    fleet_posture: dict[PostureRating, int],
) -> list[uuid.UUID]:
    """Flag images whose posture is strictly worse than the fleet median.

    Skips if fewer than 3 images. Returns sorted by descending severity,
    then lexicographic image_id.
    """
    if len(reports) < 3:
        return []

    ordinals: list[int] = []
    for rating, count in fleet_posture.items():
        ordinals.extend([_POSTURE_ORDINAL[rating]] * count)
    ordinals.sort()

    median_ordinal = median_low(ordinals)

    outliers: list[tuple[int, str, uuid.UUID]] = []
    for report in reports:
        ordinal = _POSTURE_ORDINAL[report.posture_rating]
        if ordinal > median_ordinal:
            outliers.append((ordinal, str(report.image_id), report.image_id))

    outliers.sort(key=lambda t: (-t[0], t[1]))
    return [image_id for _, _, image_id in outliers]


def compute_risk_ranking(
    reports: Sequence[ImageAnalysisReport],
) -> list[ActionRecord]:
    """Rank images by risk score and surface top 3 as ActionRecords.

    risk_score = sum(mismatch composite_scores) + 10 * count(CRITICAL findings)
    """
    scores: list[FleetRiskScore] = []
    for report in reports:
        composite_sum = 0.0
        critical_count = 0
        for finding in report.findings:
            if finding.category == "classification_mismatch":
                if finding.evidence.deviation_score is not None:
                    composite_sum += finding.evidence.deviation_score.composite_score
            if finding.severity == SeverityLevel.CRITICAL:
                critical_count += 1

        risk_score = composite_sum + 10.0 * critical_count
        scores.append(
            FleetRiskScore(
                image_id=report.image_id,
                risk_score=risk_score,
                finding_count=len(report.findings),
            )
        )

    scores.sort(key=lambda s: (-s.risk_score, str(s.image_id)))

    top_3 = scores[:3]
    actions: list[ActionRecord] = []
    for score in top_3:
        actions.append(
            ActionRecord(
                action_id=uuid.uuid5(
                    uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
                    f"fleet-risk:{score.image_id}",
                ),
                finding_id=uuid.uuid5(
                    uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
                    f"fleet-finding:{score.image_id}",
                ),
                action_type="INVESTIGATE",
                description=f"Image {score.image_id}: risk_score={score.risk_score:.1f}",
            )
        )

    return actions
