"""Component_Pairing logic over (Target_Records, Baseline_Manifest).

Implements Requirement 3 (component_id-keyed bijection-with-defects).
The four functions in this module are pure: ``check_pairing_preconditions``
detects duplicate component_id values on either side and raises
``AnalysisInputError`` (R3.6, R3.7); ``build_baseline_index`` returns the
dict the pipeline keys pairing on (R18.2's single-dict contract);
``pair_records`` yields (target, paired_baseline-or-None) tuples in
target input order (R3.4); ``unpaired_baselines`` returns the
ascending-component_id-sorted list of baseline records that no target
record matched.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING

from loki.analysis.errors import AnalysisInputError

if TYPE_CHECKING:
    from loki.models.classification import ClassificationRecord

__all__ = [
    "build_baseline_index",
    "check_pairing_preconditions",
    "pair_records",
    "unpaired_baselines",
]


def check_pairing_preconditions(
    target_records: Sequence[ClassificationRecord],
    baseline_manifest: Sequence[ClassificationRecord],
    baseline_id: uuid.UUID,
) -> None:
    """Detect duplicate ``component_id`` values on either side (R3.6, R3.7).

    Raises ``AnalysisInputError(side="target", duplicates=[...])`` when
    target_records contains duplicate ``component_id`` values; raises
    ``AnalysisInputError(side="baseline", duplicates=[...],
    baseline_id=baseline_id)`` when baseline_manifest contains
    duplicates. The function is pure; it returns ``None`` on success.

    The target check fires first; duplicate-on-both-sides scenarios
    surface the target side's complaint first.
    """
    target_dups = _find_duplicates(target_records)
    if target_dups:
        raise AnalysisInputError(side="target", duplicates=target_dups)

    baseline_dups = _find_duplicates(baseline_manifest)
    if baseline_dups:
        raise AnalysisInputError(
            side="baseline",
            duplicates=baseline_dups,
            baseline_id=baseline_id,
        )


def build_baseline_index(
    baseline_manifest: Sequence[ClassificationRecord],
) -> dict[uuid.UUID, ClassificationRecord]:
    """Return the dict the pipeline keys pairing on (R18.2).

    Pre-condition: the caller has already run ``check_pairing_preconditions``
    so the manifest carries no duplicate ``component_id`` values. With
    that pre-condition the dict construction is unambiguous; without it
    the last-write-wins semantics of dict literal construction would
    silently mask the duplicate.
    """
    return {record.component_id: record for record in baseline_manifest}


def pair_records(
    target_records: Sequence[ClassificationRecord],
    baseline_index: dict[uuid.UUID, ClassificationRecord],
) -> Iterator[tuple[ClassificationRecord, ClassificationRecord | None]]:
    """Yield (target, paired_baseline-or-None) tuples in input order (R3.4).

    The iterator emits one tuple per Target_Record in the order the
    caller passed them. When a Target_Record's ``component_id`` matches
    a baseline record in the index, the second element is that baseline
    record; when no match exists, the second element is ``None``.

    The function does not mark consumed component_ids itself; the
    caller (the pipeline) tracks consumption to drive the
    ``unpaired_baselines`` pass.
    """
    for target in target_records:
        yield target, baseline_index.get(target.component_id)


def unpaired_baselines(
    baseline_index: dict[uuid.UUID, ClassificationRecord],
    consumed_ids: set[uuid.UUID],
) -> list[ClassificationRecord]:
    """Return baseline records whose component_id was not consumed (R3.4).

    The returned list is sorted by ascending ``component_id`` per R3.4's
    deterministic ordering rule. ``consumed_ids`` is the set of
    component_id values the pipeline saw on the target side during
    pairing.
    """
    unpaired = [
        record
        for component_id, record in baseline_index.items()
        if component_id not in consumed_ids
    ]
    unpaired.sort(key=lambda r: r.component_id)
    return unpaired


def _find_duplicates(records: Sequence[ClassificationRecord]) -> list[uuid.UUID]:
    """Return the list of component_id values that appear more than once."""
    seen: set[uuid.UUID] = set()
    duplicates: list[uuid.UUID] = []
    duplicates_seen: set[uuid.UUID] = set()
    for record in records:
        cid = record.component_id
        if cid in seen and cid not in duplicates_seen:
            duplicates.append(cid)
            duplicates_seen.add(cid)
        seen.add(cid)
    return duplicates
