"""``QuarantineEntry`` + ``QuarantineSet`` for load-side soft failures.

Bulk loads (:meth:`BaselineStore.load`) populate a
:class:`QuarantineSet` instead of raising on the first malformed
file (R2.4). One entry per rejected Baseline_File. Single-file
loads (:meth:`BaselineStore.load_one`) raise typed errors instead.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

__all__ = ["QuarantineEntry", "QuarantineSet"]


@dataclass(frozen=True)
class QuarantineEntry:
    """One rejected Baseline_File plus its rejection reason.

    Attributes:
        path: Absolute path to the file that was rejected.
        reason: Human-readable rejection reason. Must match one of
            the strings enumerated in the design's Error Handling
            section so callers can pattern-match on the prefix.
        raw: Original file bytes (or ``None`` if the file couldn't
            be read at all). Retained so future GUI work can offer
            a "View raw" affordance without re-reading the file.
    """

    path: Path
    reason: str
    raw: bytes | None


class QuarantineSet:
    """Append-only ordered container of :class:`QuarantineEntry`.

    The entries surface in the order :meth:`BaselineStore.load`
    encountered them — lexicographic Baseline_Filename order.
    """

    def __init__(self) -> None:
        self._entries: list[QuarantineEntry] = []

    def add(self, entry: QuarantineEntry) -> None:
        """Append ``entry`` to the set."""
        self._entries.append(entry)

    def __iter__(self) -> Iterator[QuarantineEntry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)

    def __repr__(self) -> str:
        return f"QuarantineSet({len(self._entries)} entries)"
