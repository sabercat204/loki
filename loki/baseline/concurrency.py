"""``FileSnapshot`` + mtime/size check for the Atomic_Write protocol.

The persistence subsystem detects external mutation by recording
each Baseline_File's ``(st_mtime_ns, st_size)`` at load time and
re-checking it immediately before ``os.replace`` (R5.1, R5.2). When
the file moved, :func:`check_unchanged` raises
:class:`BaselineConcurrentModificationError` and the save is
abandoned without overwriting the file.

This module is pure — no logging, no I/O beyond ``os.stat``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from loki.baseline.errors import BaselineConcurrentModificationError

__all__ = [
    "FileSnapshot",
    "check_unchanged",
    "snapshot",
]


@dataclass(frozen=True)
class FileSnapshot:
    """Captured ``(st_mtime_ns, st_size)`` for a Baseline_File.

    Captured at :meth:`BaselineStore.load` time and re-checked at
    :meth:`BaselineStore.save` time. The path is stored alongside
    the snapshot so error messages can name the offending file.
    """

    path: Path
    mtime_ns: int
    size: int


def snapshot(path: Path) -> FileSnapshot:
    """Capture ``stat()``'s ``st_mtime_ns`` and ``st_size`` for ``path``.

    Raises:
        FileNotFoundError: if ``path`` doesn't exist (caller decides
            whether that's a soft or hard failure).
        OSError: on other filesystem errors.
    """

    info = os.stat(path)
    return FileSnapshot(
        path=Path(path),
        mtime_ns=info.st_mtime_ns,
        size=info.st_size,
    )


def check_unchanged(snap: FileSnapshot) -> None:
    """Raise :class:`BaselineConcurrentModificationError` if ``snap.path`` moved.

    Compares the recorded ``(mtime_ns, size)`` against a fresh
    ``stat()``. A missing file is treated as a concurrent
    modification (someone deleted it between load and save).
    """

    try:
        observed = snapshot(snap.path)
    except FileNotFoundError as exc:
        raise BaselineConcurrentModificationError(
            snap.path,
            recorded=(snap.mtime_ns, snap.size),
            observed=(-1, -1),
        ) from exc
    if (observed.mtime_ns, observed.size) != (snap.mtime_ns, snap.size):
        raise BaselineConcurrentModificationError(
            snap.path,
            recorded=(snap.mtime_ns, snap.size),
            observed=(observed.mtime_ns, observed.size),
        )
