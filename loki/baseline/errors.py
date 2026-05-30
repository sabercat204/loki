"""Typed exception hierarchy for the baseline-persistence subsystem.

Six exception classes leave the subsystem boundary:

- :class:`BaselineStoreError` — root parent.
- :class:`BaselineConcurrentModificationError` — destination's
  ``(mtime_ns, size)`` moved since load (R5.2).
- :class:`BaselineAlreadyExistsError` — save without prior load
  and the destination file exists, with ``force=False`` (R5.3).
- :class:`BaselineSerializationError` — save-side validation
  failure (R3.8), 16 MiB size-limit exceeded (R9.8), or
  single-file load failure (R6.6 / R7.4).
- :class:`BaselineStorageUnwritableError` — destination directory
  exists but is not writable by the current process (R8.7).
- :class:`BaselineNotFoundError` — the requested ``baseline_id``
  is not present in the store, used by
  :meth:`BaselineStore.delete` (R6.8 anchor).

These are control-flow exceptions, not data models — plain
``Exception`` subclasses with typed ``__init__`` signatures.
"""

from __future__ import annotations

import uuid
from pathlib import Path

__all__ = [
    "BaselineAlreadyExistsError",
    "BaselineConcurrentModificationError",
    "BaselineNotFoundError",
    "BaselineSerializationError",
    "BaselineStorageUnwritableError",
    "BaselineStoreError",
]


class BaselineStoreError(Exception):
    """Base class for every error raised by ``loki.baseline``."""


class BaselineConcurrentModificationError(BaselineStoreError):
    """The destination Baseline_File was modified since load (R5.2).

    Carries the offending path plus the recorded vs observed
    ``(mtime_ns, size)`` snapshots so callers can render a useful
    diagnostic.
    """

    def __init__(
        self,
        path: Path | str,
        recorded: tuple[int, int],
        observed: tuple[int, int],
    ) -> None:
        self.path = Path(path)
        self.recorded = recorded
        self.observed = observed
        super().__init__(
            f"baseline file at {self.path} was modified since load: "
            f"recorded {recorded}, observed {observed}"
        )


class BaselineAlreadyExistsError(BaselineStoreError):
    """A save would overwrite a Baseline_File that wasn't previously loaded (R5.3).

    Pass ``force=True`` to :meth:`BaselineStore.save` to override.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        super().__init__(f"baseline file at {self.path} already exists")


class BaselineSerializationError(BaselineStoreError):
    """Save-side validation or size-limit failure (R3.8, R9.8).

    Carries an optional ``cause`` (typically a
    :class:`pydantic.ValidationError`) so the GUI / CLI can drill
    into the underlying field-level errors.
    """

    def __init__(
        self,
        message: str,
        *,
        cause: BaseException | None = None,
    ) -> None:
        self.message = message
        self.__cause__ = cause
        super().__init__(message)


class BaselineStorageUnwritableError(BaselineStoreError):
    """The Storage_Directory exists but isn't writable (R8.7).

    Carries the path and the underlying ``OSError`` errno so callers
    can distinguish permission errors from filesystem-level failures.
    """

    def __init__(self, path: Path | str, errno: int) -> None:
        self.path = Path(path)
        self.errno = errno
        super().__init__(f"baseline storage at {self.path} is not writable (errno={errno})")


class BaselineNotFoundError(BaselineStoreError):
    """The requested ``baseline_id`` is not present in the store.

    Raised by :meth:`BaselineStore.delete` when the caller asks to
    delete a baseline whose ``baseline_id`` was never loaded, or
    whose Baseline_File has gone missing on disk between
    :meth:`BaselineStore.load` and the delete call. The handoff
    explicitly calls this out as a separate failure mode from
    :class:`BaselineStorageUnwritableError`.
    """

    def __init__(self, baseline_id: uuid.UUID, *, path: Path | str | None = None) -> None:
        self.baseline_id = baseline_id
        self.path = Path(path) if path is not None else None
        if self.path is not None:
            super().__init__(f"baseline {baseline_id} not found at {self.path}")
        else:
            super().__init__(f"baseline {baseline_id} not found in store")
